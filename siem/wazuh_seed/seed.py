#!/usr/bin/env python3
"""Ranger SOC telemetry seeder.

Pulls REAL ATT&CK-labeled telemetry from GitHub (OTRF Security-Datasets: redistributable, each
dataset is real Windows/Sysmon event logs from an emulated attack) and, optionally, HuggingFace
datasets, and bulk-loads it into the Wazuh indexer under a `ranger-telemetry` index so candidates
investigate real events in the SOC console. Runs inside the ranger-shared-infra project, where the
Wazuh indexer is reachable over the private network. Deterministic doc ids make re-runs idempotent.

Env (set via Railway references in the shared project):
  INDEXER_URL            https://<wazuh-indexer private domain>:9200
  INDEXER_USER           admin
  INDEXER_PASSWORD       ${{wazuh-indexer.INDEXER_PASSWORD}}
  RANGER_TELEMETRY_INDEX ranger-telemetry   (default)
  RANGER_SEED_SOURCES    comma list of GitHub raw .zip/.jsonl URLs (default: a curated ATT&CK set)
  RANGER_SEED_HF         comma list of HuggingFace dataset sources "repo_id:filename" (optional)
  PORT                   health server port (Railway provides)
"""
import hashlib
import io
import json
import os
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = os.environ.get("INDEXER_URL", "https://wazuh-indexer.railway.internal:9200").rstrip("/")
USER = os.environ.get("INDEXER_USER", "admin")
PW = os.environ.get("INDEXER_PASSWORD", "")
INDEX = os.environ.get("RANGER_TELEMETRY_INDEX", "ranger-telemetry")
PORT = int(os.environ.get("PORT", "8080"))
BATCH = int(os.environ.get("RANGER_SEED_BATCH", "2000"))

_GH = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"
DEFAULT_SOURCES = ",".join([
    _GH + "/credential_access/host/empire_mimikatz_logonpasswords.zip",   # T1003 credential dumping
    _GH + "/execution/host/empire_launcher_vbs.zip",                      # T1059 execution
    _GH + "/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",   # T1021 lateral movement
])
SOURCES = [s.strip() for s in os.environ.get("RANGER_SEED_SOURCES", DEFAULT_SOURCES).split(",") if s.strip()]
HF_SOURCES = [s.strip() for s in os.environ.get("RANGER_SEED_HF", "").split(",") if s.strip()]
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "").rstrip("/")
CAND_USER = os.environ.get("RANGER_CANDIDATE_USER", "ranger-candidate")
CAND_PW = os.environ.get("RANGER_CANDIDATE_PW", "")

STATE = {"status": "starting", "loaded": 0, "sources": [], "errors": []}


def log(*a):
    print("[seed]", *a, flush=True)


def _label(url):
    # .../windows/<tactic>/host/<name>.zip  ->  (tactic, name)
    tail = url.split("/windows/")[-1] if "/windows/" in url else url
    parts = [p for p in tail.split("/") if p]
    tactic = parts[0] if parts else "unknown"
    name = (parts[-1] if parts else "dataset").rsplit(".", 1)[0]
    return tactic, name


def _iter_lines(raw, url):
    if url.endswith(".zip"):
        z = zipfile.ZipFile(io.BytesIO(raw))
        for n in z.namelist():
            if n.endswith(".json") or n.endswith(".jsonl") or n.endswith(".ndjson"):
                for line in z.open(n).read().decode("utf-8", "replace").splitlines():
                    if line.strip():
                        yield line
    else:
        for line in raw.decode("utf-8", "replace").splitlines():
            if line.strip():
                yield line


def _docs(lines, tactic, name, source, url):
    for line in lines:
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if not isinstance(ev, dict):
            continue
        ev["ranger"] = {"dataset": name, "attack_tactic": tactic, "source": source, "source_ref": url}
        _id = hashlib.sha1(("%s|%s" % (name, line)).encode("utf-8", "replace")).hexdigest()
        yield _id, ev


def _bulk(docs):
    sess = requests.Session()
    buf, n, total = [], 0, 0
    def flush():
        nonlocal buf, n
        if not buf:
            return 0
        body = "\n".join(buf) + "\n"
        r = sess.post("%s/_bulk" % INDEXER_URL, auth=(USER, PW), verify=False, data=body.encode("utf-8"),
                      headers={"Content-Type": "application/x-ndjson"}, timeout=180)
        r.raise_for_status()
        out = r.json()
        if out.get("errors"):
            first = next((i for i in out.get("items", []) if list(i.values())[0].get("error")), None)
            if first:
                log("bulk item error sample:", json.dumps(first)[:300])
        done = n
        buf, n = [], 0
        return done
    for _id, doc in docs:
        buf.append(json.dumps({"index": {"_index": INDEX, "_id": _id}}))
        buf.append(json.dumps(doc, default=str))
        n += 1
        if n >= BATCH:
            total += flush()
    total += flush()
    return total


def ensure_index():
    try:
        requests.put("%s/%s" % (INDEXER_URL, INDEX), auth=(USER, PW), verify=False,
                     json={"settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0,
                                                   "mapping": {"total_fields": {"limit": 4000}}}}},
                     headers={"Content-Type": "application/json"}, timeout=60)
    except Exception as e:  # noqa: BLE001
        log("ensure_index:", str(e)[:200])


def ensure_candidate_user():
    """A read-only Wazuh login candidates use to investigate the telemetry (no admin rights)."""
    if not CAND_PW:
        log("no RANGER_CANDIDATE_PW set; skipping candidate user")
        return
    try:
        r = requests.put("%s/_plugins/_security/api/internalusers/%s" % (INDEXER_URL, CAND_USER),
                         auth=(USER, PW), verify=False,
                         json={"password": CAND_PW, "opendistro_security_roles": ["readall", "kibana_user"],
                               "attributes": {"ranger": "candidate"}},
                         headers={"Content-Type": "application/json"}, timeout=30)
        log("candidate user '%s':" % CAND_USER, r.status_code, str(r.text)[:160])
    except Exception as e:  # noqa: BLE001
        log("candidate user error:", str(e)[:200])


def ensure_index_pattern():
    """So the ranger-telemetry data is browsable in the dashboard the moment a candidate opens it."""
    if not DASHBOARD_URL:
        log("no DASHBOARD_URL set; skipping index pattern")
        return
    try:
        r = requests.post("%s/api/saved_objects/index-pattern/ranger-telemetry" % DASHBOARD_URL,
                          auth=(USER, PW), verify=False,
                          headers={"osd-xsrf": "true", "Content-Type": "application/json"},
                          json={"attributes": {"title": "ranger-telemetry*", "timeFieldName": "@timestamp"}},
                          timeout=40)
        log("index pattern:", r.status_code, str(r.text)[:160])
    except Exception as e:  # noqa: BLE001
        log("index pattern error:", str(e)[:200])


def wait_indexer():
    for _ in range(60):
        try:
            r = requests.get(INDEXER_URL, auth=(USER, PW), verify=False, timeout=10)
            if r.status_code < 500:
                log("indexer reachable:", r.status_code)
                return True
        except Exception as e:  # noqa: BLE001
            log("waiting for indexer:", str(e)[:120])
        time.sleep(5)
    return False


def load_github(url):
    r = requests.get(url, timeout=180)
    if r.status_code != 200:
        raise RuntimeError("HTTP %s" % r.status_code)
    tactic, name = _label(url)
    n = _bulk(_docs(_iter_lines(r.content, url), tactic, name, "github", url))
    return name, tactic, n


def load_hf(entry):
    # entry: "repo_id:filename"  (dataset repo)
    from huggingface_hub import hf_hub_download  # optional dependency
    repo_id, _, filename = entry.partition(":")
    path = hf_hub_download(repo_id=repo_id, filename=filename, repo_type="dataset",
                           token=os.environ.get("HF_TOKEN") or None)
    with open(path, "rb") as f:
        raw = f.read()
    name = ("%s/%s" % (repo_id, filename)).replace("/", "_")
    n = _bulk(_docs(_iter_lines(raw, filename), "huggingface", name, "huggingface", entry))
    return name, "huggingface", n


def seed():
    STATE["status"] = "waiting_indexer"
    if not wait_indexer():
        STATE["status"] = "error:indexer_unreachable"
        log("indexer never came up; giving up this run")
        return
    ensure_index()
    STATE["status"] = "loading"
    total = 0
    for url in SOURCES:
        try:
            name, tactic, n = load_github(url)
            total += n
            STATE["sources"].append({"name": name, "tactic": tactic, "events": n, "source": "github"})
            log("loaded github", name, tactic, n)
        except Exception as e:  # noqa: BLE001
            STATE["errors"].append("github %s: %s" % (url, str(e)[:160]))
            log("ERROR github", url, str(e)[:200])
    for entry in HF_SOURCES:
        try:
            name, tactic, n = load_hf(entry)
            total += n
            STATE["sources"].append({"name": name, "tactic": tactic, "events": n, "source": "huggingface"})
            log("loaded hf", name, n)
        except Exception as e:  # noqa: BLE001
            STATE["errors"].append("hf %s: %s" % (entry, str(e)[:160]))
            log("ERROR hf", entry, str(e)[:200])
    try:
        requests.post("%s/%s/_refresh" % (INDEXER_URL, INDEX), auth=(USER, PW), verify=False, timeout=30)
    except Exception:
        pass
    ensure_candidate_user()
    ensure_index_pattern()
    STATE.update(status="done", loaded=total)
    log("SEED COMPLETE: %d events into index '%s' across %d datasets"
        % (total, INDEX, len(STATE["sources"])))
    log("Create the index pattern 'ranger-telemetry*' in the Wazuh dashboard (Stack Management > "
        "Index Patterns) to browse it, if it is not already present.")


class _Health(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(STATE).encode("utf-8"))

    def log_message(self, *a):  # silence access logs
        return


def main():
    threading.Thread(target=seed, daemon=True).start()
    HTTPServer(("0.0.0.0", PORT), _Health).serve_forever()


if __name__ == "__main__":
    main()
