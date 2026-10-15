"""Live OpenSearch client over the Security plugin REST API (stdlib only).

This is the real counterpart to client.FakeOpenSearch. It talks to a running
cluster over HTTPS using the Security plugin, with the admin credential held by
the Ranger backend (the broker). It is deliberately written on urllib + ssl so it
adds no dependency to the portal image.

Access model it enforces on the real cluster, mirroring authz.py:
  - per-candidate internal user with a generated password
  - per-candidate security role: read-only on that candidate's index pattern,
    with document-level security on ranger.candidate_id
  - the broker (admin) is the only writer; candidates authenticate as themselves,
    so a cross-candidate read is refused by OpenSearch with 403, not by Ranger.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request


class LiveError(Exception):
    pass


class AuthzError(LiveError):
    """OpenSearch refused the action (HTTP 403)."""


class NotFound(LiveError):
    """HTTP 404."""


class LiveCluster:
    def __init__(self, base_url: str, admin_user: str, admin_password: str,
                 verify_tls: bool = False, timeout: int = 30, ca_path: str | None = None):
        self.base = base_url.rstrip("/")
        self.admin = (admin_user, admin_password)
        self.timeout = timeout
        if ca_path:
            # Verify the node certificate against the Ranger CA (full verification).
            self._ctx = ssl.create_default_context(cafile=ca_path)
        elif verify_tls:
            self._ctx = ssl.create_default_context()
        else:
            self._ctx = ssl._create_unverified_context()

    # --- transport -------------------------------------------------------
    def _req(self, method, path, body=None, auth=None, ndjson=False):
        url = self.base + path
        headers = {}
        data = None
        if body is not None:
            if ndjson:
                data = body.encode()
                headers["Content-Type"] = "application/x-ndjson"
            else:
                data = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
        u, p = auth or self.admin
        headers["Authorization"] = "Basic " + base64.b64encode(
            f"{u}:{p}".encode()).decode()
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=self.timeout) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                parsed = json.loads(raw)
            except Exception:  # noqa: BLE001
                parsed = {"raw": raw}
            return e.code, parsed

    # --- cluster ---------------------------------------------------------
    def health(self):
        return self._req("GET", "/_cluster/health")

    def node_stats(self):
        return self._req("GET", "/_nodes/stats/jvm,os,fs,indices")

    def refresh(self, index):
        return self._req("POST", f"/{index}/_refresh")

    # --- index lifecycle (admin) ----------------------------------------
    def create_index(self, index, mapping=None):
        code, body = self._req("PUT", f"/{index}", body=mapping or {})
        if code not in (200, 201) and not (
                code == 400 and "resource_already_exists" in json.dumps(body)):
            raise LiveError(f"create_index {index}: {code} {body}")
        return body

    def index_exists(self, index):
        code, _ = self._req("HEAD", f"/{index}")
        return code == 200

    def delete_index(self, index):
        return self._req("DELETE", f"/{index}")

    def bulk_index(self, index, docs):
        lines = []
        for d in docs:
            lines.append(json.dumps({"index": {"_index": index, "_id": d["_id"]}}))
            lines.append(json.dumps(d["_source"]))
        body = "\n".join(lines) + "\n"
        code, resp = self._req("POST", "/_bulk", body=body, ndjson=True)
        if code not in (200, 201):
            raise LiveError(f"bulk {index}: {code} {resp}")
        errors = resp.get("errors")
        indexed = sum(1 for it in resp.get("items", [])
                      if it.get("index", {}).get("status") in (200, 201))
        return {"indexed": indexed, "errors": bool(errors), "took": resp.get("took")}

    def count(self, index, auth=None):
        code, body = self._req("GET", f"/{index}/_count", auth=auth)
        if code == 403:
            raise AuthzError(f"{auth[0] if auth else 'admin'} may not count {index}")
        if code == 404:
            raise NotFound(index)
        if code != 200:
            raise LiveError(f"count {index}: {code} {body}")
        return body.get("count", 0)

    def search(self, index, query=None, auth=None, size=1000):
        body = {"size": size, "query": query or {"match_all": {}}}
        code, resp = self._req("GET", f"/{index}/_search", body=body, auth=auth)
        if code == 403:
            raise AuthzError(f"{auth[0] if auth else 'admin'} may not read {index}")
        if code == 404:
            raise NotFound(index)
        if code != 200:
            raise LiveError(f"search {index}: {code} {resp}")
        return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]

    # --- security API (admin) -------------------------------------------
    def put_role(self, name, index_patterns, dls=None, allow_write=False,
                 cluster_perms=None):
        actions = ["read", "search", "indices:data/read/*", "indices:admin/mappings/get"]
        if allow_write:
            actions += ["write", "indices:data/write/*", "indices:admin/create"]
        perm = {"index_patterns": index_patterns, "allowed_actions": actions}
        if dls:
            field, val = next(iter(dls.items()))
            perm["dls"] = json.dumps({"term": {field: val}})
        role = {"cluster_permissions": cluster_perms or [],
                "index_permissions": [perm]}
        code, body = self._req("PUT", f"/_plugins/_security/api/roles/{name}", body=role)
        if code not in (200, 201):
            raise LiveError(f"put_role {name}: {code} {body}")
        return body

    def put_user(self, name, password, roles):
        payload = {"password": password, "opendistro_security_roles": list(roles)}
        code, body = self._req(
            "PUT", f"/_plugins/_security/api/internalusers/{name}", body=payload)
        if code not in (200, 201):
            raise LiveError(f"put_user {name}: {code} {body}")
        return body

    def delete_user(self, name):
        return self._req("DELETE", f"/_plugins/_security/api/internalusers/{name}")

    def delete_role(self, name):
        return self._req("DELETE", f"/_plugins/_security/api/roles/{name}")

    def get_user(self, name):
        return self._req("GET", f"/_plugins/_security/api/internalusers/{name}")

    # --- Security Analytics ---------------------------------------------
    def sa_create_rule(self, category, rule_yaml):
        return self._req("POST",
                         f"/_plugins/_security_analytics/rules?category={category}",
                         body={"rule": rule_yaml} if isinstance(rule_yaml, str) else rule_yaml)

    def sa_create_detector(self, detector):
        return self._req("POST", "/_plugins/_security_analytics/detectors", body=detector)

    def sa_search_findings(self, detector_type=None):
        path = "/_plugins/_security_analytics/findings/_search"
        if detector_type:
            path += f"?detectorType={detector_type}"
        return self._req("GET", path)

    def sa_get_detector(self, detector_id):
        return self._req("GET", f"/_plugins/_security_analytics/detectors/{detector_id}")
