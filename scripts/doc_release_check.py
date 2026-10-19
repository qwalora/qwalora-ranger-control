#!/usr/bin/env python3
"""Release-aligned documentation validation (section C of the Living-Handbook task).

This is the controlled check that must pass before a release is considered documentation-safe.
It validates that candidate-facing documentation claims still match the deployed application,
so the handbook/docs cannot silently fall behind the implementation (stale-document detection),
and it emits release metadata (app commit, timestamp, doc versions) for the release record.

What it checks (fail-closed; any failure exits non-zero):
  1. Every candidate-facing ROUTE the docs rely on still exists in the Flask URL map.
  2. Per-board ENVIRONMENT facts the docs state still hold (Board 1 portal-hosted dataset;
     Board 2 OpenSearch SIEM; Boards 5-6 isolated range) — so docs never describe the wrong
     platform.
  3. The candidate Handbook link points at the authoritative published manual URL (not the
     removed /handbook path).
  4. Internal relative links inside docs/ resolve to files that exist.

It does NOT publish anything and does NOT assert the live public PDF is current — publication
to ranger.qwalora.com is a separate, authorized step (see HANDBOOK_AUDIT_DISCREPANCY_REGISTER.md).

Usage:  python scripts/doc_release_check.py            # human-readable, exits 0/1
        python scripts/doc_release_check.py --json      # machine-readable report
"""
import json
import os
import re
import subprocess
import sys
import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Candidate-facing routes the documentation depends on. If any is renamed/removed, the docs
# that reference it are stale and this check fails.
REQUIRED_ROUTES = [
    "/me", "/me/workspace", "/me/workspace/data", "/me/workspace/draft",
    "/me/workspace/incident", "/me/workspace/incident/data", "/me/workspace/incident/draft",
    "/me/report", "/me/report/draft", "/me/mission",
    "/account", "/parallax/workspace", "/resources",
]

# Per-board environment facts the docs state (board -> expected environment_kind).
EXPECTED_ENV_KIND = {1: "dataset", 2: "siem", 3: "dataset", 4: "dataset", 5: "range", 6: "range"}

# The authoritative published handbook (the "Ranger manual"); the removed /handbook path 404s.
HANDBOOK_URL = "https://ranger.qwalora.com/downloads/Qwalora-Ranger-Manual.pdf"
BROKEN_HANDBOOK = "ranger.qwalora.com/handbook"


def _app_routes():
    os.environ.setdefault("SECRET_KEY", "doc-release-check")
    os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
    os.environ.setdefault("DEFAULT_COHORT", "2026-A")
    import app as appmod
    application = appmod.create_app()
    rules = set()
    for r in application.url_map.iter_rules():
        rules.add(str(r.rule))
    return rules


def _git_commit():
    try:
        return subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def run_check():
    failures = []
    routes = _app_routes()

    # 1. required candidate-facing routes exist
    for rt in REQUIRED_ROUTES:
        if rt not in routes:
            failures.append(f"route-missing: documented route {rt} no longer exists in the app")

    # 2. per-board environment facts still hold
    import strata_missions
    for board, kind in EXPECTED_ENV_KIND.items():
        pkg = strata_missions.get(board)
        actual = (pkg or {}).get("environment_kind")
        if actual != kind:
            failures.append(f"env-drift: board {board} documented as '{kind}' but is '{actual}'")

    # 2b. Board-2 OpenSearch must never be reported available unless actually configured
    #     (no false OpenSearch promise).
    import os as _os
    gateway_cfg = bool(_os.environ.get("RANGER_JWT_PRIVATE_B64")
                       and _os.environ.get("OPENSEARCH_ADMIN_PASSWORD")
                       and _os.environ.get("RANGER_CASE_UI", "").strip().lower()
                       in ("1", "true", "yes", "on"))
    b2 = strata_missions.environment_availability(2)
    if b2["available"] and not gateway_cfg:
        failures.append("false-opensearch-promise: board 2 reports available without the SOC "
                        "gateway + Board-2 UI configured")

    # 3. handbook link is authoritative, not the broken path
    candnav = os.path.join(ROOT, "templates", "_candnav.html")
    if os.path.exists(candnav):
        txt = open(candnav).read()
        if HANDBOOK_URL not in txt:
            failures.append("handbook-link: candidate nav does not point at the authoritative manual")
        if BROKEN_HANDBOOK in txt:
            failures.append("handbook-link: candidate nav still references the broken /handbook path")

    # 4. required candidate-facing documents exist (a release must not drop them)
    for rel in ("docs/handbook/RANGER_CANDIDATE_HANDBOOK.md",
                "docs/HANDBOOK_AUDIT_DISCREPANCY_REGISTER.md",
                "docs/RELEASE_DOC_VALIDATION.md"):
        if not os.path.exists(os.path.join(ROOT, rel)):
            failures.append(f"doc-missing: required document {rel} is absent")

    # 5. internal relative links inside docs/ (recursively) resolve
    docs_dir = os.path.join(ROOT, "docs")
    link_re = re.compile(r"\[[^\]]+\]\((?!https?://|#|mailto:)([^)]+)\)")
    for base, _dirs, files in os.walk(docs_dir):
        if os.sep + "dist" in base:   # skip generated build outputs
            continue
        for fn in files:
            if not fn.endswith(".md"):
                continue
            path = os.path.join(base, fn)
            for m in link_re.finditer(open(path).read()):
                target = m.group(1).split("#", 1)[0].strip()
                if not target:
                    continue
                resolved = os.path.normpath(os.path.join(base, target))
                if not os.path.exists(resolved):
                    failures.append(f"broken-internal-link: {os.path.relpath(path, ROOT)} -> {target}")

    metadata = {
        "app_git_commit": _git_commit(),
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "deployment_id": os.environ.get("RANGER_DEPLOYMENT_ID", "unset"),
        "ranger_env": os.environ.get("RANGER_ENV", "unset"),
        "required_routes_verified": len(REQUIRED_ROUTES),
        "boards_env_verified": len(EXPECTED_ENV_KIND),
        "handbook_url": HANDBOOK_URL,
    }
    return {"ok": not failures, "failures": failures, "metadata": metadata}


def main():
    as_json = "--json" in sys.argv
    result = run_check()
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print("Documentation release check")
        print("  commit:     ", result["metadata"]["app_git_commit"])
        print("  checked_at: ", result["metadata"]["checked_at"])
        print("  routes:     ", result["metadata"]["required_routes_verified"], "verified")
        print("  boards:     ", result["metadata"]["boards_env_verified"], "env facts verified")
        if result["ok"]:
            print("RESULT: PASS")
        else:
            print("RESULT: FAIL")
            for f in result["failures"]:
                print("  -", f)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
