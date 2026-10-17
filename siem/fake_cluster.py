"""An in-process DOUBLE of siem.live.LiveCluster for S5 integration tests.

This is NOT a live OpenSearch. It is a faithful stand-in that implements the exact LiveCluster
method surface the S5 provisioning, the /soc role/DLS model, and the case_contract LiveReader use -
including the `_req(...)` transport those readers call - and enforces the SAME authorization model
the real cluster does: a per-user security role granting read on an index pattern, plus optional
document-level security on `ranger.candidate_id`. It exists so ingestion, search, per-candidate
isolation and evidence reproduction can be exercised deterministically where no disposable OpenSearch
node is available.

Results obtained against this double are labelled as such in the S5 report: they demonstrate the
Ranger-side logic and the authorization contract, and are NOT a substitute for live OpenSearch
validation, which remains a separate requirement.
"""
from __future__ import annotations

import fnmatch
import json


def _get(doc, dotted):
    cur = doc
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _match(source, q):
    """A small subset of the query DSL: match_all, term, range, ids, wildcard, exists, bool/must."""
    if not q or "match_all" in q:
        return True
    if "bool" in q:
        must = q["bool"].get("must", [])
        if isinstance(must, dict):
            must = [must]
        return all(_match(source, m) for m in must)
    if "ids" in q:
        return True   # id filtering is applied by the caller against the doc _id
    if "term" in q:
        f, v = next(iter(q["term"].items()))
        return _get(source, f) == v
    if "match" in q:
        f, v = next(iter(q["match"].items()))
        return str(v).lower() in str(_get(source, f) or "").lower()
    if "wildcard" in q:
        f, pat = next(iter(q["wildcard"].items()))
        if isinstance(pat, dict):
            pat = pat.get("value", "")
        return fnmatch.fnmatch(str(_get(source, f) or ""), str(pat))
    if "range" in q:
        f, b = next(iter(q["range"].items()))
        v = _get(source, f)
        if v is None:
            return False
        if "gte" in b and v < b["gte"]:
            return False
        if "lte" in b and v > b["lte"]:
            return False
        return True
    if "exists" in q:
        return _get(source, q["exists"].get("field", "")) is not None
    return True


class FakeCluster:
    """In-process LiveCluster double. `admin_ok` identities (the broker) have full access; a mapped
    candidate user is scoped by its role's index pattern + DLS."""

    def __init__(self):
        self._idx: dict[str, dict] = {}         # index -> {_id: _source}
        self._roles: dict[str, dict] = {}        # name -> {patterns, dls, allow_write}
        self._mapping: dict[str, set] = {}       # role -> {users}
        self.admin = ("admin", "admin")          # broker identity tuple

    # --- index lifecycle (admin) ---
    def create_index(self, index, mapping=None):
        self._idx.setdefault(index, {})
        return {"acknowledged": True}

    def index_exists(self, index):
        return index in self._idx

    def delete_index(self, index):
        self._idx.pop(index, None)
        return 200, {}

    def refresh(self, index):
        return 200, {}

    def bulk_index(self, index, docs):
        if index not in self._idx:
            self._idx[index] = {}
        indexed = 0
        for d in docs:
            self._idx[index][d["_id"]] = d["_source"]   # upsert by _id (idempotent/retry-safe)
            indexed += 1
        return {"indexed": indexed, "errors": False, "took": 1}

    # --- authorization resolution ---
    def _roles_for(self, user):
        return [rn for rn, m in self._mapping.items() if user in m]

    def _authorize_read(self, index, auth):
        if auth is None or tuple(auth) == tuple(self.admin) or auth[0] == "admin":
            return None     # admin: no DLS
        user = auth[0]
        roles = self._roles_for(user)
        if not roles:
            from siem.live import AuthzError
            raise AuthzError(f"{user} has no roles")
        permitted = False
        dls = None
        for rn in roles:
            role = self._roles.get(rn) or {}
            if any(fnmatch.fnmatch(index, p) for p in role.get("patterns", [])):
                permitted = True
                if role.get("dls"):
                    dls = role["dls"]
        if not permitted:
            from siem.live import AuthzError
            raise AuthzError(f"{user} may not read {index}")
        return dls

    def _rows(self, index, auth):
        from siem.live import NotFound
        dls = self._authorize_read(index, auth)
        if index not in self._idx:
            raise NotFound(index)
        rows = [{"_id": _id, "_source": src} for _id, src in self._idx[index].items()]
        if dls:
            f, v = next(iter(dls.items()))
            rows = [r for r in rows if _get(r["_source"], f) == v]
        return rows

    def count(self, index, auth=None):
        return len(self._rows(index, auth))

    def search(self, index, query=None, auth=None, size=1000):
        rows = self._rows(index, auth)
        return [r["_source"] for r in rows if _match(r["_source"], query)][:size]

    # --- security API (admin) ---
    def put_role(self, name, index_patterns, dls=None, allow_write=False,
                 cluster_perms=None, tenant_permissions=None):
        self._roles[name] = {"patterns": list(index_patterns), "dls": dls,
                             "allow_write": allow_write}
        return {"status": "OK"}

    def put_rolesmapping(self, role, users=None, backend_roles=None):
        self._mapping.setdefault(role, set()).update(users or [])
        return {"status": "OK"}

    def delete_role(self, name):
        self._roles.pop(name, None)
        return 200, {}

    def delete_rolesmapping(self, role):
        self._mapping.pop(role, None)
        return 200, {}

    # --- transport shim (_req) used by strata_board2.read_index_meta and the case_routes LiveReader ---
    def _req(self, method, path, body=None, auth=None, ndjson=False, bearer=None, timeout=None):
        parts = path.strip("/").split("/")
        # GET /{index}/_doc/{id} - enforce the SAME scoped-role + DLS authorization as search. A
        # direct document read is not a bypass: an unauthorized candidate is denied (AuthzError, as
        # the real Security plugin returns 403), and a document outside the role's DLS term is hidden
        # (404), while the broker admin reads unrestricted.
        if method == "GET" and len(parts) == 3 and parts[1] == "_doc":
            index, _id = parts[0], parts[2]
            dls = self._authorize_read(index, auth)   # raises AuthzError if the role may not read it
            src = self._idx.get(index, {}).get(_id)
            if src is None:
                return 404, {"found": False}
            if dls:
                f, v = next(iter(dls.items()))
                if _get(src, f) != v:
                    return 404, {"found": False}       # DLS hides a document outside the term
            return 200, {"found": True, "_id": _id, "_source": src}
        # GET /{index}/_search
        if method == "GET" and len(parts) == 2 and parts[1] == "_search":
            index = parts[0]
            q = (body or {}).get("query") or {}
            # extract an ids filter if present (query_matches uses bool.must with an ids clause)
            want_ids = None
            clauses = []
            if "bool" in q:
                must = q["bool"].get("must", [])
                if isinstance(must, dict):
                    must = [must]
                for m in must:
                    if "ids" in m:
                        want_ids = set(m["ids"].get("values", []))
                    else:
                        clauses.append(m)
            else:
                clauses = [q]
            try:
                rows = self._rows(index, auth)
            except Exception:  # noqa: BLE001 - mirror a 403/404 as an empty/miss for the reader
                return 403, {"hits": {"total": {"value": 0}, "hits": []}}
            hits = []
            for r in rows:
                if want_ids is not None and r["_id"] not in want_ids:
                    continue
                if all(_match(r["_source"], c) for c in clauses):
                    hits.append({"_id": r["_id"], "_source": r["_source"]})
            return 200, {"hits": {"total": {"value": len(hits)}, "hits": hits}}
        if method == "POST" and path.endswith("/_refresh"):
            return 200, {}
        if method == "HEAD":
            return (200 if parts[0] in self._idx else 404), {}
        return 400, {"error": f"unsupported in FakeCluster: {method} {path}"}

    # convenience for tests / provisioning parity with LiveCluster
    def health(self):
        return 200, {"status": "green"}

    def raw_source(self, index, _id):
        return self._idx.get(index, {}).get(_id)

    def dump(self, index):
        return json.loads(json.dumps(list(self._idx.get(index, {}).values())))
