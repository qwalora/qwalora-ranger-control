"""OpenSearch client interface, with a security-enforcing in-process fake.

Two implementations behind one interface:

- FakeOpenSearch: an in-process store that enforces the SAME authorization model
  the real cluster will (per-user roles granting read on specific index patterns,
  plus optional document-level security). This lets the isolation tests prove, here
  and now, that candidate A cannot read candidate B's index at the API layer, not
  just in a UI. The same tests run against RealOpenSearch once the node exists.

- RealOpenSearch: a thin HTTPS client against a live cluster's REST API using the
  Security plugin. It is NOT exercised in this environment (no cluster); it is the
  code that runs after the node is approved and provisioned.

Terminology mirrors the OpenSearch Security model: a Role grants index-pattern
privileges (+ optional DLS query); a RoleMapping binds a user to roles.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field


class AuthorizationError(Exception):
    """Raised when a user attempts an action its roles do not permit (HTTP 403)."""


class NotFoundError(Exception):
    """Index does not exist (HTTP 404)."""


@dataclass
class Role:
    name: str
    index_patterns: list[str]          # patterns this role may read
    allow_write: bool = False          # only the broker/admin writes
    dls: dict | None = None            # document-level security term filter, e.g. {"ranger.candidate_id": "c1"}


@dataclass
class _User:
    name: str
    roles: list[str] = field(default_factory=list)


class FakeOpenSearch:
    """In-process OpenSearch with Security-plugin-equivalent authorization."""

    ADMIN = "_broker_admin"  # the broker's privileged identity

    def __init__(self):
        self._indices: dict[str, list[dict]] = {}
        self._roles: dict[str, Role] = {}
        self._users: dict[str, _User] = {}
        # The broker admin: full index access, read+write. Held only by the broker.
        self._roles["admin"] = Role("admin", ["*"], allow_write=True)
        self._users[self.ADMIN] = _User(self.ADMIN, ["admin"])

    # --- security administration (broker only) ---------------------------
    def put_role(self, as_user: str, role: Role):
        self._require_admin(as_user)
        self._roles[role.name] = role

    def put_user(self, as_user: str, name: str, roles: list[str]):
        self._require_admin(as_user)
        self._users[name] = _User(name, list(roles))

    def delete_user(self, as_user: str, name: str):
        self._require_admin(as_user)
        self._users.pop(name, None)

    def delete_role(self, as_user: str, name: str):
        self._require_admin(as_user)
        self._roles.pop(name, None)

    def _require_admin(self, as_user: str):
        if as_user != self.ADMIN:
            raise AuthorizationError("admin privilege required")

    # --- index lifecycle (broker only) ----------------------------------
    def create_index(self, as_user: str, index: str, mapping: dict | None = None):
        self._require_admin(as_user)
        self._indices.setdefault(index, [])

    def delete_index(self, as_user: str, index: str):
        self._require_admin(as_user)
        self._indices.pop(index, None)

    def index_exists(self, index: str) -> bool:
        return index in self._indices

    def list_indices(self, as_user: str) -> list[str]:
        self._require_admin(as_user)
        return sorted(self._indices)

    # --- data plane ------------------------------------------------------
    def bulk_index(self, as_user: str, index: str, docs: list[dict]) -> int:
        if not self._can_write(as_user, index):
            raise AuthorizationError(f"{as_user} may not write {index}")
        if index not in self._indices:
            raise NotFoundError(index)
        existing = {d.get("_id") for d in self._indices[index]}
        added = 0
        for d in docs:
            _id = d["_id"]
            if _id in existing:         # idempotent: same _id is an upsert, not a dupe
                for i, cur in enumerate(self._indices[index]):
                    if cur.get("_id") == _id:
                        self._indices[index][i] = d
                        break
            else:
                self._indices[index].append(d)
                existing.add(_id)
                added += 1
        return added

    def count(self, as_user: str, index: str) -> int:
        return len(self._read(as_user, index))

    def search(self, as_user: str, index: str, query: dict | None = None) -> list[dict]:
        """Return matching source docs. Enforces role index-pattern access first
        (403 if not permitted), then applies the role's DLS filter, then the query."""
        docs = self._read(as_user, index)
        return [d["_source"] for d in docs if _matches(d["_source"], query)]

    # --- authorization core ---------------------------------------------
    def _read(self, as_user: str, index: str) -> list[dict]:
        user = self._users.get(as_user)
        if user is None:
            raise AuthorizationError(f"unknown user {as_user}")
        if not self._index_permitted(user, index):
            # Mirrors OpenSearch returning 403 for an index the role cannot see.
            raise AuthorizationError(f"{as_user} may not read {index}")
        if index not in self._indices:
            raise NotFoundError(index)
        dls = self._effective_dls(user)
        docs = self._indices[index]
        if dls:
            field_, val = next(iter(dls.items()))
            docs = [d for d in docs if _get(d["_source"], field_) == val]
        return docs

    def _index_permitted(self, user: _User, index: str) -> bool:
        for rn in user.roles:
            role = self._roles.get(rn)
            if role and any(fnmatch.fnmatch(index, p) for p in role.index_patterns):
                return True
        return False

    def _can_write(self, as_user: str, index: str) -> bool:
        user = self._users.get(as_user)
        if not user:
            return False
        return any(self._roles.get(rn) and self._roles[rn].allow_write
                   and any(fnmatch.fnmatch(index, p) for p in self._roles[rn].index_patterns)
                   for rn in user.roles)

    def _effective_dls(self, user: _User) -> dict | None:
        for rn in user.roles:
            role = self._roles.get(rn)
            if role and role.dls:
                return role.dls
        return None


def _get(doc: dict, dotted: str):
    cur = doc
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _matches(source: dict, query: dict | None) -> bool:
    """A tiny subset of query DSL: {'term': {field: value}} and {'match_all': {}}."""
    if not query or "match_all" in query:
        return True
    if "term" in query:
        field_, val = next(iter(query["term"].items()))
        return _get(source, field_) == val
    if "range" in query:
        field_, bounds = next(iter(query["range"].items()))
        v = _get(source, field_)
        if v is None:
            return False
        if "gte" in bounds and v < bounds["gte"]:
            return False
        if "lte" in bounds and v > bounds["lte"]:
            return False
        return True
    return True


class RealOpenSearch:
    """HTTPS client against a live cluster (Security plugin). Not run in this
    environment; present so the broker and tests target one interface. Requires
    `requests`; all calls go over TLS with the admin credential held by the broker."""

    def __init__(self, base_url: str, admin_auth: tuple[str, str], verify_tls=True):
        self.base = base_url.rstrip("/")
        self.auth = admin_auth
        self.verify = verify_tls

    def _requests(self):
        import requests  # imported lazily; only needed against a real cluster
        return requests

    def create_index(self, as_user, index, mapping=None):
        r = self._requests()
        resp = r.put(f"{self.base}/{index}", auth=self.auth, verify=self.verify,
                     headers={"Content-Type": "application/json"},
                     data=json.dumps(mapping or {}))
        resp.raise_for_status()

    def bulk_index(self, as_user, index, docs):
        r = self._requests()
        lines = []
        for d in docs:
            lines.append(json.dumps({"index": {"_index": index, "_id": d["_id"]}}))
            lines.append(json.dumps(d["_source"]))
        body = "\n".join(lines) + "\n"
        resp = r.post(f"{self.base}/_bulk", auth=self.auth, verify=self.verify,
                      headers={"Content-Type": "application/x-ndjson"}, data=body)
        resp.raise_for_status()
        return len(docs)

    # put_role / put_user / search etc. mirror the Security and _search APIs; omitted
    # here because they are only exercised against the live cluster after approval.
