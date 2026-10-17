"""STRATA S5.1 - safe REAL-OpenSearch test isolation with a POSITIVE test-environment boundary.

The real-OpenSearch validation suite must run against an actual OpenSearch 2.17.1 node with the
Security plugin, NEVER against siem.fake_cluster.FakeCluster. This module is the gate that makes that
safe. It mirrors the design of _pgtest.py for PostgreSQL:

  * Destructive operations (create/delete indices, create/delete security roles and users) are
    refused unless the operator has POSITIVELY authorized a dedicated, disposable node.
  * Authorization is fail-closed: opt-in env var MUST be set, a DEDICATED test URL MUST be given
    (never the app's OPENSEARCH_URL), the host MUST be loopback or explicitly allow-listed, and -
    crucially - a localhost address alone is NOT sufficient (spec S5.1 section 4). A SENTINEL INDEX,
    created once by the operator on the disposable node, must be present; and no production-like
    index may be present on the server.
  * The node must actually be reachable and must self-report as OpenSearch 2.17.1 (an explicit
    opt-out allows a labelled near-version run, never silently).
  * When any check fails the caller SKIPS (pytest.skip). It NEVER substitutes FakeCluster.

Env vars (all required unless noted):
  RANGER_TEST_ALLOW_OS_MUTATION   opt-in: "1"/"true"/"yes"/"on"
  RANGER_TEST_OPENSEARCH_URL      dedicated disposable node base URL, e.g. https://127.0.0.1:9200
  RANGER_TEST_OPENSEARCH_USER     admin user for the disposable node (default "admin")
  RANGER_TEST_OPENSEARCH_PASSWORD admin password for the disposable node
  RANGER_TEST_OS_CA               (optional) CA bundle path for full TLS verification
  RANGER_TEST_OS_SENTINEL_INDEX   (optional) authorizing sentinel index name
                                  (default ".ranger-ostest-sentinel")
  RANGER_TEST_OS_AUTHORIZED_HOSTS (optional) extra comma-separated hostnames to treat as local
  RANGER_TEST_OS_ALLOW_VERSION_MISMATCH (optional) run against a non-2.17.1 node, labelled

The authorizing sentinel is created once, by hand, on a throwaway node:
    PUT https://127.0.0.1:9200/.ranger-ostest-sentinel
It records nothing; its mere presence is the operator's statement "this node is disposable."
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

OPT_IN_ENV = "RANGER_TEST_ALLOW_OS_MUTATION"
URL_ENV = "RANGER_TEST_OPENSEARCH_URL"
USER_ENV = "RANGER_TEST_OPENSEARCH_USER"
PASS_ENV = "RANGER_TEST_OPENSEARCH_PASSWORD"
CA_ENV = "RANGER_TEST_OS_CA"
SENTINEL_ENV = "RANGER_TEST_OS_SENTINEL_INDEX"
AUTHORIZED_HOSTS_ENV = "RANGER_TEST_OS_AUTHORIZED_HOSTS"
ALLOW_VERSION_MISMATCH_ENV = "RANGER_TEST_OS_ALLOW_VERSION_MISMATCH"

DEFAULT_SENTINEL_INDEX = ".ranger-ostest-sentinel"
REQUIRED_VERSION = "2.17.1"
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}

# Index names that indicate a shared/production OpenSearch instance. Their presence refuses the run:
# the real Ranger qualification/operational data must never share a node with destructive tests.
PRODUCTION_LIKE_INDEX_PREFIXES = ("ranger-prod", "ranger-live", ".ranger-qualmeta-prod")


class UnauthorizedTestServer(RuntimeError):
    """The OpenSearch target is not a positively identified, disposable test instance."""


class UnsafeTestIndex(RuntimeError):
    """An index name is not an obvious disposable test index; refusing create/delete."""


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _opt_in() -> bool:
    return _truthy(os.environ.get(OPT_IN_ENV))


def _sentinel_index() -> str:
    return (os.environ.get(SENTINEL_ENV) or DEFAULT_SENTINEL_INDEX).strip()


def _authorized_hosts() -> set:
    raw = os.environ.get(AUTHORIZED_HOSTS_ENV, "") or ""
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def resolve_test_url():
    """The DEDICATED disposable test node URL, or None. Deliberately does NOT fall back to the
    application's OPENSEARCH_URL: a destructive test must never run against the app's own node."""
    url = os.environ.get(URL_ENV)
    return url if url and url.strip().lower().startswith(("http://", "https://")) else None


def _host_of(url: str) -> str:
    from urllib.parse import urlparse
    return (urlparse(url).hostname or "").strip().lower()


def _is_local_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if h in _LOCAL_HOSTS:
        return True
    if h.endswith(".localhost") or h.endswith(".test"):
        return True
    return h in _authorized_hosts()


def _ctx(url: str):
    ca = os.environ.get(CA_ENV)
    if ca:
        return ssl.create_default_context(cafile=ca)
    if url.lower().startswith("http://"):
        return None
    # A disposable local node often uses a self-signed cert; verification is relaxed ONLY for the
    # test node, never for the app. The difference from production TLS is documented in the S5.1 doc.
    return ssl._create_unverified_context()


def _raw_get(url: str, path: str, timeout=10):
    """A tiny stdlib GET against the node (admin basic-auth), returning (status, parsed-json).
    Used for server identification BEFORE constructing the project client, so a bad target is
    diagnosed without importing project state."""
    import base64
    user = os.environ.get(USER_ENV, "admin")
    pw = os.environ.get(PASS_ENV, "")
    req = urllib.request.Request(url.rstrip("/") + path, method="GET")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    ctx = _ctx(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw}


def server_version(url: str):
    """(version_string_or_None, distribution_or_None) from GET / on the node."""
    try:
        code, body = _raw_get(url, "/")
    except Exception:  # noqa: BLE001
        return None, None
    if code != 200 or not isinstance(body, dict):
        return None, None
    ver = (body.get("version") or {})
    return ver.get("number"), ver.get("distribution")


def _index_exists(url: str, index: str) -> bool:
    try:
        import base64
        user = os.environ.get(USER_ENV, "admin")
        pw = os.environ.get(PASS_ENV, "")
        req = urllib.request.Request(url.rstrip("/") + "/" + index, method="HEAD")
        req.add_header("Authorization", "Basic "
                       + base64.b64encode(f"{user}:{pw}".encode()).decode())
        with urllib.request.urlopen(req, timeout=10, context=_ctx(url)) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        return e.code == 200
    except Exception:  # noqa: BLE001
        return False


def _present_indices(url: str) -> set:
    """All non-system index names the node reports (best-effort), for the production-like check."""
    code, body = _raw_get(url, "/_cat/indices?format=json&h=index")
    if code != 200 or not isinstance(body, list):
        return set()
    return {row.get("index", "") for row in body if isinstance(row, dict)}


def assert_authorized_test_server(url=None, *, probe=True):
    """Positively identify the target as an authorized, disposable OpenSearch test node, or raise
    UnauthorizedTestServer. Host check runs FIRST (no connection) so a remote/production-like target
    is refused before any mutation. With probe=True the node is contacted to confirm reachability,
    version, the authorizing sentinel index, and the absence of production-like indices."""
    url = url or resolve_test_url()
    if not url:
        raise UnauthorizedTestServer(f"{URL_ENV} not set (a dedicated disposable node is required)")
    host = _host_of(url)
    if not _is_local_host(host):
        raise UnauthorizedTestServer(
            f"refusing destructive tests against non-local host {host!r}: not loopback and not in "
            f"{AUTHORIZED_HOSTS_ENV}")
    if not probe:
        return True
    # reachable + real OpenSearch
    ver, dist = server_version(url)
    if ver is None:
        raise UnauthorizedTestServer(
            f"cannot reach or identify an OpenSearch node at {url} (no version from GET /)")
    if (dist or "").lower() != "opensearch":
        raise UnauthorizedTestServer(f"target at {url} is not OpenSearch (distribution={dist!r})")
    if ver != REQUIRED_VERSION and not _truthy(os.environ.get(ALLOW_VERSION_MISMATCH_ENV)):
        raise UnauthorizedTestServer(
            f"node version {ver} != required {REQUIRED_VERSION}; set {ALLOW_VERSION_MISMATCH_ENV}=1 "
            f"to run against a near version (clearly labelled), or use a 2.17.1 node")
    # no production-like data may share this node
    present = _present_indices(url)
    prod = sorted(i for i in present
                  if any(i.startswith(p) for p in PRODUCTION_LIKE_INDEX_PREFIXES))
    if prod:
        raise UnauthorizedTestServer(
            f"refusing: node hosts production-like index(es) {prod}; not a dedicated test instance")
    # the authorizing sentinel must be present (localhost alone is not proof)
    sentinel = _sentinel_index()
    if not _index_exists(url, sentinel):
        raise UnauthorizedTestServer(
            f"authorizing sentinel index {sentinel!r} is absent; create it once on a dedicated "
            f"disposable node (PUT /{sentinel}) to authorize destructive tests (fail-closed)")
    return True


def authorization_status():
    """(ok, reason). Never raises. Used by the suite to skip fail-closed."""
    if not _opt_in():
        return False, f"{OPT_IN_ENV} not set"
    url = resolve_test_url()
    if not url:
        return False, f"{URL_ENV} not set (dedicated disposable OpenSearch node required)"
    try:
        assert_authorized_test_server(url)
    except UnauthorizedTestServer as e:
        return False, str(e)
    return True, "authorized"


def require_authorized_or_skip():
    """Skip the calling test fail-closed unless a positively authorized disposable node is present.
    Returns the node URL when authorized. NEVER returns or implies a FakeCluster fallback."""
    ok, reason = authorization_status()
    if not ok:
        pytest.skip(f"no authorized real OpenSearch 2.17.1 node: {reason}")
    return resolve_test_url()


def admin_cluster():
    """A REAL siem.live.LiveCluster bound to the authorized disposable node with admin credentials.
    Only call after require_authorized_or_skip(). Never a double."""
    from siem.live import LiveCluster
    url = resolve_test_url()
    return LiveCluster(
        url,
        os.environ.get(USER_ENV, "admin"),
        os.environ.get(PASS_ENV, ""),
        ca_path=os.environ.get(CA_ENV) or None,
        verify_tls=bool(os.environ.get(CA_ENV)),
        timeout=30,
    )


def candidate_cluster(username, password):
    """A REAL LiveCluster that authenticates AS a candidate internal user, to prove the Security
    plugin (not Ranger) enforces isolation/DLS. Admin field holds the candidate's own basic-auth."""
    from siem.live import LiveCluster
    url = resolve_test_url()
    return LiveCluster(url, username, password,
                       ca_path=os.environ.get(CA_ENV) or None,
                       verify_tls=bool(os.environ.get(CA_ENV)), timeout=30)


def guard_disposable_index(index: str, test_marker: str):
    """Refuse any index name that is not an obvious disposable test index for THIS run. Called before
    any create/delete so a production/shared index can never be the target. The marker is the unique
    per-run token embedded in every index the suite creates."""
    if not index or test_marker not in index:
        raise UnsafeTestIndex(
            f"refusing to create/delete {index!r}: not a disposable test index for marker "
            f"{test_marker!r}")
    return index


@contextmanager
def isolated_os_namespace(prefix="ostest"):
    """Yield a unique, disposable cohort token for one test and CLEAN UP afterward: delete every
    index whose name carries the token, remove the matching .ranger-qualmeta stamp(s), and delete any
    candidate roles/users/rolesmappings created under the token. Safe because every name the suite
    derives (authz.qualification_index_name / role_name / user_name) is built from this cohort token,
    so the marker check positively scopes all destructive cleanup to this run.

    Yields a dict: {"cohort", "marker", "cluster", "created_indices", "created_principals"}.
    created_indices / created_principals are lists the test appends to so cleanup is exhaustive."""
    import secrets as _secrets
    require_authorized_or_skip()
    token = f"{prefix}-{_secrets.token_hex(4)}"
    cl = admin_cluster()
    state = {"cohort": token, "marker": token, "cluster": cl,
             "created_indices": [], "created_principals": []}
    try:
        yield state
    finally:
        # delete indices created under this token (marker-guarded)
        for idx in list(dict.fromkeys(state["created_indices"])):
            try:
                guard_disposable_index(idx, token)
                cl.delete_index(idx)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        # remove this run's qual-meta stamps by _id (never delete the shared meta index wholesale)
        for idx in list(dict.fromkeys(state["created_indices"])):
            try:
                cl._req("DELETE", f"/.ranger-qualmeta/_doc/{idx}")
            except Exception:  # noqa: BLE001
                pass
        # delete candidate roles/users/rolesmappings created under this token
        for principal in list(dict.fromkeys(state["created_principals"])):
            if token not in principal:
                continue
            for op in (lambda: cl.delete_rolesmapping(principal),
                       lambda: cl.delete_user(principal),
                       lambda: cl.delete_role(principal)):
                try:
                    op()
                except Exception:  # noqa: BLE001
                    pass
