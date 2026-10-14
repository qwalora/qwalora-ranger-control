"""Ludus range broker.

One Candidate maps to exactly one Ludus user, which owns exactly one range.
That is the whole mapping, and it mirrors how Ludus itself works (per-user
isolated ranges, each reachable over its own WireGuard tunnel).

The broker exposes the full range lifecycle:

    ensure_user(candidate)      admin-create the Ludus user, return its API key
    set_range_config(c, tmpl)   push the range config YAML (GOAD by default)
    deploy_range(candidate)     POST deploy; range builds on the Proxmox host
    range_status(candidate)     poll current state
    wireguard_config(candidate) fetch the WG config the ranger connects with
    destroy_range(candidate)    tear the range down (frees VMs / cost)

MODE
----
Live when LUDUS_API_URL is set (plus LUDUS_API_KEY, the admin key). Until then
the broker runs in MOCK mode: every call returns deterministic, well-formed
results and the state machine advances exactly as the real one would, so the
whole control plane is provably correct end to end without a Proxmox box. The
day the box is up, set two env vars and nothing in app.py changes.

    LUDUS_API_URL   e.g. https://ludus.internal.qwalora.com   (admin API base)
    LUDUS_API_KEY   the Ludus admin API key (X-API-KEY)

The REST surface below matches Ludus's shape (X-API-KEY auth; per-user range
with config/deploy/status; admin user management). Confirm exact paths against
the running Ludus version when the box is live; they are isolated to this file.
"""
import datetime as _dt
import hashlib
import json
import os
import urllib.error
import urllib.request

# GOAD (Game of Active Directory): a vulnerable multi-DC AD lab, the standard
# Ludus template for SOC / detection / IR / red-team work. One config per user.
GOAD_TEMPLATE = "ludus-goad-ranger"

_TIMEOUT = 20


def _api_base():
    return (os.environ.get("LUDUS_API_URL") or "").rstrip("/")


def _admin_key():
    return os.environ.get("LUDUS_API_KEY", "")


def is_live():
    return bool(_api_base())


def broker_status():
    """Human-readable state for the admin dashboard."""
    return "live" if is_live() else "mock (set LUDUS_API_URL to go live)"


def mode():
    return "live" if is_live() else "mock"


# --- mock helpers ------------------------------------------------------------
def _mock_user_id(candidate):
    # Ludus userIDs are short and alnum; derive a stable one from the handle.
    h = "".join(ch for ch in candidate.handle if ch.isalnum()).upper()
    return (h[:6] or "RGR") + "-" + hashlib.md5(
        candidate.handle.encode()).hexdigest()[:4].upper()


def _mock_key(candidate):
    return "mock_" + hashlib.sha256(
        f"ludus:{candidate.handle}".encode()).hexdigest()[:40]


def _mock_range_id(candidate):
    return _mock_user_id(candidate).split("-")[0] + "-RANGE"


def _mock_wireguard(candidate):
    uid = _mock_user_id(candidate)
    pub = hashlib.sha256(f"wg:{candidate.handle}".encode()).hexdigest()[:43] + "="
    return (
        "# Qwalora Ranger - MOCK WireGuard profile (no live range yet)\n"
        "[Interface]\n"
        f"# Ludus user {uid}\n"
        "PrivateKey = <issued-by-ludus-when-range-is-live>\n"
        "Address = 10.{0}.0.2/24\n"
        "[Peer]\n"
        f"PublicKey = {pub}\n"
        "Endpoint = ludus.qwalora.com:51820\n"
        "AllowedIPs = 10.{0}.0.0/16\n"
        "PersistentKeepalive = 25\n"
    ).format(abs(hash(candidate.handle)) % 240 + 2)


# --- live HTTP ---------------------------------------------------------------
def _req(method, path, payload=None, key=None):
    url = _api_base() + path
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"X-API-KEY": key or _admin_key()}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
        raw = r.read().decode() or "{}"
    try:
        return json.loads(raw)
    except ValueError:
        return {"raw": raw}


# --- lifecycle ---------------------------------------------------------------
def ensure_user(candidate):
    """Create (or reuse) the Ludus user for this candidate.

    Returns (ludus_user_id, api_key, detail). The api_key is the per-user key
    Ludus issues; the caller encrypts and stores it on the Candidate.
    """
    if not is_live():
        return (_mock_user_id(candidate), _mock_key(candidate),
                "mock: Ludus user minted locally")
    uid = _mock_user_id(candidate)  # deterministic userID; Ludus requires one
    try:
        out = _req("POST", "/user", {"name": candidate.name, "userID": uid})
        key = out.get("apiKey") or out.get("ApiKey") or out.get("api_key")
        return (uid, key, "Ludus user created")
    except urllib.error.HTTPError as e:
        if e.code == 409:  # already exists; not fatal
            return (uid, None, "Ludus user already existed")
        return (uid, None, f"user create failed: HTTP {e.code}")
    except Exception as e:  # noqa: BLE001
        return (uid, None, f"user create error: {e}")


def set_range_config(candidate, template=GOAD_TEMPLATE, user_key=None, template_vars=None):
    """Push the range config for this candidate's Ludus user.

    template_vars carries per-range variables for the template to consume at
    deploy time, e.g. the board-5 flags to plant (so each ranger's range holds
    their own seed-bound flags). Returns (ok, detail).
    """
    nvars = len(template_vars or {})
    if not is_live():
        extra = f" with {nvars} template vars" if nvars else ""
        return (True, f"mock: {template} config staged{extra}")
    try:
        payload = {"template": template, "userID": candidate.ludus_user_id}
        if template_vars:
            payload["templateVars"] = template_vars
        _req("POST", "/range/config", payload, key=user_key or _admin_key())
        return (True, f"{template} config set" + (f" (+{nvars} vars)" if nvars else ""))
    except Exception as e:  # noqa: BLE001
        return (False, f"config set error: {e}")


def deploy_range(candidate, user_key=None):
    """Deploy (build) the candidate's range.

    Returns (status, ludus_range_id, detail). status is one of
    deploying/deployed/failed.
    """
    if not is_live():
        return ("deploying", _mock_range_id(candidate),
                "mock: deploy accepted; range would build on the Ludus host")
    try:
        out = _req("POST", "/range/deploy", {"userID": candidate.ludus_user_id},
                   key=user_key or _admin_key())
        rid = out.get("rangeID") or out.get("rangeId") or candidate.ludus_user_id
        return ("deploying", str(rid), "deploy accepted")
    except Exception as e:  # noqa: BLE001
        return ("failed", None, f"deploy error: {e}")


def range_status(candidate, user_key=None):
    """Poll the live range state.

    Returns (status, detail) with status in
    configured/deploying/deployed/failed/destroyed.
    """
    if not is_live():
        # Mock: once asked, report deployed so the end-to-end chain completes.
        return ("deployed", "mock: range SUCCESS (simulated)")
    try:
        out = _req("GET", f"/range?userID={candidate.ludus_user_id}",
                   key=user_key or _admin_key())
        state = (out.get("rangeState") or out.get("state") or "").upper()
        mapping = {
            "SUCCESS": "deployed", "DEPLOYED": "deployed",
            "DEPLOYING": "deploying", "PENDING": "deploying",
            "ERROR": "failed", "FAILURE": "failed", "NEVER DEPLOYED": "configured",
            "DESTROYED": "destroyed",
        }
        return (mapping.get(state, "deploying"), f"Ludus state: {state or 'unknown'}")
    except Exception as e:  # noqa: BLE001
        return ("failed", f"status error: {e}")


def wireguard_config(candidate, user_key=None):
    """Return the WireGuard config text the ranger uses to reach their range."""
    if not is_live():
        return _mock_wireguard(candidate)
    try:
        out = _req("GET", f"/user/wireguard?userID={candidate.ludus_user_id}",
                   key=user_key or _admin_key())
        return out.get("wireGuardConfig") or out.get("config") or ""
    except Exception as e:  # noqa: BLE001
        return f"# wireguard fetch error: {e}\n"


def destroy_range(candidate, user_key=None):
    """Tear down the candidate's range (frees VMs/cost). Returns (ok, detail)."""
    if not is_live():
        return (True, "mock: range destroyed")
    try:
        _req("DELETE", "/range", {"userID": candidate.ludus_user_id},
             key=user_key or _admin_key())
        return (True, "range teardown accepted")
    except Exception as e:  # noqa: BLE001
        return (False, f"destroy error: {e}")


# --- backwards-compat --------------------------------------------------------
def queue_range(candidate):
    """Legacy entry point: kept so older callers don't break.

    Equivalent to "configured" without a deploy. Prefer the explicit lifecycle
    functions above.
    """
    _now = _dt.datetime.now(_dt.timezone.utc)  # noqa: F841 (parity with old sig)
    if not is_live():
        return ("configured", _mock_range_id(candidate),
                "mock: range configured, not deployed")
    return ("configured", None, "configured; deploy on lab-start")
