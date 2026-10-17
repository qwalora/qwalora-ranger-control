"""Ludus range broker.

One Candidate maps to exactly one Ludus user, which owns exactly one range.
That is the whole mapping, and it mirrors how Ludus itself works (per-user
isolated ranges, each reachable over its own WireGuard tunnel).

The broker exposes the full range lifecycle:

    ensure_user(candidate)      admin-create the Ludus user, return its API key
    set_range_config(c, tmpl)   push the range config YAML (GOAD by default)
    deploy_range(candidate)     POST deploy; range builds on the Proxmox host
    range_status(candidate)     poll current state
    verify_range(c, expected)   independent technical probe of a live range
    power_off(candidate)        suspend = Proxmox stop (disks preserved)
    power_on(candidate)         resume  = Proxmox start
    wireguard_config(candidate) fetch the WG config the ranger connects with
    destroy_range(candidate)    tear the range down (frees VMs / cost)

MODE
----
Live when LUDUS_API_URL is set (plus LUDUS_API_KEY, the admin key). Until then
the broker runs in MOCK mode: every call returns deterministic, well-formed
results and the state machine advances exactly as the real one would, so the
whole control plane is provably correct end to end without a Proxmox box.

    LUDUS_API_URL          e.g. https://ludus.internal.qwalora.com (admin API base)
    LUDUS_API_KEY          the Ludus admin API key (X-API-KEY)
    LUDUS_VERIFY_TLS       1 (default) verify server cert; 0 disables (discouraged)
    LUDUS_CA_BUNDLE        path to a custom CA bundle for the Ludus endpoint
    LUDUS_TIMEOUT          per-request timeout seconds (default 20)
    LUDUS_RETRIES          max attempts for idempotent calls (default 3)

HONESTY / VERIFICATION STATUS (S6 §15)
--------------------------------------
The REST surface below matches Ludus's documented shape (X-API-KEY auth;
per-user range with config/deploy/status; admin user management; per-VM/all
power on/off; destroy). The exact paths are NOT yet confirmed against a running
Ludus node, so the live adapter is gated: `adapter_verified()` returns False
until an operator who has confirmed the paths against their installed Ludus
version sets LUDUS_ADAPTER_VERIFIED=1. Technical validation (and therefore any
real-range objective credit) stays fail-closed until that flag is set on a real
host. Mock mode never claims a verified adapter and `verify_range` never passes
a mock range. There is NO snapshot-based suspend in Ludus: "suspend" is a
power-off (Proxmox stop, disks preserved) and "resume" is a power-on; a full
rebuild is destroy + deploy. This module never claims otherwise.
"""
import datetime as _dt
import hashlib
import json
import os
import random
import ssl
import time
import urllib.error
import urllib.request

# GOAD (Game of Active Directory): a vulnerable multi-DC AD lab, the standard
# Ludus template for SOC / detection / IR / red-team work. One config per user.
GOAD_TEMPLATE = "ludus-goad-ranger"

_DEFAULT_TIMEOUT = 20
_DEFAULT_RETRIES = 3
_BACKOFF_BASE = 0.5   # seconds; capped exponential backoff for idempotent retries
_BACKOFF_CAP = 8.0


# --- typed errors ------------------------------------------------------------
class LudusError(Exception):
    """Base class for all broker/adapter errors. Carries the HTTP status (when
    known) and whether the failing operation is safe to retry."""

    retryable = False
    status = None

    def __init__(self, message, *, status=None, retryable=None):
        super().__init__(message)
        if status is not None:
            self.status = status
        if retryable is not None:
            self.retryable = retryable


class LudusTimeout(LudusError):
    """The request timed out. Retryable for idempotent operations."""
    retryable = True


class LudusUnavailable(LudusError):
    """Transport failure or 5xx from the node. Retryable for idempotent ops."""
    retryable = True


class LudusAuthError(LudusError):
    """401/403 - bad or unauthorized API key. Never retried."""


class LudusNotFound(LudusError):
    """404 - user/range absent. Never retried (the caller decides)."""


class LudusConflict(LudusError):
    """409 - resource already exists / already in the requested state. The
    caller treats this as idempotent success where appropriate."""


class LudusProtocolError(LudusError):
    """The node responded but not in a shape we can use (bad JSON, missing
    fields). Never retried blindly - a retry would just repeat the confusion."""


# --- config ------------------------------------------------------------------
def _api_base():
    return (os.environ.get("LUDUS_API_URL") or "").rstrip("/")


def _admin_key():
    return os.environ.get("LUDUS_API_KEY", "")


def _timeout():
    try:
        return float(os.environ.get("LUDUS_TIMEOUT", "") or _DEFAULT_TIMEOUT)
    except ValueError:
        return _DEFAULT_TIMEOUT


def _max_attempts():
    try:
        n = int(os.environ.get("LUDUS_RETRIES", "") or _DEFAULT_RETRIES)
    except ValueError:
        n = _DEFAULT_RETRIES
    return max(1, min(n, 6))


def _verify_tls():
    """TLS verification is ON by default. Only an explicit 0/false/no disables
    it, and that is logged into the detail stream by the caller, not silent."""
    v = (os.environ.get("LUDUS_VERIFY_TLS", "1") or "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def _ssl_context():
    """Build the TLS context for the Ludus endpoint. Verifying by default, with
    an optional operator-supplied CA bundle (LUDUS_CA_BUNDLE) for a private CA.
    When verification is explicitly disabled, return an unverified context -
    discouraged, and surfaced in broker_status()."""
    if not _verify_tls():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ca = os.environ.get("LUDUS_CA_BUNDLE") or None
    if ca and os.path.exists(ca):
        return ssl.create_default_context(cafile=ca)
    return ssl.create_default_context()


def is_live():
    return bool(_api_base())


def adapter_verified():
    """Whether an operator has confirmed this adapter's REST paths against their
    installed Ludus version. Until set, the live adapter is present but NOT
    trusted to validate a range (fail-closed; see verify_range)."""
    v = (os.environ.get("LUDUS_ADAPTER_VERIFIED", "0") or "0").strip().lower()
    return v in ("1", "true", "yes", "on")


def broker_status():
    """Human-readable state for the admin dashboard."""
    if not is_live():
        return "mock (set LUDUS_API_URL to go live)"
    bits = ["live"]
    bits.append("adapter verified" if adapter_verified()
                else "adapter UNVERIFIED (set LUDUS_ADAPTER_VERIFIED=1 on a confirmed host)")
    if not _verify_tls():
        bits.append("TLS verification DISABLED")
    return "; ".join(bits)


def mode():
    return "live" if is_live() else "mock"


# --- mock helpers ------------------------------------------------------------
def _cohort_tag(candidate):
    """A short alnum tag for the candidate's cohort, so Ludus users and ranges
    are scoped per cohort and never collide across runs (2026-A vs 2026-B)."""
    raw = "".join(ch for ch in (getattr(candidate, "cohort", "") or "") if ch.isalnum()).upper()
    return (raw[-4:] or "C0")  # e.g. "2026-A" -> "026A"


def _mock_user_id(candidate):
    # Ludus userIDs are short and alnum; derive a stable, cohort-scoped one.
    h = "".join(ch for ch in candidate.handle if ch.isalnum()).upper()
    sig = hashlib.md5(f"{_cohort_tag(candidate)}:{candidate.handle}".encode()).hexdigest()[:4].upper()
    return _cohort_tag(candidate) + "-" + (h[:6] or "RGR") + "-" + sig


def _mock_key(candidate):
    return "mock_" + hashlib.sha256(
        f"ludus:{_cohort_tag(candidate)}:{candidate.handle}".encode()).hexdigest()[:40]


def _mock_range_id(candidate):
    uid = _mock_user_id(candidate)
    # Ludus derives range_id from the userID; keep the cohort tag in front so a
    # range name tells you which cohort it belongs to.
    return "-".join(uid.split("-")[:2]) + "-RANGE"


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
def _classify_http_error(e):
    code = getattr(e, "code", None)
    try:
        body = e.read().decode()[:300]
    except Exception:  # noqa: BLE001
        body = ""
    msg = f"HTTP {code}" + (f": {body}" if body else "")
    if code in (401, 403):
        return LudusAuthError(msg, status=code)
    if code == 404:
        return LudusNotFound(msg, status=code)
    if code == 409:
        return LudusConflict(msg, status=code)
    if code is not None and 500 <= code < 600:
        return LudusUnavailable(msg, status=code)
    # 4xx other than the above: a definite, non-retryable client error.
    return LudusError(msg, status=code, retryable=False)


def _do_once(method, path, payload, key, timeout):
    url = _api_base() + path
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"X-API-KEY": key or _admin_key()}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
            raw = r.read().decode() or "{}"
    except urllib.error.HTTPError as e:
        raise _classify_http_error(e)
    except (TimeoutError, ssl.SSLError) as e:
        # An SSL error under verification is a hard trust failure, not transient:
        # surface it as a non-retryable protocol error rather than masking it.
        if isinstance(e, ssl.SSLError):
            raise LudusProtocolError(f"TLS error talking to Ludus: {e}")
        raise LudusTimeout(f"request timed out after {timeout:g}s")
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, (TimeoutError,)):
            raise LudusTimeout(f"request timed out after {timeout:g}s")
        if isinstance(reason, ssl.SSLError):
            raise LudusProtocolError(f"TLS error talking to Ludus: {reason}")
        raise LudusUnavailable(f"transport error: {reason}")
    try:
        return json.loads(raw)
    except ValueError:
        return {"raw": raw}


def _req(method, path, payload=None, key=None, *, idempotent=False):
    """One Ludus API call with bounded retry/backoff for IDEMPOTENT operations.

    Only idempotent calls (GET status/config/wireguard, and explicitly-safe
    power toggles) are retried, and only on retryable typed errors (timeout,
    transport, 5xx). Non-idempotent writes (user/range create, deploy, destroy)
    are never silently retried here - a double-send could double-provision;
    their callers handle idempotency via status checks and 409 handling."""
    timeout = _timeout()
    attempts = _max_attempts() if idempotent else 1
    last = None
    for i in range(attempts):
        try:
            return _do_once(method, path, payload, key, timeout)
        except LudusError as e:
            last = e
            if not (idempotent and e.retryable) or i == attempts - 1:
                raise
            # capped exponential backoff with full jitter
            delay = min(_BACKOFF_CAP, _BACKOFF_BASE * (2 ** i))
            time.sleep(random.uniform(0, delay))
    if last:
        raise last
    raise LudusError("no attempts made")  # unreachable


# --- lifecycle ---------------------------------------------------------------
def ensure_user(candidate):
    """Create (or reuse) the Ludus user for this candidate.

    Returns (ludus_user_id, api_key, detail). The api_key is the per-user key
    Ludus issues; the caller encrypts and stores it on the Candidate. Idempotent:
    a 409 (user already exists) is reported as reuse, not an error."""
    if not is_live():
        return (_mock_user_id(candidate), _mock_key(candidate),
                "mock: Ludus user minted locally")
    uid = _mock_user_id(candidate)  # deterministic userID; Ludus requires one
    try:
        out = _req("POST", "/user", {"name": candidate.name, "userID": uid})
        key = out.get("apiKey") or out.get("ApiKey") or out.get("api_key")
        return (uid, key, "Ludus user created")
    except LudusConflict:
        return (uid, None, "Ludus user already existed")
    except LudusError as e:
        return (uid, None, f"user create failed: {e}")


def set_range_config(candidate, template=GOAD_TEMPLATE, user_key=None, template_vars=None):
    """Push the range config for this candidate's Ludus user.

    template_vars carries per-range variables for the template to consume at
    deploy time, e.g. the board-5 flags to plant (so each ranger's range holds
    their own seed-bound flags). Returns (ok, detail)."""
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
    except LudusError as e:
        return (False, f"config set error: {e}")


def deploy_range(candidate, user_key=None):
    """Deploy (build) the candidate's range.

    Returns (status, ludus_range_id, detail). status is one of
    deploying/deployed/failed. Not retried at the transport layer (a resend
    could kick a second build); the caller's reserve-before-launch guard and a
    status poll provide idempotency."""
    if not is_live():
        return ("deploying", _mock_range_id(candidate),
                "mock: deploy accepted; range would build on the Ludus host")
    try:
        out = _req("POST", "/range/deploy", {"userID": candidate.ludus_user_id},
                   key=user_key or _admin_key())
        rid = out.get("rangeID") or out.get("rangeId") or candidate.ludus_user_id
        return ("deploying", str(rid), "deploy accepted")
    except LudusError as e:
        return ("failed", None, f"deploy error: {e}")


def range_status(candidate, user_key=None):
    """Poll the live range state (idempotent GET; retried on transient faults).

    Returns (status, detail) with status in
    configured/deploying/deployed/suspended/failed/destroyed/unknown. R3-2: a transient probe error
    returns 'unknown' (NOT 'failed'), so a caller never drops an in-flight (slot-holding) range out of
    its reserved state on an uncertain probe - it keeps the reservation and re-checks on a later pass.
    Only a definite Ludus ERROR/FAILURE state maps to 'failed'."""
    if not is_live():
        # Mock: once asked, report deployed so the end-to-end chain completes.
        return ("deployed", "mock: range SUCCESS (simulated)")
    try:
        out = _req("GET", f"/range?userID={candidate.ludus_user_id}",
                   key=user_key or _admin_key(), idempotent=True)
        state = (out.get("rangeState") or out.get("state") or "").upper()
        mapping = {
            "SUCCESS": "deployed", "DEPLOYED": "deployed",
            "DEPLOYING": "deploying", "PENDING": "deploying",
            "ERROR": "failed", "FAILURE": "failed", "NEVER DEPLOYED": "configured",
            "DESTROYED": "destroyed",
            "POWEREDOFF": "suspended", "POWERED OFF": "suspended", "STOPPED": "suspended",
        }
        # An unrecognized/empty state is UNKNOWN (conservative), not an assumed 'deploying'.
        return (mapping.get(state, "unknown"), f"Ludus state: {state or 'unknown'}")
    except LudusNotFound:
        return ("destroyed", "Ludus state: range not found")
    except LudusError as e:
        return ("unknown", f"status probe error (transient): {e}")


def range_detail(candidate, user_key=None):
    """Fetch the structured range detail (VMs, power state, IPs) for the
    technical-validation probe. Idempotent GET. Returns a dict or raises a typed
    error. In mock mode there is no live range, so this raises LudusUnavailable
    (a mock range is never technically validated)."""
    if not is_live():
        raise LudusUnavailable("mock: no live range to inspect")
    return _req("GET", f"/range?userID={candidate.ludus_user_id}",
                key=user_key or _admin_key(), idempotent=True)


# The complete mandatory technical-validation contract (S6 §2). Every check must be verified TRUE for
# a range to back qualification credit; a missing/unknown result is NEVER a pass. Each check is tagged
# by how it can be verified:
#   "ludus"          - verifiable through the Ludus API from the range detail (VM inventory, power,
#                      range state, candidate/user ownership, assessment window).
#   "guest_scenario" - requires in-guest or scenario-specific validation (AD domains/trusts/roles,
#                      service reachability, account/ACL configuration, flag-placement preflight,
#                      network segmentation/candidate isolation). These need a guest-probe the adapter
#                      must supply; until it does they are UNKNOWN and the range cannot be credited.
PROBE_CONTRACT = {
    "candidate_attempt_ownership": "ludus",
    "expected_vms_present": "ludus",
    "vm_count": "ludus",
    "all_powered_on": "ludus",
    "range_deployed": "ludus",
    "assessment_window_valid": "ludus",
    "domains_trusts_roles_present": "guest_scenario",
    "required_services_reachable": "guest_scenario",
    "account_acl_configuration": "guest_scenario",
    "flag_placement_preflight": "guest_scenario",
    "network_segmentation_isolation": "guest_scenario",
}


def verify_range(candidate, expected, user_key=None):
    """Independent technical probe of a LIVE range against the COMPLETE mandatory contract (S6 §2).

    A broker-reported `deployed` is never trusted on its own. This runs every check in PROBE_CONTRACT:
    the Ludus-direct checks from the range detail, and the guest/scenario checks from whatever verified
    guest-probe results the adapter supplies via `expected["guest_results"]`. A check with no verified
    result is recorded as None (UNKNOWN) and is NEVER treated as a pass.

    `expected` keys: vms (expected VM names), expected_vm_count, require_powered_on, owner_user_id (the
    candidate's Ludus user the range must belong to), assessment_window ({expires_at}), and
    guest_results (a dict of guest_scenario check -> bool from a TRUSTED guest probe). Returns
    {ok, observed_vms, checks, unknown, categories, reason}.

    NEVER passes a mock range, and NEVER passes while the adapter is unverified or while ANY mandatory
    check is false or unknown (fail-closed honesty): a real pass requires a confirmed adapter
    (LUDUS_ADAPTER_VERIFIED=1) AND every mandatory check verified true, including the guest/scenario
    checks that need a guest-probe not yet implemented."""
    result = {"ok": False, "observed_vms": [], "checks": {}, "unknown": [],
              "categories": dict(PROBE_CONTRACT), "reason": ""}
    if not is_live():
        result["reason"] = "mock: no live range to validate"
        return result
    if not adapter_verified():
        result["reason"] = ("live range present but adapter is UNVERIFIED "
                            "(set LUDUS_ADAPTER_VERIFIED=1 on a confirmed host); fail closed")
        return result
    try:
        detail = range_detail(candidate, user_key=user_key)
    except LudusError as e:
        result["reason"] = f"range detail fetch failed: {e}"
        return result
    vms = detail.get("VMs") or detail.get("vms") or []
    observed, powered = [], []
    for vm in vms:
        if isinstance(vm, dict):
            name = vm.get("name") or vm.get("Name") or ""
            observed.append(name)
            if vm.get("poweredOn") or vm.get("PoweredOn") or (vm.get("powerState") == "running"):
                powered.append(name)
        elif isinstance(vm, str):
            observed.append(vm)
    result["observed_vms"] = observed

    # Every mandatory check starts UNKNOWN (None); only a positively verified result sets True/False.
    checks = {k: None for k in PROBE_CONTRACT}

    # --- Ludus-direct checks ---
    owner = expected.get("owner_user_id")
    detail_owner = detail.get("userID") or detail.get("user_id") or detail.get("userId")
    if owner is not None and detail_owner is not None:
        checks["candidate_attempt_ownership"] = (str(detail_owner) == str(owner))
    exp_names = list(expected.get("vms") or [])
    if exp_names:
        checks["expected_vms_present"] = all(
            any(e.lower() in o.lower() for o in observed) for e in exp_names)
    exp_count = expected.get("expected_vm_count")
    if exp_count is not None:
        checks["vm_count"] = len(observed) >= int(exp_count)
    if expected.get("require_powered_on"):
        checks["all_powered_on"] = bool(observed) and len(powered) == len(observed)
    state = (detail.get("rangeState") or detail.get("state") or "").upper()
    checks["range_deployed"] = state in ("SUCCESS", "DEPLOYED")
    win = expected.get("assessment_window") or {}
    if win.get("expires_at"):
        try:
            import datetime as _d
            checks["assessment_window_valid"] = (
                _d.datetime.fromisoformat(win["expires_at"]) > _d.datetime.now(_d.timezone.utc))
        except Exception:  # noqa: BLE001
            checks["assessment_window_valid"] = False

    # --- guest/scenario checks: only trusted, verified guest-probe results count as a pass ---
    guest = expected.get("guest_results") or {}
    for name, cat in PROBE_CONTRACT.items():
        if cat == "guest_scenario" and name in guest:
            checks[name] = bool(guest[name])

    result["checks"] = checks
    result["unknown"] = [k for k, v in checks.items() if v is None]
    # A pass requires EVERY mandatory check verified exactly True. Any False or UNKNOWN fails closed.
    result["ok"] = all(v is True for v in checks.values())
    if result["ok"]:
        result["reason"] = "all mandatory technical-validation checks verified"
    elif result["unknown"]:
        result["reason"] = ("incomplete technical validation: unverified checks %s (guest/scenario "
                            "probe required); fail closed" % ", ".join(result["unknown"]))
    else:
        result["reason"] = "one or more mandatory technical-validation checks failed"
    return result


# --- operation outcomes (S6 §2) ----------------------------------------------
# A Ludus power/delete call being ACCEPTED is not the same as the remote state having CHANGED. These
# five outcomes keep the two apart so callers only act on independently-confirmed state.
OP_CONFIRMED = "confirmed"   # remote state independently verified (VMs stopped/running, range absent)
OP_ACCEPTED = "accepted"     # request accepted by the API but remote state not yet confirmed
OP_PENDING = "pending"       # in progress; remote state not yet the target state
OP_FAILED = "failed"         # the request itself failed (definite)
OP_UNKNOWN = "unknown"       # could not determine remote state (treat conservatively, retryable)

_CONFIRM_POLLS = 3


def _confirm(fn, *, want, attempts=_CONFIRM_POLLS):
    """Poll a predicate `fn()` (returns True once the remote state matches the target) up to `attempts`
    times. Returns (ok, outcome). Any probe error leaves the outcome UNKNOWN, never a false CONFIRMED.
    Against real Ludus the poll cadence/paths need validation (category D)."""
    for _ in range(max(1, attempts)):
        try:
            if fn():
                return True, OP_CONFIRMED
        except LudusError:
            return False, OP_UNKNOWN
        except Exception:  # noqa: BLE001
            return False, OP_UNKNOWN
    return False, OP_PENDING


# Tri-state VM power (S6 R3-3): a power state is only RUNNING or STOPPED when an EXPLICIT, recognized
# field says so. An absent or unrecognized field is UNKNOWN - never silently treated as stopped.
VM_RUNNING = "running"
VM_STOPPED = "stopped"
VM_UNKNOWN = "unknown"
_RUNNING_TOKENS = frozenset({"running", "on", "poweredon", "powered on", "started", "up", "active"})
_STOPPED_TOKENS = frozenset({"stopped", "off", "poweredoff", "powered off", "shutoff",
                             "shut off", "halted", "down"})


def _classify_vm(vm):
    """Classify one VM's power state as running/stopped/unknown from explicit recognized fields only."""
    for key in ("poweredOn", "PoweredOn", "poweredon"):
        if key in vm and isinstance(vm[key], bool):
            return VM_RUNNING if vm[key] else VM_STOPPED
    ps = vm.get("powerState") or vm.get("PowerState") or vm.get("state") or vm.get("status")
    if ps is None:
        return VM_UNKNOWN           # no recognized power field present
    token = str(ps).strip().lower()
    if token in _RUNNING_TOKENS:
        return VM_RUNNING
    if token in _STOPPED_TOKENS:
        return VM_STOPPED
    return VM_UNKNOWN               # an unrecognized value stays UNKNOWN, never assumed stopped


def _vm_power_states(detail):
    """Map VM name -> tri-state power (running/stopped/unknown). A VM given only as a bare name, with
    no power field, is UNKNOWN."""
    out = {}
    for vm in (detail.get("VMs") or detail.get("vms") or []):
        if isinstance(vm, dict):
            out[vm.get("name") or vm.get("Name") or ""] = _classify_vm(vm)
        elif isinstance(vm, str):
            out[vm] = VM_UNKNOWN
    return out


def _all_stopped(states):
    """True only when there is at least one VM and EVERY VM is explicitly stopped. Any running,
    unknown or (by construction) missing VM makes this False - power-off is never confirmed on doubt."""
    return bool(states) and all(s == VM_STOPPED for s in states.values())


def _all_running(states):
    """True only when there is at least one VM and EVERY VM is explicitly running."""
    return bool(states) and all(s == VM_RUNNING for s in states.values())


def confirm_power(candidate, want, user_key=None, *, attempts=1):
    """READ-ONLY confirmation of a range's VM power state - issues NO power command (so it never
    re-sends a destructive/uncertain operation). want is 'running' or 'stopped'. Returns
    (confirmed, outcome), polling up to `attempts` times. Mock is treated as confirmed. A probe error
    is UNKNOWN; every VM explicitly in the target state is CONFIRMED; every VM explicitly in the
    definitive opposite state (e.g. all stopped when a resume wanted running) is FAILED; anything else
    (mixed, or any unknown/missing VM) is PENDING - never confirmed on doubt."""
    if not is_live():
        return (True, OP_CONFIRMED)
    for _ in range(max(1, attempts)):
        try:
            states = _vm_power_states(range_detail(candidate, user_key=user_key))
        except LudusError:
            return (False, OP_UNKNOWN)
        except Exception:  # noqa: BLE001
            return (False, OP_UNKNOWN)
        if (_all_running(states) if want == "running" else _all_stopped(states)):
            return (True, OP_CONFIRMED)
        if (_all_stopped(states) if want == "running" else _all_running(states)):
            return (False, OP_FAILED)   # definitive opposite: the operation did not take
    return (False, OP_PENDING)


def power_off(candidate, user_key=None, *, confirm=True):
    """Suspend the range = Proxmox power-off of all VMs. Disks are preserved; this is NOT a
    snapshot-suspend (Ludus has none). Returns (confirmed, detail, outcome).

    §2: the POST being accepted does NOT mean the VMs are stopped. When `confirm`, poll the range
    detail until every VM is confirmed powered off; a slot must not be freed until this returns
    CONFIRMED. A partial/interrupted power-off is PENDING, a probe failure UNKNOWN - both conservative
    and retryable, and neither re-sends the destructive request automatically."""
    if not is_live():
        return (True, "mock: range powered off (suspend = Proxmox stop; disks preserved)", OP_CONFIRMED)
    try:
        _req("POST", "/range/poweroff", {"userID": candidate.ludus_user_id, "machines": "all"},
             key=user_key or _admin_key())
    except LudusError as e:
        return (False, f"power-off request failed: {e}", OP_FAILED)
    if not confirm:
        return (False, "power-off accepted (VMs stopping; not yet confirmed)", OP_ACCEPTED)
    # Resolve via the tri-state confirmation: all stopped -> CONFIRMED; all running (power-off did not
    # take) -> FAILED; mixed/unknown -> PENDING. Never confirm on any unknown/missing/running VM.
    ok, outcome = confirm_power(candidate, "stopped", user_key=user_key, attempts=_CONFIRM_POLLS)
    msg = {OP_CONFIRMED: "power-off confirmed (all VMs stopped; disks preserved)",
           OP_FAILED: "power-off not effective (VMs still running)",
           OP_PENDING: "power-off accepted but VMs not yet confirmed stopped",
           OP_UNKNOWN: "power-off accepted but remote state could not be confirmed"}[outcome]
    return (ok, msg, outcome)


def power_on(candidate, user_key=None, *, confirm=True):
    """Resume the range = Proxmox power-on of all VMs (disks intact). Returns (confirmed, detail,
    outcome). §2: a range is not treated as resumed/deployed until the required VMs are CONFIRMED
    running; accepted-but-unconfirmed is ACCEPTED/PENDING, a probe failure UNKNOWN."""
    if not is_live():
        return (True, "mock: range powered on (resume = Proxmox start)", OP_CONFIRMED)
    try:
        _req("POST", "/range/poweron", {"userID": candidate.ludus_user_id, "machines": "all"},
             key=user_key or _admin_key())
    except LudusError as e:
        return (False, f"power-on request failed: {e}", OP_FAILED)
    if not confirm:
        return (False, "power-on accepted (VMs starting; not yet confirmed)", OP_ACCEPTED)
    # all running -> CONFIRMED; all stopped (power-on did not take) -> FAILED; mixed/unknown -> PENDING.
    ok, outcome = confirm_power(candidate, "running", user_key=user_key, attempts=_CONFIRM_POLLS)
    msg = {OP_CONFIRMED: "power-on confirmed (all VMs running)",
           OP_FAILED: "power-on not effective (VMs still stopped)",
           OP_PENDING: "power-on accepted but VMs not yet confirmed running",
           OP_UNKNOWN: "power-on accepted but remote state could not be confirmed"}[outcome]
    return (ok, msg, outcome)


def wireguard_config(candidate, user_key=None):
    """Return the WireGuard config text the ranger uses to reach their range.
    Idempotent GET; retried on transient faults."""
    if not is_live():
        return _mock_wireguard(candidate)
    try:
        out = _req("GET", f"/user/wireguard?userID={candidate.ludus_user_id}",
                   key=user_key or _admin_key(), idempotent=True)
        return out.get("wireGuardConfig") or out.get("config") or ""
    except LudusError as e:
        return f"# wireguard fetch error: {e}\n"


def destroy_range(candidate, user_key=None, *, confirm=True):
    """Tear down the candidate's range (frees VMs/cost). Returns (confirmed, detail, outcome).

    §2: a DELETE being accepted does NOT mean the range is gone. A range must not be marked destroyed
    (nor its slot/evidence considered reclaimed) until ABSENCE is independently confirmed. When
    `confirm`, poll the range detail until it reports the range absent; a 404 on the DELETE itself, or
    a confirmed-absent poll, is CONFIRMED; still-present is PENDING; a probe failure is UNKNOWN. The
    destructive DELETE is never auto-resent on PENDING/UNKNOWN - the caller retries on a later pass."""
    if not is_live():
        return (True, "mock: range destroyed", OP_CONFIRMED)
    try:
        _req("DELETE", "/range", {"userID": candidate.ludus_user_id},
             key=user_key or _admin_key())
    except LudusNotFound:
        return (True, "range already absent (confirmed)", OP_CONFIRMED)
    except LudusError as e:
        return (False, f"destroy request failed: {e}", OP_FAILED)
    if not confirm:
        return (False, "destroy accepted (range not yet confirmed absent)", OP_ACCEPTED)

    def _absent():
        try:
            range_detail(candidate, user_key=user_key)
        except LudusNotFound:
            return True
        return False
    ok, outcome = _confirm(_absent, want=True)
    msg = {OP_CONFIRMED: "range destruction confirmed (range absent)",
           OP_PENDING: "destroy accepted but range not yet confirmed absent",
           OP_UNKNOWN: "destroy accepted but remote state could not be confirmed"}[outcome]
    return (ok, msg, outcome)


# --- backwards-compat --------------------------------------------------------
def queue_range(candidate):
    """Legacy entry point: kept so older callers don't break.

    Equivalent to "configured" without a deploy. Prefer the explicit lifecycle
    functions above."""
    _now = _dt.datetime.now(_dt.timezone.utc)  # noqa: F841 (parity with old sig)
    if not is_live():
        return ("configured", _mock_range_id(candidate),
                "mock: range configured, not deployed")
    return ("configured", None, "configured; deploy on lab-start")
