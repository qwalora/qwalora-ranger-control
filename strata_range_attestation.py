"""STRATA S6 - range attestation: real-range IDENTITY + validation for isolated boards (5/6).

Section 9 established the fail-closed real-vs-mock boundary. Section 13 hardens it so that a range is
proven to be a REAL, technically-validated, candidate-owned environment - not merely a configured
broker URL or a stored "deployed" status - and so grading/promotion VERIFY the stored signed
attestation rather than minting a fresh one.

Four corrections implemented (section 13):
  1. `broker.is_live()` (a configured URL) is necessary but NOT sufficient. A real award requires an
     independent technical validation to pass; a live-but-unprobed range is "unavailable", not real.
  2. A stored `deployed` status does not prove the VMs exist/function; the technical-validation
     contract (not the status field) decides.
  3. `_evaluate_gate` VERIFIES the stored, signed attestation (identity + freshness + mode), and never
     mints a new one to make a prior award pass (see `verify_stored`).
  4. The actual range mode is explicit - real | mock | unavailable | test_fixture. A test fixture can
     drive the offline pipeline but is NEVER accepted as real-production proof.

Modes:
  real          - live broker AND independent technical validation passed; the ONLY creditable
                  production mode.
  unavailable   - live broker but no validated/deployed range (fail closed; not creditable).
  test_fixture  - the deterministic offline test override is active; creditable ONLY while that
                  override is active, never as real-production proof.
  mock          - mock broker, no override; never creditable.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os

import signing

ATTESTATION_VERSION = 2
MODE_REAL = "real"
MODE_MOCK = "mock"
MODE_UNAVAILABLE = "unavailable"
MODE_TEST_FIXTURE = "test_fixture"

# Lifecycle states (section 16 state machine; the attestation records the state it was taken in).
STATES = (
    "requested", "queued", "provisioning", "deployed", "validated", "ready", "active",
    "suspended", "resumed", "failed", "expired", "destroyed",
)


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(dt) -> str:
    return dt.isoformat() if dt else None


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _key_version() -> str:
    """A stable identifier for the active signing key, so an attestation records which key signed it
    (section 13 'signing-key version'). Derived from the public key; rotating the key changes it."""
    try:
        return hashlib.sha256(signing.public_key_b64().encode()).hexdigest()[:12]
    except Exception:  # noqa: BLE001
        return "unknown"


def test_override_active() -> bool:
    """Deterministic allow-path for ISOLATED offline tests ONLY: an explicit test/ci environment AND
    an explicit opt-in flag. Inert anywhere else, so a test fixture can never relax a real deployment
    or be accepted outside the test environment (mirrors S5 authorized-test activation)."""
    return (os.environ.get("RANGER_ENV", "").strip().lower() in ("test", "ci")
            and _truthy(os.environ.get("RANGER_S6_ATTEST_TEST")))


def technical_validation(candidate, board, rr, broker_mod, *, expected_vms=None):
    """Independent post-deployment technical validation (section 13). Returns a structured result.

    A broker-reported `deployed` is NOT enough. Against a REAL live range the adapter would probe:
    expected VMs exist; expected domains/roles present; required services reachable through authorized
    paths; scenario artifacts present; account/flag-placement preflight passes; network segmentation
    effective; the range belongs to the correct candidate+attempt. That live probing requires a Ludus
    host and is NOT implemented here, so a live range returns `passed=False` (fail closed) until the
    real adapter lands - we never fabricate a pass. Offline, the checks are SIMULATED and explicitly
    labeled `simulated=True`."""
    check_names = ("vms_present", "domains_roles_present", "services_reachable",
                   "scenario_artifacts_present", "account_flag_preflight", "network_segmentation",
                   "candidate_attempt_ownership")
    live = bool(broker_mod is not None and broker_mod.is_live())
    if live:
        # Real validation path is a release-gated dependency (needs a Ludus/Proxmox host).
        return {
            "simulated": False,
            "passed": False,
            "checks": {k: None for k in check_names},
            "observed_vms": [],
            "reason": "live technical validation requires a Ludus host (adapter not yet verified); "
                      "fail closed",
        }
    # offline: simulate, clearly labeled. Mock simulation is never creditable as real on its own.
    return {
        "simulated": True,
        "passed": True,
        "checks": {k: True for k in check_names},
        "observed_vms": list(expected_vms or []),
        "reason": "simulated technical validation (no live range)",
    }


def _mode(broker_mod, tv) -> str:
    if broker_mod is not None and broker_mod.is_live():
        return MODE_REAL if tv.get("passed") else MODE_UNAVAILABLE
    if test_override_active():
        return MODE_TEST_FIXTURE
    return MODE_MOCK


def _creditable(mode: str) -> bool:
    """Whether this mode may back an objective award. Only a real validated range in production, or a
    test fixture while the explicit offline override is active (never real-production)."""
    if mode == MODE_REAL:
        return True
    if mode == MODE_TEST_FIXTURE:
        return test_override_active()
    return False


def attest(candidate, board, rr, broker_mod, *, cohort=None, attempt=1, scenario=None,
           window=None, expected_vms=None, evidence_ref=None, state=None):
    """Build and Ed25519-SIGN a full range attestation (section 13). Returns (creditable, record).

    The record binds candidate/cohort, board/attempt, approved scenario id+version+content-hash, the
    Ludus user + range id, the blueprint + config version, expected vs observed VM inventory, the
    deployment outcome, the independent technical-validation outcome and timestamps, the authorized
    assessment window, the actual range mode, a server-side evidence reference, and the signing-key
    version. It never contains flags, seeds, grader truth or WireGuard keys."""
    scenario = scenario or {}
    tv = technical_validation(candidate, board, rr, broker_mod, expected_vms=expected_vms)
    mode = _mode(broker_mod, tv)
    now = _now()
    claim = {
        "attestation_version": ATTESTATION_VERSION,
        "kind": "range_attestation",
        "handle": getattr(candidate, "handle", None),
        "cohort": cohort if cohort is not None else getattr(candidate, "cohort", None),
        "board": int(board),
        "attempt": int(attempt or 1),
        "scenario_ref": scenario.get("scenario_ref"),
        "scenario_version": scenario.get("scenario_version"),
        "scenario_content_hash": scenario.get("content_hash"),
        "ludus_user_id": getattr(candidate, "ludus_user_id", None),
        "range_id": getattr(rr, "ludus_range_id", None) if rr is not None else None,
        "blueprint": (getattr(rr, "template", None) if rr is not None else None)
        or scenario.get("blueprint"),
        "config_version": scenario.get("config_version"),
        "expected_vms": list(expected_vms or []),
        "observed_vms": tv.get("observed_vms", []),
        "deployment_outcome": (getattr(rr, "status", None) if rr is not None else "none"),
        "technical_validation": {"passed": bool(tv.get("passed")),
                                 "simulated": bool(tv.get("simulated")),
                                 "checks": tv.get("checks", {}),
                                 "reason": tv.get("reason")},
        "validated_at": _iso(now) if tv.get("passed") else None,
        "assessment_window": window or _default_window(now),
        "state": state or ("ready" if mode in (MODE_REAL, MODE_TEST_FIXTURE) else "failed"),
        "mode": mode,
        "real": mode == MODE_REAL,
        "evidence_ref": evidence_ref,
        "key_version": _key_version(),
        "at": _iso(now),
    }
    record = dict(claim)
    record["signature"] = signing.sign(claim)
    return _creditable(mode), record


def _default_window(now):
    try:
        hours = int(os.environ.get("RANGE_MAX_AGE_HOURS", "48"))
    except ValueError:
        hours = 48
    return {"opened_at": _iso(now), "expires_at": _iso(now + _dt.timedelta(hours=hours))}


def _parse(ts):
    try:
        return _dt.datetime.fromisoformat(ts)
    except Exception:  # noqa: BLE001
        return None


def verify_stored(record, *, handle, board, cohort, attempt=1, scenario_ref=None, range_id=None,
                  now=None):
    """Verify a STORED attestation at objective grading / promotion (section 13 'Qualification
    safety'). Returns (ok, reason). Verifies the signature; matches the exact candidate/board/cohort/
    attempt (and scenario/range when provided); checks freshness against the assessment window; and
    accepts only a creditable mode. Rejects forged/altered (bad signature), foreign/superseded
    (identity mismatch), expired, simulated/unvalidated, and mock. Never mints a new attestation."""
    if not isinstance(record, dict):
        return False, "no stored attestation"
    sig = record.get("signature")
    if not sig:
        return False, "attestation has no signature"
    claim = {k: record[k] for k in record if k != "signature"}
    try:
        if not signing.verify(claim, sig):
            return False, "attestation signature invalid (forged or altered)"
    except Exception:  # noqa: BLE001
        return False, "attestation signature could not be verified"
    # exact identity binding
    for field, want in (("handle", handle), ("board", int(board)),
                        ("cohort", cohort), ("attempt", int(attempt or 1))):
        if record.get(field) != want:
            return False, f"attestation {field} mismatch (foreign/superseded)"
    if scenario_ref is not None and record.get("scenario_ref") != scenario_ref:
        return False, "attestation scenario mismatch"
    if range_id is not None and record.get("range_id") != range_id:
        return False, "attestation range mismatch"
    # creditable mode only
    mode = record.get("mode")
    if mode == MODE_REAL:
        tv = record.get("technical_validation") or {}
        if record.get("real") is not True or not tv.get("passed"):
            return False, "attestation is not technically validated"
    elif mode == MODE_TEST_FIXTURE:
        if not test_override_active():
            return False, "test-fixture attestation is not valid real-production proof"
    else:
        return False, f"attestation mode {mode!r} is not creditable (mock/unavailable)"
    # freshness
    win = record.get("assessment_window") or {}
    exp = _parse(win.get("expires_at")) if win.get("expires_at") else None
    if exp is not None and exp < (now or _now()):
        return False, "assessment window expired"
    return True, "ok"


# Back-compat: evaluate() still returns a quick (real, mode, reason) triple for callers that only
# want the posture, now derived from the full technical validation.
def evaluate(rr, broker_mod):
    tv = technical_validation(None, 0, rr, broker_mod)
    mode = _mode(broker_mod, tv)
    return (mode == MODE_REAL), mode, tv.get("reason")


def verify(record) -> bool:
    """Signature + real-mode check, without identity binding (used where only authenticity matters)."""
    if not isinstance(record, dict) or not record.get("signature"):
        return False
    claim = {k: record[k] for k in record if k != "signature"}
    try:
        if not signing.verify(claim, record["signature"]):
            return False
    except Exception:  # noqa: BLE001
        return False
    return record.get("mode") == MODE_REAL and record.get("real") is True
