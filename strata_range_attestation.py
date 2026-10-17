"""STRATA S6 - range attestation: the real-vs-mock boundary for isolated boards (5 Raider, 6 Vanguard).

Section 9 non-negotiable: "A simulated range must never become sufficient proof for qualification."
The Ludus broker has a mock mode that reports a range as `deployed` unconditionally (broker.range_status
in mock), so without this module a mock/simulated range could drive a real Board 5/6 objective award and
promotion. This module makes the boundary EXPLICIT and FAIL-CLOSED: an isolated-board objective is only
awardable against a REAL, validated range, and every award carries a signed attestation recording which
posture (real or mock) produced it.

It does not weaken any existing control. It is additive and defaults to enforcing on isolated boards. A
deterministic TEST override lets offline tests exercise the allow-path without a live Ludus host, exactly
as the S5 qualification activation does; the override is inert outside an explicit test/ci environment.
"""
from __future__ import annotations

import datetime as _dt
import os

import signing

# The range/assessment lifecycle states (spec section 9). A real objective award requires the range to
# have reached a validated, candidate-ready posture; a mock simulation never does.
STATES = (
    "mock_simulation",
    "configuration_validated",
    "provisioning",
    "real_deployment_detected",
    "technical_validation_passed",
    "candidate_ready",
    "assessment_in_progress",
    "suspended",
    "completed",
    "expired",
    "destroyed",
    "failed",
)

# Posture that is ACCEPTABLE as proof of a real, validated range for an objective award.
_REAL_READY_STATES = ("technical_validation_passed", "candidate_ready", "assessment_in_progress",
                      "completed")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def test_override_active() -> bool:
    """A deterministic allow-path for ISOLATED offline integration tests ONLY. Active only in an
    explicitly declared test/ci environment AND with the explicit opt-in flag, mirroring the S5
    authorized-test activation. Inert in any other environment, so it can never relax a real
    deployment."""
    return (os.environ.get("RANGER_ENV", "").strip().lower() in ("test", "ci")
            and _truthy(os.environ.get("RANGER_S6_ATTEST_TEST")))


def range_is_real(rr, broker_mod) -> bool:
    """True only when a genuinely live broker reports this candidate's range as deployed/validated.
    A mock broker (no LUDUS_API_URL) is never real. A missing or non-deployed range is never real."""
    if broker_mod is None or not broker_mod.is_live():
        return False
    if rr is None:
        return False
    # the range record must show a deployed/validated posture
    if getattr(rr, "is_deployed", False):
        return True
    state = str(getattr(rr, "status", "") or "")
    return state in _REAL_READY_STATES


def evaluate(rr, broker_mod):
    """Return (real: bool, mode: str, reason: str) for the current range posture."""
    if range_is_real(rr, broker_mod):
        return True, "candidate_ready", "live Ludus range deployed and validated"
    if test_override_active():
        return True, "candidate_ready", "TEST override: attested real range (isolated test env only)"
    live = bool(broker_mod is not None and broker_mod.is_live())
    mode = "failed" if live else "mock_simulation"
    reason = ("broker is live but no deployed/validated range for this candidate"
              if live else "broker is in mock/simulated mode; no real range exists")
    return False, mode, reason


def attest(candidate, board, rr, broker_mod, *, cohort=None, attempt=1, scenario_ref=None):
    """Build and SIGN a range attestation for an isolated-board objective award. Returns
    (real: bool, record: dict). The signed record binds candidate/board/cohort/attempt/scenario/range
    and the real-vs-mock posture, so a mock-derived award is permanently distinguishable and never
    passes the gate. Never contains flags, seeds, grader truth or WireGuard keys."""
    real, mode, reason = evaluate(rr, broker_mod)
    claim = {
        "kind": "range_attestation",
        "handle": getattr(candidate, "handle", None),
        "cohort": cohort if cohort is not None else getattr(candidate, "cohort", None),
        "board": int(board),
        "attempt": int(attempt or 1),
        "scenario_ref": scenario_ref,
        "range_id": getattr(rr, "ludus_range_id", None) if rr is not None else None,
        "range_status": getattr(rr, "status", None) if rr is not None else None,
        "mode": mode,
        "real": bool(real),
        "broker_live": bool(broker_mod is not None and broker_mod.is_live()),
        "reason": reason,
        "at": _now_iso(),
    }
    record = dict(claim)
    record["signature"] = signing.sign(claim)
    return real, record


def verify(record) -> bool:
    """Verify a stored attestation's signature and that it asserts a real range. Fail-closed on any
    tamper, missing signature, or a record that does not assert real=True."""
    if not isinstance(record, dict):
        return False
    sig = record.get("signature")
    if not sig:
        return False
    claim = {k: record[k] for k in record if k != "signature"}
    try:
        if not signing.verify(claim, sig):
            return False
    except Exception:  # noqa: BLE001
        return False
    return bool(record.get("real") is True)
