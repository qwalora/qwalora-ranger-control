"""STRATA S6 §16 - the isolated-range lifecycle state machine and its
evidence-preservation guards.

This module is PURE: it owns the legal states, the legal transitions between
them, and the policy decisions (what reclamation may do to a range right now).
It performs no I/O - it imports neither the broker nor the database. app.py
supplies the current time, the broker, and the persisted range row, executes the
decision this module returns, and persists the resulting state. Keeping the
policy here makes it exhaustively unit-testable offline, independent of a Ludus
host (which remains category-D unverified).

Lifecycle reality (matches Ludus; see broker.py):
  - "suspend" is a Proxmox POWER-OFF (VM stop). Disks and all planted artifacts
    are preserved; only host RAM is freed. There is NO snapshot-suspend.
  - "resume" is a Proxmox POWER-ON (VM start) of the same disks.
  - a "rebuild" is destroy + deploy (a fresh range), NOT a resume.

States
------
  configured   staged, not yet building (no slot held)
  queued_slot  waiting for a concurrency slot (no slot held)
  deploying    building on the host (HOLDS a slot)
  deployed     live and reachable (HOLDS a slot)
  suspended    powered off; disks preserved (frees the slot, keeps evidence)
  failed       a step failed (no slot held)
  destroyed    torn down; VMs and disks gone (no slot held)
"""

# Canonical states.
CONFIGURED = "configured"
QUEUED_SLOT = "queued_slot"
DEPLOYING = "deploying"
DEPLOYED = "deployed"
SUSPENDED = "suspended"
FAILED = "failed"
DESTROYED = "destroyed"

STATES = (CONFIGURED, QUEUED_SLOT, DEPLOYING, DEPLOYED, SUSPENDED, FAILED, DESTROYED)

# States that consume a host RAM slot (count against the concurrency cap).
# A suspended range is powered off, so it frees its slot while its disks persist.
SLOT_STATES = (DEPLOYING, DEPLOYED)

# States that are still part of an active, resumable lifecycle (not terminal).
ACTIVE_STATES = (CONFIGURED, QUEUED_SLOT, DEPLOYING, DEPLOYED, SUSPENDED)

# Legal transitions. A state may always "transition" to itself (idempotent
# re-poll); that is allowed implicitly by can_transition.
TRANSITIONS = {
    CONFIGURED: {QUEUED_SLOT, DEPLOYING, FAILED, DESTROYED},
    QUEUED_SLOT: {DEPLOYING, FAILED, DESTROYED},
    # DEPLOYING -> SUSPENDED: a reserve-before-launch RESUME (suspended -> deploying) whose power-on
    # did not confirm releases its reservation back to the preserved suspended state (disks intact).
    DEPLOYING: {DEPLOYED, FAILED, DESTROYED, SUSPENDED},
    DEPLOYED: {SUSPENDED, DESTROYED, FAILED},
    SUSPENDED: {DEPLOYED, DEPLOYING, DESTROYED, FAILED},
    FAILED: {CONFIGURED, DEPLOYING, DESTROYED},
    DESTROYED: {CONFIGURED, DEPLOYING},  # rebuild
}


class IllegalTransition(Exception):
    """A requested state change is not permitted by the lifecycle."""


def is_slot_occupying(state):
    return state in SLOT_STATES


def is_active(state):
    return state in ACTIVE_STATES


def is_terminal(state):
    return state in (DESTROYED,)


def can_transition(frm, to):
    if frm == to:
        return True
    return to in TRANSITIONS.get(frm, set())


def assert_transition(frm, to):
    if not can_transition(frm, to):
        raise IllegalTransition(f"illegal range transition: {frm} -> {to}")
    return to


# --- action semantics (what the broker call for each lifecycle verb is) ------
# Each returns a small plan the caller executes against the broker. The caller
# runs the broker op, then applies `to_state` on success.
def suspend_plan():
    """Suspend a deployed range: power_off, land in SUSPENDED (frees the slot,
    preserves disks/evidence). NOT a snapshot."""
    return {"verb": "suspend", "broker_op": "power_off", "from": DEPLOYED,
            "to_state": SUSPENDED, "note": "power-off (Proxmox stop); disks and evidence preserved"}


def resume_plan():
    """Resume a suspended range: power_on, land back in DEPLOYED (re-takes a slot)."""
    return {"verb": "resume", "broker_op": "power_on", "from": SUSPENDED,
            "to_state": DEPLOYED, "note": "power-on (Proxmox start) of the preserved disks"}


def rebuild_plan():
    """Rebuild = destroy + deploy. A fresh range, not a resume; any planted
    evidence on the old disks is lost, so callers must preserve evidence first."""
    return {"verb": "rebuild", "broker_ops": ["destroy_range", "deploy_range"],
            "to_state": DEPLOYING, "note": "destroy + deploy (fresh range); evidence NOT preserved"}


# --- evidence-preservation guard ---------------------------------------------
def reclaim_decision(*, state, now, evidence_hold_until, reason):
    """Decide what reclamation may do to a slot-occupying range right now.

    Inputs:
      state                current range state
      now                  tz-aware datetime
      evidence_hold_until  tz-aware datetime or None - while now < this, the
                           range is under an OPEN assessment/evidence window and
                           its disks (which hold candidate evidence) must not be
                           destroyed.
      reason               why reclamation fired ("max_age" | "idle")

    Returns a decision dict:
      {"action": "destroy"|"suspend"|"hold", "to_state": <state>|None, "reason": str}

    Policy:
      - Not under evidence hold  -> destroy (frees VMs and cost, as before).
      - Under evidence hold       -> never destroy. Suspend (power-off) to free
        the host RAM slot while preserving the disks and evidence. This applies
        even to a max-age reclaim: within the bounded hold window, evidence
        integrity outranks cost. (The hold window is itself bounded, so cost is
        still capped once it expires.)
      - A range not holding a slot, or already suspended, needs no action.
    """
    if state not in SLOT_STATES:
        return {"action": "hold", "to_state": None,
                "reason": f"{state} holds no slot; nothing to reclaim"}
    under_hold = evidence_hold_until is not None and now < evidence_hold_until
    if not under_hold:
        return {"action": "destroy", "to_state": DESTROYED,
                "reason": f"reclaimed ({reason}); no open evidence window"}
    return {"action": "suspend", "to_state": SUSPENDED,
            "reason": (f"evidence window open until {evidence_hold_until.isoformat()}: "
                       f"{reason} reclaim SUSPENDS (power-off) instead of destroying, "
                       "preserving disks and evidence")}


def teardown_allowed(*, state, now, evidence_hold_until):
    """Whether an explicit destroy of this range is permitted right now.

    A destroy is refused while an evidence window is open (now <
    evidence_hold_until), because tearing down the VMs discards the disks that
    hold the candidate's evidence. Returns (allowed: bool, reason: str)."""
    if evidence_hold_until is not None and now < evidence_hold_until:
        return (False, f"evidence window open until {evidence_hold_until.isoformat()}; "
                       "destroy refused (suspend to free capacity instead)")
    return (True, "no open evidence window; destroy permitted")
