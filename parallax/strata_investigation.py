"""Read-only bridge from the existing PARALLAX research store to the STRATA investigation view-model.

Assembles the entitlement-gated `strata_view` from data the researcher already owns, reusing the
existing owner-scoped store functions (overview_for, get_run, _decisions_for) and the existing signed
review workflow. It builds NO parallel database and persists nothing; it links a trial's evidence to
its investigation's signed adjudications by parent_run, and lets the measurement layer enforce that a
disposition is authoritative only when verified, signed, and authored by someone other than the
record's producer (separation of duties). An authenticated reviewer id alone is never treated as proof
of independent review: only a signature-verifying, non-self disposition counts.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from parallax.research import store as rstore
from parallax.research import measurement as M
from parallax.research import strata_view as SV

_SCOPE_NOTE = "Attack only the provided synthetic research corpus. No real PII. No out-of-scope targets."


def assemble(db, *, researcher_id: str, run_id: Optional[str] = None,
             verifier_report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build the STRATA investigation view for an entitled researcher over their OWN runs. The caller
    has already enforced authentication + PARALLAX entitlement; `researcher_id` is the owner scope, so
    get_run refuses another owner's runs. Raises strata_view.EntitlementError only via build_view."""
    items = rstore.overview_for(db, authenticated_researcher_id=researcher_id)
    trials = [i for i in items if i.get("kind") == "trial"]
    investigations = [i for i in items if i.get("kind") == "investigation"]
    if run_id:
        focused = [t for t in trials if t.get("run_id") == run_id]
        trials = focused or trials                      # focus if it resolves, else show all owned

    records: List[Dict[str, Any]] = []
    key_of_run: Dict[str, str] = {}
    for t in trials:
        full = rstore.get_run(db, run_id=t["run_id"], authenticated_researcher_id=researcher_id)
        if not full:
            continue
        tr = ((full.get("record") or {}).get("metrics") or {}).get("record") or {}
        rec = dict(tr)
        rec.setdefault("experiment_id", t["run_id"])
        rec["run_id"] = t["run_id"]
        rec["backend_is_real"] = (t.get("backend_provenance") == "infrastructure_backed")
        rec["produced_by"] = researcher_id              # enables separation-of-duties enforcement
        records.append(rec)
        key_of_run[t["run_id"]] = M._record_key(rec)

    # Link each investigation's latest SIGNED decision to its parent trial's record key. The measurement
    # layer ignores a disposition that is unsigned/unverified or self-authored; we pass signature-verify
    # through so an unverifiable adjudication never counts as review.
    adjudications: Dict[str, Dict[str, Any]] = {}
    for inv in investigations:
        parent = inv.get("parent_run")
        if parent not in key_of_run:
            continue
        decisions = rstore._decisions_for(db, inv["run_id"])
        latest = decisions[-1] if decisions else None
        if not latest or not latest.get("decision"):
            continue
        disp = M.disposition_from_decision(
            latest["decision"], reviewer_id=latest.get("reviewer_id") or "",
            verified=bool(latest.get("signature_verifies")), signed=True)
        if disp:
            adjudications[key_of_run[parent]] = disp

    mission = {
        "program": "PARALLAX",
        "title": "Prompt-injection boundary investigation",
        "campaign_id": run_id or "all-owned-trials",
        "dataset": "synthetic research corpus",
        "authorized_scope": _SCOPE_NOTE,
        "rules_of_engagement": "Observe recorded behavior and attributed sources only; do not submit "
                               "real credentials or out-of-scope content.",
    }
    return SV.build_view(mission=mission, records=records, adjudications=adjudications,
                         verifier_report=verifier_report, entitled=True, viewer_scope=["PARALLAX"])
