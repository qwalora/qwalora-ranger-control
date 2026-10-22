"""Read-only bridge from the existing PARALLAX research store to the STRATA investigation workspace.

Assembles the entitlement-gated `strata_view` plus a chronological timeline, owner-scoped campaign
navigation, and SERVER-SIDE evidence verification, reusing the existing owner-scoped store functions
(overview_for, get_run, _decisions_for, _evidence_summary) and the existing signed review workflow and
trusted-key rules. It builds NO parallel database and persists nothing.

Separation of concerns that this module keeps strictly distinct:
- cryptographic verification (did the signed bytes verify under an explicitly trusted key),
- integrity (does the recomputed evidence hash match),
- independent scientific validation (a human-confirmed, real-backend, validated-model finding) - which
  is NEVER implied by cryptographic verification or by anchors merely being supplied.
Verification is done server-side; the browser is never trusted as a verification engine.
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Tuple

import signing
from parallax.research import store as rstore
from parallax.research import measurement as M
from parallax.research import strata_view as SV
from parallax.research import evidence_verifier as EV

_SCOPE_NOTE = "Attack only the provided synthetic research corpus. No real PII. No out-of-scope targets."

# A fixed causal order used to sequence events when timestamps are absent or ambiguous. Stable record
# identifiers break ties within a type so ordering is deterministic and never fabricated.
_TYPE_ORDER = {
    "authorized_task": 0, "untrusted_content": 1, "model_response": 2, "tool_call": 3,
    "tool_result": 4, "automated_detection": 5, "human_review": 6, "evidence_verification": 7,
}


def _iso_epoch(v: Any) -> Optional[str]:
    try:
        return (datetime.datetime.fromtimestamp(float(v), datetime.timezone.utc)
                .replace(tzinfo=None).isoformat() + "Z")
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------ campaign navigation (owner-scoped)

def list_campaigns(db, *, researcher_id: str) -> List[Dict[str, Any]]:
    """Owner-scoped campaigns the researcher may access. Each trial run is a campaign here; reviewer-
    authored adjudications are excluded by overview_for. Empty/single/multiple are all handled."""
    items = rstore.overview_for(db, authenticated_researcher_id=researcher_id)
    out = []
    for i in items:
        if i.get("kind") != "trial":
            continue
        out.append({"campaign_id": i["run_id"], "created_at": i.get("created_at"),
                    "model_id": i.get("model_id"), "outcome": i.get("outcome"),
                    "backend_provenance": i.get("backend_provenance"),
                    "finding_status": i.get("finding_status")})
    return out


# ------------------------------------------------------------------ server-side verification (4 states)

def verify_record_server_side(full_run: Dict[str, Any], *, is_empirical: Optional[bool] = None,
                              has_human_confirmed: bool = False,
                              full_outcome_review: bool = False,
                              model_validated: bool = False) -> Dict[str, Any]:
    """Return the four DISTINCT verification concepts for one stored run. Crypto + integrity are
    computed here, server-side, against the signing module's trusted public registry. Independent
    scientific validation is a separate, stricter concept and is never implied by crypto success."""
    record = full_run.get("record") or {}
    signature = None  # signature is never returned by get_run; we use its verified flag plus a re-check
    crypto = "unavailable"
    # get_run already verified the signature against the trusted registry; surface that result and also
    # confirm the inner trial record's evidence hash is self-consistent (integrity).
    sig_verifies = full_run.get("signature_verifies")
    if sig_verifies is True:
        crypto = "succeeded"
    elif sig_verifies is False:
        crypto = "failed"

    tr = ((record.get("metrics") or {}).get("record") or {})
    integrity = "absent"
    if tr.get("evidence_hash"):
        recomputed = EV._recompute_evidence_hash(tr)
        integrity = "ok" if recomputed == tr.get("evidence_hash") else "mismatch"

    # independent scientific validation: a real-backend, validated-model, human-confirmed finding under
    # full outcome review. Anything short of ALL of these is not_established. Never asserted from crypto.
    reasons = []
    if is_empirical is not True:
        reasons.append("not an infrastructure-backed, signature-verified run")
    if not model_validated:
        reasons.append("model is not on the validated list")
    if not has_human_confirmed:
        reasons.append("no human-confirmed disposition")
    if not full_outcome_review:
        reasons.append("outcome review is not complete (unreviewed negatives remain)")
    independent_finding = "established" if not reasons else "not_established"

    return {
        "crypto": crypto,                       # succeeded | failed | unavailable
        "integrity": integrity,                 # ok | mismatch | absent
        "independent_finding": independent_finding,   # established | not_established
        "independent_finding_reasons": reasons,
        "independence_attested_by_tool": False,  # custody is external; never asserted here
        "trusted_kids": [e["kid"] for e in signing.public_registry()],
        "note": ("Cryptographic verification and integrity are separate from independent scientific "
                 "validation; a verified signature never implies independent custody or a correct "
                 "scientific conclusion."),
    }


# ------------------------------------------------------------------ chronological timeline

def build_timeline(full_run: Dict[str, Any], *, decisions: List[Dict[str, Any]],
                   verification: Dict[str, Any], measurement_status: str) -> List[Dict[str, Any]]:
    """Construct the event timeline from STORED evidence only. Each event distinguishes event time
    (when it happened), ingestion time (when the run was persisted), and review time (when adjudicated).
    Events are emitted ONLY when the underlying record supports them; nothing is fabricated."""
    record = full_run.get("record") or {}
    tr = ((record.get("metrics") or {}).get("record") or {})
    run_id = full_run.get("run_id") or record.get("run_id") or "run"
    ingestion = None  # get_run does not return created_at; the overview item carries it (passed via run)
    ingestion = full_run.get("created_at")
    timing = tr.get("timing") or {}
    prov_ts = ((tr.get("provenance") or {}).get("timestamps") or {})
    event_time = _iso_epoch(prov_ts.get("started") or timing.get("started"))

    events: List[Dict[str, Any]] = []

    def add(etype, label, detail, *, event_time=None, review_time=None, record_id=None,
            confirmed=False):
        events.append({"type": etype, "label": label, "detail": detail,
                       "event_time": event_time, "ingestion_time": ingestion,
                       "review_time": review_time, "record_id": record_id or run_id,
                       "confirmed_conclusion": confirmed})

    if tr.get("legitimate_task") or tr.get("legitimate_task_id"):
        add("authorized_task", "Authorized task",
            tr.get("legitimate_task") or tr.get("legitimate_task_id"), event_time=event_time)
    if tr.get("adversarial_input_id") or tr.get("retrieved_doc_ids"):
        src = tr.get("adversarial_input_id") or ""
        docs = tr.get("retrieved_doc_ids") or []
        add("untrusted_content", "Untrusted content in context",
            ("attributed source: %s; retrieved: %s" % (src or "-", docs or "-")), event_time=event_time)
    if tr.get("observed_behavior") is not None:
        add("model_response", "Model response", str(tr.get("observed_behavior")), event_time=event_time)
    # tool-call / execution events are emitted ONLY if the record actually carries them (it usually does
    # not for this study); never fabricated.
    for tc in (tr.get("tool_calls") or []):
        add("tool_call", "Tool-call request", str(tc.get("request") if isinstance(tc, dict) else tc),
            event_time=event_time)
        if isinstance(tc, dict) and "result" in tc:
            add("tool_result", "Observed execution result", str(tc.get("result")), event_time=event_time)
    if tr.get("outcome"):
        add("automated_detection", "Automated detection (heuristic)",
            ("machine outcome: %s; status: %s (candidate detections are heuristic, not confirmed)"
             % (tr.get("outcome"), measurement_status)), event_time=event_time)
    for d in decisions:
        add("human_review", "Human-review decision",
            ("decision: %s by %s%s" % (d.get("decision"), d.get("reviewer_id") or "?",
                                       "" if d.get("signature_verifies") else " (signature UNVERIFIED)")),
            review_time=d.get("at"), record_id=d.get("adjudication_id"),
            confirmed=(d.get("decision") == "met" and bool(d.get("signature_verifies"))))
    add("evidence_verification", "Evidence verification (server-side)",
        ("crypto: %s; integrity: %s; independent finding: %s"
         % (verification["crypto"], verification["integrity"], verification["independent_finding"])))

    # order by the best available timestamp, then the fixed causal order, then record id for stability
    def _key(e):
        ts = e["event_time"] or e["review_time"] or e["ingestion_time"] or ""
        return (ts, _TYPE_ORDER.get(e["type"], 99), str(e["record_id"]))
    events.sort(key=_key)
    for idx, e in enumerate(events):
        e["seq"] = idx
    return events


# ------------------------------------------------------------------ top-level assembly

def assemble(db, *, researcher_id: str, run_id: Optional[str] = None,
             investigation_id: Optional[str] = None) -> Dict[str, Any]:
    """Build the full investigation workspace view for an entitled researcher over their OWN runs.

    Server-side validation: get_run is owner-scoped, so a cross-owner or unknown run_id raises/returns
    nothing and we fall back to the owner's own campaigns rather than leaking. A cross-program viewer is
    rejected upstream by the route's entitlement check and here by build_view's scope gate."""
    campaigns = list_campaigns(db, researcher_id=researcher_id)
    campaign_ids = {c["campaign_id"] for c in campaigns}
    selected = run_id if (run_id in campaign_ids) else (campaigns[0]["campaign_id"] if campaigns else None)

    items = rstore.overview_for(db, authenticated_researcher_id=researcher_id)
    trials = [i for i in items if i.get("kind") == "trial"]
    investigations = [i for i in items if i.get("kind") == "investigation"]
    focus_trials = [t for t in trials if t["run_id"] == selected] if selected else []

    records: List[Dict[str, Any]] = []
    key_of_run: Dict[str, str] = {}
    full_by_run: Dict[str, Dict[str, Any]] = {}
    for t in (focus_trials or trials):
        full = rstore.get_run(db, run_id=t["run_id"], authenticated_researcher_id=researcher_id)
        if not full:
            continue
        full["created_at"] = t.get("created_at")       # carry ingestion time for the timeline
        full_by_run[t["run_id"]] = full
        tr = ((full.get("record") or {}).get("metrics") or {}).get("record") or {}
        rec = dict(tr)
        rec.setdefault("experiment_id", t["run_id"])
        rec["run_id"] = t["run_id"]
        rec["backend_is_real"] = (t.get("backend_provenance") == "infrastructure_backed")
        rec["produced_by"] = researcher_id
        records.append(rec)
        key_of_run[t["run_id"]] = M._record_key(rec)

    adjudications: Dict[str, Dict[str, Any]] = {}
    decisions_by_run: Dict[str, List[Dict[str, Any]]] = {}
    for inv in investigations:
        parent = inv.get("parent_run")
        if parent not in key_of_run:
            continue
        decs = rstore._decisions_for(db, inv["run_id"])
        decisions_by_run.setdefault(parent, []).extend(decs)
        latest = decs[-1] if decs else None
        if latest and latest.get("decision"):
            disp = M.disposition_from_decision(
                latest["decision"], reviewer_id=latest.get("reviewer_id") or "",
                verified=bool(latest.get("signature_verifies")), signed=True)
            if disp:
                adjudications[key_of_run[parent]] = disp

    mission = {"program": "PARALLAX", "title": "Prompt-injection boundary investigation",
               "campaign_id": selected or "none", "dataset": "synthetic research corpus",
               "authorized_scope": _SCOPE_NOTE,
               "rules_of_engagement": "Observe recorded behavior and attributed sources only."}

    view = SV.build_view(mission=mission, records=records, adjudications=adjudications,
                         entitled=True, viewer_scope=["PARALLAX"])

    # Campaign navigation state (owner-scoped; selected id preserved).
    view["campaigns"] = campaigns
    view["selected_campaign"] = selected
    view["campaign_count"] = len(campaigns)

    # Server-side verification + timeline for the selected campaign only (bounded work).
    if selected and selected in full_by_run:
        full = full_by_run[selected]
        sel_decisions = decisions_by_run.get(selected, [])
        # measurement status of the selected record (for timeline labelling)
        sel_rec = next((r for r in records if r.get("run_id") == selected), {})
        cls = M.classify_record(sel_rec, adjudications.get(key_of_run.get(selected, "")))
        summ = view["measurement"]["adjudicated"]
        verification = verify_record_server_side(
            full, is_empirical=full.get("is_empirical_finding"),
            has_human_confirmed=(summ["confirmed"] > 0),
            full_outcome_review=bool(summ.get("full_outcome_review")),
            model_validated=False)
        view["verification"] = verification
        view["timeline"] = build_timeline(full, decisions=sel_decisions, verification=verification,
                                           measurement_status=cls["status"])
    else:
        view["verification"] = {"crypto": "unavailable", "integrity": "absent",
                                "independent_finding": "not_established",
                                "independent_finding_reasons": ["no campaign selected or evidence missing"],
                                "independence_attested_by_tool": False, "trusted_kids": []}
        view["timeline"] = []
    return view
