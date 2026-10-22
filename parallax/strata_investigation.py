"""Read-only bridge from the existing PARALLAX research store to the STRATA investigation workspace.

MINIMAL-RELEASE variant: depends only on store functions present in the deployed nonprod revision
(runs_for, get_run, _decisions_for, _kind_of, _parent_of) so the STRATA workspace can ship as a purely
additive backport without the unrelated integration commits. It builds NO parallel database, persists
nothing, reuses the existing signed review workflow, and lets the measurement layer enforce that a
disposition is authoritative only when verified, signed, and authored by someone other than the
record's producer (separation of duties). Cryptographic verification is done server-side and is kept
distinct from integrity and from independent scientific validation.
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

import signing
from parallax.research import store as rstore
from parallax.research import measurement as M
from parallax.research import strata_view as SV
from parallax.research import evidence_verifier as EV

_SCOPE_NOTE = "Attack only the provided synthetic research corpus. No real PII. No out-of-scope targets."


class CampaignNotFound(Exception):
    """An explicitly requested campaign id is not among the viewer's own campaigns (404, not a silent
    fallback). Identical for a nonexistent id and another owner's id, so it leaks no existence."""


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


def _owner_created_at(run_id: str, researcher_id: str) -> Optional[str]:
    """Owner-scoped ingestion time for one run, read directly (get_run does not return it). Double
    owner check: filter by run_id AND researcher_id so another owner's row is never read."""
    try:
        from models import ParallaxResearchRun
        row = ParallaxResearchRun.query.filter_by(run_id=run_id, researcher_id=researcher_id).first()
        return row.created_at.isoformat() if (row and row.created_at) else None
    except Exception:  # noqa: BLE001
        return None


def _owned_runs(db, researcher_id: str) -> List[Dict[str, Any]]:
    """Resolve the researcher's own runs into {run_id, kind, parent_run, backend_provenance, record,
    created_at}, using only b0f1588-present store functions."""
    out: List[Dict[str, Any]] = []
    for r in rstore.runs_for(db, authenticated_researcher_id=researcher_id):
        full = rstore.get_run(db, run_id=r["run_id"], authenticated_researcher_id=researcher_id)
        if not full:
            continue
        rec = full.get("record") or {}
        out.append({"run_id": r["run_id"], "kind": rstore._kind_of(rec) or "run",
                    "parent_run": rstore._parent_of(rec),
                    "backend_provenance": r.get("backend_provenance"),
                    "is_empirical_finding": full.get("is_empirical_finding"),
                    "model_id": r.get("model_id"),
                    "created_at": _owner_created_at(r["run_id"], researcher_id),
                    "record": rec, "full": full})
    return out


# ------------------------------------------------------------------ campaign navigation (owner-scoped)

def list_campaigns(db, *, researcher_id: str) -> List[Dict[str, Any]]:
    """Owner-scoped campaigns (each trial run is a campaign). Empty/single/multiple all handled."""
    out = []
    for r in _owned_runs(db, researcher_id):
        if r["kind"] != "trial":
            continue
        tr = ((r["record"].get("metrics") or {}).get("record") or {})
        out.append({"campaign_id": r["run_id"], "created_at": r["created_at"],
                    "model_id": r.get("model_id"), "outcome": tr.get("outcome"),
                    "backend_provenance": r.get("backend_provenance")})
    return out


# ------------------------------------------------------------------ server-side verification (4 states)

def verify_record_server_side(full_run: Dict[str, Any], *, is_empirical: Optional[bool] = None,
                              has_human_confirmed: bool = False,
                              full_outcome_review: bool = False,
                              model_validated: bool = False) -> Dict[str, Any]:
    """Four DISTINCT verification concepts for one stored run, computed server-side against the signing
    module's trusted registry. Independent scientific validation is never implied by crypto success."""
    record = full_run.get("record") or {}
    crypto = "unavailable"
    sig_verifies = full_run.get("signature_verifies")
    if sig_verifies is True:
        crypto = "succeeded"
    elif sig_verifies is False:
        crypto = "failed"

    tr = ((record.get("metrics") or {}).get("record") or {})
    integrity = "absent"
    if tr.get("evidence_hash"):
        integrity = "ok" if EV._recompute_evidence_hash(tr) == tr.get("evidence_hash") else "mismatch"

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
        "scope": "per_record",
        "full_chain_verification": "not_run_inline",
        "crypto": crypto, "integrity": integrity,
        "independent_finding": independent_finding, "independent_finding_reasons": reasons,
        "independence_attested_by_tool": False,
        "trusted_kids": [e["kid"] for e in signing.public_registry()],
        "trusted_key_source": "server signing registry (active/verify-only keys), not client-supplied",
        "note": ("PER-RECORD cryptographic verification and integrity only, distinct from full "
                 "campaign-chain verification (not run here). Neither implies independent custody or a "
                 "correct scientific conclusion."),
    }


# ------------------------------------------------------------------ chronological timeline

def build_timeline(full_run: Dict[str, Any], *, decisions: List[Dict[str, Any]],
                   verification: Dict[str, Any], measurement_status: str,
                   ingestion: Optional[str] = None) -> List[Dict[str, Any]]:
    record = full_run.get("record") or {}
    tr = ((record.get("metrics") or {}).get("record") or {})
    run_id = full_run.get("run_id") or record.get("run_id") or "run"
    if ingestion is None:
        ingestion = full_run.get("created_at")
    timing = tr.get("timing") or {}
    prov_ts = ((tr.get("provenance") or {}).get("timestamps") or {})
    event_time = _iso_epoch(prov_ts.get("started") or timing.get("started"))
    events: List[Dict[str, Any]] = []

    def add(etype, label, detail, *, event_time=None, review_time=None, record_id=None, confirmed=False):
        events.append({"type": etype, "label": label, "detail": detail, "event_time": event_time,
                       "ingestion_time": ingestion, "review_time": review_time,
                       "record_id": record_id or run_id, "confirmed_conclusion": confirmed})

    if tr.get("legitimate_task") or tr.get("legitimate_task_id"):
        add("authorized_task", "Authorized task",
            tr.get("legitimate_task") or tr.get("legitimate_task_id"), event_time=event_time)
    if tr.get("adversarial_input_id") or tr.get("retrieved_doc_ids"):
        add("untrusted_content", "Untrusted content in context",
            ("attributed source: %s; retrieved: %s" % (tr.get("adversarial_input_id") or "-",
                                                        tr.get("retrieved_doc_ids") or "-")),
            event_time=event_time)
    if tr.get("observed_behavior") is not None:
        add("model_response", "Model response", str(tr.get("observed_behavior")), event_time=event_time)
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

    def _key(e):
        ts = e["event_time"] or e["review_time"] or e["ingestion_time"] or ""
        return (ts, _TYPE_ORDER.get(e["type"], 99), str(e["record_id"]))
    events.sort(key=_key)
    for idx, e in enumerate(events):
        e["seq"] = idx
    return events


# ------------------------------------------------------------------ top-level assembly

def _record_key(rec: Dict[str, Any]) -> str:
    return rec.get("evidence_hash") or rec.get("experiment_id") or ""


def assemble(db, *, researcher_id: str, run_id: Optional[str] = None,
             investigation_id: Optional[str] = None) -> Dict[str, Any]:
    owned = _owned_runs(db, researcher_id)
    trials = [r for r in owned if r["kind"] == "trial"]
    investigations = [r for r in owned if r["kind"] == "investigation"]
    campaigns = [{"campaign_id": t["run_id"], "created_at": t["created_at"], "model_id": t.get("model_id"),
                  "outcome": ((t["record"].get("metrics") or {}).get("record") or {}).get("outcome"),
                  "backend_provenance": t.get("backend_provenance")} for t in trials]
    campaign_ids = {c["campaign_id"] for c in campaigns}
    if run_id and run_id not in campaign_ids:
        raise CampaignNotFound("campaign %r is not available to this user" % run_id)
    selected = run_id if (run_id in campaign_ids) else (campaigns[0]["campaign_id"] if campaigns else None)

    focus = [t for t in trials if t["run_id"] == selected] if selected else []
    records: List[Dict[str, Any]] = []
    key_of_run: Dict[str, str] = {}
    full_by_run: Dict[str, Dict[str, Any]] = {}
    ingest_by_run: Dict[str, Optional[str]] = {}
    for t in (focus or trials):
        tr = ((t["record"].get("metrics") or {}).get("record") or {})
        rec = dict(tr)
        rec.setdefault("experiment_id", t["run_id"])
        rec["run_id"] = t["run_id"]
        rec["backend_is_real"] = (t.get("backend_provenance") == "infrastructure_backed")
        rec["produced_by"] = researcher_id
        records.append(rec)
        key_of_run[t["run_id"]] = _record_key(rec)
        full_by_run[t["run_id"]] = t["full"]
        ingest_by_run[t["run_id"]] = t["created_at"]

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

    sel_tr = ((full_by_run.get(selected or "", {}).get("record") or {}).get("metrics") or {}).get("record") or {}
    dataset = sel_tr.get("corpus_version") or "synthetic research corpus (no corpus_version recorded)"
    mission = {"program": "PARALLAX", "title": "Prompt-injection boundary investigation",
               "campaign_id": selected or "none", "dataset": dataset,
               "authorized_scope": _SCOPE_NOTE,
               "rules_of_engagement": "Observe recorded behavior and attributed sources only."}

    view = SV.build_view(mission=mission, records=records, adjudications=adjudications,
                         entitled=True, viewer_scope=["PARALLAX"])
    view["campaigns"] = campaigns
    view["selected_campaign"] = selected
    view["campaign_count"] = len(campaigns)

    if selected and selected in full_by_run:
        full = full_by_run[selected]
        sel_rec = next((r for r in records if r.get("run_id") == selected), {})
        cls = M.classify_record(sel_rec, adjudications.get(key_of_run.get(selected, "")))
        summ = view["measurement"]["adjudicated"]
        verification = verify_record_server_side(
            full, is_empirical=full.get("is_empirical_finding"),
            has_human_confirmed=(summ["confirmed"] > 0),
            full_outcome_review=bool(summ.get("full_outcome_review")), model_validated=False)
        view["verification"] = verification
        view["timeline"] = build_timeline(full, decisions=decisions_by_run.get(selected, []),
                                           verification=verification, measurement_status=cls["status"],
                                           ingestion=ingest_by_run.get(selected))
    else:
        view["verification"] = {"crypto": "unavailable", "integrity": "absent",
                                "independent_finding": "not_established",
                                "independent_finding_reasons": ["no campaign selected or evidence missing"],
                                "independence_attested_by_tool": False, "trusted_kids": []}
        view["timeline"] = []
    return view
