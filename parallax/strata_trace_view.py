"""Read-only STRATA trace-explorer view (Workstream C).

Layers the new px-trace-v1 normalization, px-trust-v1 trust-boundary analysis, and the deterministic
investigation summary over the SAME owner-scoped research store the investigation page already uses.
It builds no parallel database and persists nothing, reuses the investigation module's owner-scoped
campaign navigation and its CampaignNotFound isolation (identical 404 for a foreign-owner id and a
nonexistent id), and surfaces:

- a trace explorer with server-side filter facets (event type, trust zone, has-finding, review status,
  evidence availability),
- evidence inspection as BOUNDED, HTML-escaped excerpts (Jinja autoescapes; we also length-bound),
- investigation relationships drawn ONLY from observed boundary crossings, each labelled a structural/
  temporal link and explicitly NOT proven causation (a labelled hypothesis, never asserted fact),
- a deterministic investigation summary (reused from investigation_bundle.build_summary).

Honesty invariants carried through: heuristic detections stay candidates, never confirmed compromise;
no tool execution, decision, timestamp, or authorization is invented; cryptographic/structural
consistency is kept distinct from independent human validation.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from parallax.research import store as rstore
from parallax.research import agent_trace as AT
from parallax.research import trust_analysis as TA
from parallax.research import investigation_bundle as IB
from parallax import strata_investigation as SI

EXCERPT_CHARS = 280

# Formatting characters that are invisible or can reverse visible text order. Untrusted evidence may
# embed them to spoof how an exfiltration URL or instruction reads to a human reviewer. They are
# neutralized in the DISPLAY excerpt only (made visible), never removed from the stored trace content,
# so the recorded evidence stays faithful while the reviewer cannot be visually deceived.
_SPOOF_CHARS = {
    "‪": "<U+202A LRE>", "‫": "<U+202B RLE>", "‬": "<U+202C PDF>",
    "‭": "<U+202D LRO>", "‮": "<U+202E RLO>", "⁦": "<U+2066 LRI>",
    "⁧": "<U+2067 RLI>", "⁨": "<U+2068 FSI>", "⁩": "<U+2069 PDI>",
    "​": "<U+200B ZWSP>", "‌": "<U+200C ZWNJ>", "‍": "<U+200D ZWJ>",
    "﻿": "<U+FEFF BOM>",
}

_EVENT_LABELS = {
    AT.EV_USER_REQUEST: "Authorized request",
    AT.EV_SYSTEM_INSTRUCTION: "System instruction",
    AT.EV_DEVELOPER_INSTRUCTION: "Developer instruction",
    AT.EV_RETRIEVED_DOCUMENT: "Untrusted retrieved content",
    AT.EV_TOOL_CALL_REQUEST: "Tool-call request",
    AT.EV_TOOL_RESULT: "Tool result",
    AT.EV_MODEL_OUTPUT: "Model output",
    AT.EV_SECURITY_OBSERVATION: "Automated security observation (heuristic)",
    AT.EV_HUMAN_REVIEW: "Human-review record",
}


def _excerpt(text: Optional[str]) -> Dict[str, Any]:
    """Bounded, display-safe excerpt. The template autoescapes HTML; here we additionally length-bound
    and neutralize bidi/zero-width spoofing characters (made visible, not removed), so a long or hostile
    payload can neither dominate the page nor visually deceive the reviewer. full_length reflects the
    original stored content length (the stored trace content itself is never altered)."""
    s = "" if text is None else str(text)
    full_length = len(s)
    spoofed = any(ch in s for ch in _SPOOF_CHARS)
    if spoofed:
        for ch, vis in _SPOOF_CHARS.items():
            s = s.replace(ch, vis)
    truncated = len(s) > EXCERPT_CHARS
    return {"text": s[:EXCERPT_CHARS] if truncated else s, "truncated": truncated,
            "full_length": full_length, "spoof_chars_neutralized": spoofed}


def _decisions_for_selected(db, *, researcher_id: str, selected: str) -> List[Dict[str, Any]]:
    """Owner-scoped human-review decisions for the selected campaign, mapped to the summary's shape.
    Reuses the store's owner-scoped parent/decision lookups; never fabricates a decision."""
    items = rstore.overview_for(db, authenticated_researcher_id=researcher_id)
    out: List[Dict[str, Any]] = []
    for inv in items:
        if inv.get("kind") != "investigation" or inv.get("parent_run") != selected:
            continue
        for d in rstore._decisions_for(db, inv["run_id"]):
            out.append({"decision": d.get("decision"), "reviewer_id": d.get("reviewer_id"),
                        "verified": bool(d.get("signature_verifies")), "at": d.get("at")})
    return out


def assemble_trace_view(db, *, researcher_id: str, run_id: Optional[str] = None,
                        filters: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Build the trace-explorer view for an entitled researcher over their OWN runs. Raises
    SI.CampaignNotFound for an explicitly requested campaign outside the viewer's own set."""
    filters = {k: v for k, v in (filters or {}).items() if v}
    campaigns = SI.list_campaigns(db, researcher_id=researcher_id)
    campaign_ids = {c["campaign_id"] for c in campaigns}
    if run_id and run_id not in campaign_ids:
        raise SI.CampaignNotFound("campaign %r is not available to this user" % run_id)
    selected = run_id if run_id in campaign_ids else (campaigns[0]["campaign_id"] if campaigns else None)

    base = {"campaigns": campaigns, "selected_campaign": selected, "campaign_count": len(campaigns),
            "filters": filters, "trace": None, "analysis": None, "summary": None,
            "events": [], "facets": {}, "relationships": [], "limitations": [],
            "excerpt_chars": EXCERPT_CHARS}
    if not selected:
        return base

    full = rstore.get_run(db, run_id=selected, authenticated_researcher_id=researcher_id)
    if not full:
        return base
    tr = ((full.get("record") or {}).get("metrics") or {}).get("record") or {}
    if not tr:
        return base

    trace = AT.from_parallax_record(tr)
    analysis = TA.analyze(trace)
    decisions = _decisions_for_selected(db, researcher_id=researcher_id, selected=selected)
    coverage = {"note": "per-record view; campaign-level coverage is reported on the measurement page"}
    summary = IB.build_summary(trace, analysis, decisions, coverage)

    # index observations by the event they concern, to mark events that carry a finding. An observation
    # references its events through source_event + supporting_evidence (both are stable event ids).
    obs_by_event: Dict[str, List[Dict[str, Any]]] = {}
    for o in analysis.get("observations", []):
        linked = set(o.get("supporting_evidence", []) or [])
        if o.get("source_event"):
            linked.add(o["source_event"])
        for ev in linked:
            obs_by_event.setdefault(ev, []).append(o)

    label_by_id = {e["event_id"]: _EVENT_LABELS.get(e["type"], e["type"]) for e in trace["events"]}

    rows: List[Dict[str, Any]] = []
    for e in trace["events"]:
        findings = obs_by_event.get(e["event_id"], [])
        rows.append({
            "event_id": e["event_id"], "seq": e.get("seq"), "type": e["type"],
            "type_label": _EVENT_LABELS.get(e["type"], e["type"]),
            "trust_zone": e.get("trust_zone"), "observed": e.get("observed", True),
            "excerpt": _excerpt(e.get("content")),
            "event_time": (e.get("timestamps") or {}).get("event_time"),
            "ingestion_time": (e.get("timestamps") or {}).get("ingestion_time"),
            "has_finding": bool(findings),
            "findings": [{"pattern": f["pattern"], "severity": f["severity"],
                          "unauthorized_observed": f["unauthorized_behavior_observed"]} for f in findings],
        })

    facets = {
        "event_types": sorted({r["type"] for r in rows}),
        "trust_zones": sorted({r["trust_zone"] for r in rows if r["trust_zone"]}),
        "review_status": summary["review_status"],
        "has_findings": any(r["has_finding"] for r in rows),
    }

    # server-side filtering (robust against a hostile query string; unknown values simply match nothing)
    def _keep(r: Dict[str, Any]) -> bool:
        if "event_type" in filters and r["type"] != filters["event_type"]:
            return False
        if "trust_zone" in filters and r["trust_zone"] != filters["trust_zone"]:
            return False
        if filters.get("finding") == "with" and not r["has_finding"]:
            return False
        if filters.get("finding") == "without" and r["has_finding"]:
            return False
        if filters.get("evidence") == "available" and r["excerpt"]["full_length"] == 0:
            return False
        if filters.get("evidence") == "missing" and r["excerpt"]["full_length"] != 0:
            return False
        return True

    shown = [r for r in rows if _keep(r)]

    # relationships: observed boundary crossings only, each labelled structural/temporal, NOT causation
    relationships = []
    for c in analysis.get("boundary_crossings", []):
        relationships.append({
            "kind": c.get("kind"),
            "from_event": c.get("from_event"), "from_label": label_by_id.get(c.get("from_event"), "?"),
            "to_event": c.get("to_event"), "to_label": label_by_id.get(c.get("to_event"), "?"),
            "basis": "structural/temporal adjacency in the recorded trace",
            "causation": "NOT established (labelled hypothesis; order does not prove the untrusted "
                         "content caused the later action)",
        })

    base.update({
        "trace": {"trace_id": trace["trace_id"], "trace_hash": trace["trace_hash"],
                  "schema_version": trace["schema_version"], "event_count": trace["event_count"],
                  "gaps": trace.get("gaps", [])},
        "analysis": {"analysis_version": analysis["analysis_version"],
                     "summary": analysis["summary"], "confirmation_signals": analysis.get("confirmation_signals", {})},
        "summary": summary, "events": shown, "all_event_count": len(rows),
        "shown_event_count": len(shown), "facets": facets, "relationships": relationships,
        "limitations": analysis.get("limitations", []),
    })
    return base
