"""Workstream C: STRATA trace-explorer view tests.

Monkeypatches the owner-scoped store so campaign navigation, cross-owner isolation (CampaignNotFound),
server-side filtering, bounded/escaped evidence excerpts, and the honesty invariants (heuristic ->
candidate, never confirmed compromise) are all exercised on real assembly logic.
"""
import pytest

from parallax.research import research_trace_view as STV
from parallax import strata_investigation as SI
from parallax.research import store as rstore
from parallax.research import protocol as P


def _trial_item(run_id, owner):
    return {"kind": "trial", "run_id": run_id, "created_at": "2026-01-02T00:00:00",
            "model_id": "m", "outcome": "successful_unauthorized_behavior",
            "backend_provenance": "simulated", "finding_status": "candidate", "_owner": owner}


def _inner_attack(long_doc=False):
    return {"experiment_id": "e1", "legitimate_task": "What formats are supported?",
            "adversarial_input_id": "a-direct",
            "retrieved_doc_ids": ["d1"] if not long_doc else ["d1"],
            "observed_behavior": "Sure, here you go: %s" % P.CANARY,
            "outcome": "successful_unauthorized_behavior", "condition": "experimental_attack",
            "attempts_injection": True, "evaluation": {"canary": True}, "model": {"id": "m"},
            "timing": {"started": 1000.0},
            "legitimate_task_long": ("A" * 1000) if long_doc else None}


@pytest.fixture
def fake_store(monkeypatch):
    # owner -> overview items; (owner, run_id) -> full run
    world = {
        "alice": [_trial_item("run-a", "alice")],
        "bob": [_trial_item("run-b", "bob")],
    }
    fulls = {
        ("alice", "run-a"): {"run_id": "run-a", "created_at": "2026-01-02T00:00:00",
                             "record": {"metrics": {"record": _inner_attack()}},
                             "signature_verifies": True},
        ("bob", "run-b"): {"run_id": "run-b", "created_at": "2026-01-02T00:00:00",
                           "record": {"metrics": {"record": _inner_attack()}},
                           "signature_verifies": True},
    }

    def fake_overview_for(db, *, authenticated_researcher_id):
        return [dict(i) for i in world.get(authenticated_researcher_id, [])]

    def fake_get_run(db, *, run_id, authenticated_researcher_id):
        return fulls.get((authenticated_researcher_id, run_id))   # None if not owned -> isolation

    def fake_decisions_for(db, inv_run_id):
        return []

    monkeypatch.setattr(rstore, "overview_for", fake_overview_for)
    monkeypatch.setattr(rstore, "get_run", fake_get_run)
    monkeypatch.setattr(rstore, "_decisions_for", fake_decisions_for)
    return world


def test_assembles_trace_analysis_and_summary(fake_store):
    v = STV.assemble_trace_view(object(), researcher_id="alice")
    assert v["selected_campaign"] == "run-a" and v["campaign_count"] == 1
    assert v["trace"]["schema_version"].startswith("px-trace")
    assert v["analysis"]["analysis_version"].startswith("px-trust")
    # canary emission is observed-unauthorized but a CANDIDATE, never a confirmed compromise
    assert v["summary"]["scientific_status"]["independent_validation"] == "none claimed"
    assert any(f["pattern"] == "canary_emission" for e in v["events"] for f in e["findings"])
    assert v["summary"]["review_status"] == "unreviewed"


def test_cross_owner_requested_campaign_is_not_found(fake_store):
    # bob asks for alice's run: identical 404 to a nonexistent id (no existence oracle)
    with pytest.raises(SI.CampaignNotFound):
        STV.assemble_trace_view(object(), researcher_id="bob", run_id="run-a")
    with pytest.raises(SI.CampaignNotFound):
        STV.assemble_trace_view(object(), researcher_id="bob", run_id="does-not-exist")


def test_no_campaigns_returns_empty_view(fake_store):
    v = STV.assemble_trace_view(object(), researcher_id="carol")   # not in world
    assert v["selected_campaign"] is None and v["campaign_count"] == 0
    assert v["events"] == [] and v["trace"] is None


def test_event_type_filter_is_server_side(fake_store):
    allv = STV.assemble_trace_view(object(), researcher_id="alice")
    only_model = STV.assemble_trace_view(object(), researcher_id="alice",
                                         filters={"event_type": "model_output"})
    assert only_model["shown_event_count"] >= 1
    assert all(e["type"] == "model_output" for e in only_model["events"])
    assert only_model["shown_event_count"] <= allv["all_event_count"]
    assert only_model["all_event_count"] == allv["all_event_count"]   # facets unchanged by filter


def test_finding_filter_selects_events_with_findings(fake_store):
    withf = STV.assemble_trace_view(object(), researcher_id="alice", filters={"finding": "with"})
    assert withf["shown_event_count"] >= 1
    assert all(e["has_finding"] for e in withf["events"])


def test_excerpt_is_length_bounded(fake_store, monkeypatch):
    # craft a long retrieved/observed field and confirm the excerpt is bounded, not unbounded HTML
    long_inner = _inner_attack()
    long_inner["observed_behavior"] = "<script>alert(1)</script>" + ("Z" * 5000)
    monkeypatch.setattr(rstore, "get_run",
                        lambda db, *, run_id, authenticated_researcher_id:
                        {"run_id": "run-a", "created_at": "t",
                         "record": {"metrics": {"record": long_inner}}})
    v = STV.assemble_trace_view(object(), researcher_id="alice")
    mo = [e for e in v["events"] if e["type"] == "model_output"][0]
    assert mo["excerpt"]["truncated"] is True
    assert len(mo["excerpt"]["text"]) == STV.EXCERPT_CHARS
    assert mo["excerpt"]["full_length"] > STV.EXCERPT_CHARS
