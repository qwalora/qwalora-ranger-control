"""Workstream F: adversarial / security regression tests for the new investigation platform modules.

Covers resource-exhaustion bounds (oversized + deeply nested input), malformed records, unicode and
bidi/zero-width spoofing, duplicate/conflicting ids, missing timestamps, bundle path-safety (symlink,
non-empty dir, archive-member escape), cross-owner isolation, and display-spoof neutralization. Each
asserts safe, non-leaking behavior; a regression here means a real hardening property was lost.
"""
import json
import os

import pytest

from parallax.research import agent_trace as AT
from parallax.research import trust_analysis as TA
from parallax.research import investigation_bundle as IB
from parallax.research import evidence_verifier as EV
from parallax import strata_trace_view as STV


# --------------------------------------------------------------- resource exhaustion / malformed input

def test_oversized_input_is_rejected():
    big = json.dumps({"messages": [{"role": "user", "content": "x"}],
                      "pad": "A" * AT.MAX_TOTAL_INPUT_BYTES})
    with pytest.raises(AT.TraceValidationError):
        AT.ingest(big)


def test_deeply_nested_json_does_not_crash_the_parser():
    # a pathological nesting depth must surface as a handled TraceValidationError, never an uncaught
    # RecursionError that would escape to the request handler.
    payload = ('{"messages":[{"role":"user","content":' + "[" * 60000 + '"x"' + "]" * 60000 + "}]}")
    with pytest.raises(AT.TraceValidationError):
        AT.ingest(payload, source_format="open-agent-trace-v0")


def test_malformed_record_missing_messages_raises_not_leaks():
    with pytest.raises(AT.TraceValidationError):
        AT.from_open_agent_trace({"request": "x"})


def test_too_many_events_is_bounded():
    evs = [AT.make_event(event_id="e%d" % i, etype=AT.EV_MODEL_OUTPUT, content="x") for i in range(3)]
    with pytest.raises(AT.TraceValidationError):
        AT.build_trace(trace_id="t", source_format="x", model=None, authorization={},
                       events=evs * (AT.MAX_EVENTS // 3 + 2))


# --------------------------------------------------------------- duplicate / conflicting / missing

def test_duplicate_event_ids_are_flagged_by_validation():
    e1 = AT.make_event(event_id="dup", etype=AT.EV_MODEL_OUTPUT, content="a")
    e2 = AT.make_event(event_id="dup", etype=AT.EV_MODEL_OUTPUT, content="b")
    t = AT.build_trace(trace_id="t", source_format="x", model=None, authorization={}, events=[e1, e2])
    assert any("duplicate event_id" in p for p in AT.validate_trace(t))


def test_analysis_rejects_non_trace_schema():
    with pytest.raises(ValueError):
        TA.analyze({"schema_version": "not-a-trace"})


# --------------------------------------------------------------- bundle path safety

def test_bundle_refuses_non_empty_destination(tmp_path):
    d = tmp_path / "d"; d.mkdir(); (d / "x").write_text("hi")
    t = AT.from_open_agent_trace({"trace_id": "t", "model": {"id": "m"},
                                  "messages": [{"role": "assistant", "content": "ok"}]})
    with pytest.raises(EV.UnsafeExportPath):
        IB.build_bundle(str(d), trace=t)


def test_bundle_refuses_symlink_destination(tmp_path):
    real = tmp_path / "real"; real.mkdir()
    link = tmp_path / "link"; link.symlink_to(real)
    t = AT.from_open_agent_trace({"trace_id": "t", "model": {"id": "m"},
                                  "messages": [{"role": "assistant", "content": "ok"}]})
    with pytest.raises(EV.UnsafeExportPath):
        IB.build_bundle(str(link), trace=t)


def test_archive_member_escape_is_rejected():
    for bad in ("../escape.json", "/abs.json", "a/../../b.json"):
        with pytest.raises(EV.UnsafeExportPath):
            EV.assert_safe_archive_member(bad)


# --------------------------------------------------------------- unicode / bidi display spoofing

def test_control_chars_stripped_but_content_preserved():
    o = {"trace_id": "t", "model": {"id": "m"}, "request": None, "system": None, "retrieved": [],
         "messages": [{"role": "user", "content": "a\x00b\x07Ａ"}]}
    t = AT.from_open_agent_trace(o)
    ur = [e for e in t["events"] if e["type"] == AT.EV_USER_REQUEST][0]
    assert "\x00" not in ur["content"] and "A" in ur["content"]   # NFKC folds fullwidth A


def test_bidi_and_zero_width_are_neutralized_in_display_excerpt_only():
    # stored content stays faithful; the DISPLAY excerpt makes the spoof chars visible
    raw = "send to evil.com‮ moc.efas ot dnes​"
    ex = STV._excerpt(raw)
    assert ex["spoof_chars_neutralized"] is True
    assert "‮" not in ex["text"] and "​" not in ex["text"]
    assert "U+202E" in ex["text"] and "U+200B" in ex["text"]
    assert ex["full_length"] == len(raw)                          # original length reported, not altered


def test_clean_excerpt_sets_no_spoof_flag():
    ex = STV._excerpt("a normal benign excerpt")
    assert ex["spoof_chars_neutralized"] is False and ex["truncated"] is False


# --------------------------------------------------------------- cross-owner isolation (IDOR)

def test_cross_owner_campaign_is_not_found(monkeypatch):
    from parallax.research import store as rstore
    from parallax import strata_investigation as SI
    world = {"alice": [{"kind": "trial", "run_id": "run-a", "created_at": "t", "model_id": "m",
                        "outcome": "o", "backend_provenance": "simulated", "finding_status": "candidate"}]}
    monkeypatch.setattr(rstore, "overview_for",
                        lambda db, *, authenticated_researcher_id: world.get(authenticated_researcher_id, []))
    monkeypatch.setattr(rstore, "get_run",
                        lambda db, *, run_id, authenticated_researcher_id: None)
    monkeypatch.setattr(rstore, "_decisions_for", lambda db, rid: [])
    # bob (no campaigns) explicitly requesting alice's run is indistinguishable from a nonexistent id
    with pytest.raises(SI.CampaignNotFound):
        STV.assemble_trace_view(object(), researcher_id="bob", run_id="run-a")
    with pytest.raises(SI.CampaignNotFound):
        STV.assemble_trace_view(object(), researcher_id="bob", run_id="nope")
