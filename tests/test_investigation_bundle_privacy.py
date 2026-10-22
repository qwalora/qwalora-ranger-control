"""Priority 3: investigation-bundle export privacy hardening (deny-by-default).

Verifies the export schema + sensitive-key redaction + bounded-content handling: nested secrets,
tokens embedded in tool arguments, sensitive URLs, personal information, unknown/oversized structures,
malicious archive members, symlink/non-empty destinations, and malformed manifests. Also checks that
the manifest never claims redaction is a guarantee, and that cryptographic integrity stays distinct
from independent custody.
"""
import json
import os

import pytest

from parallax.research import agent_trace as AT
from parallax.research import trust_analysis as TA
from parallax.research import investigation_bundle as IB
from parallax.research import evidence_verifier as EV


def _blob(dest):
    s = ""
    for fn in os.listdir(dest):
        s += open(os.path.join(dest, fn), encoding="utf-8").read()
    return s


def _trace_with(content_doc, tool_args=None):
    msgs = [{"role": "assistant", "content": "ok"}]
    if tool_args is not None:
        msgs = [{"role": "assistant", "tool_call": {"id": "c1", "name": "http_post", "arguments": tool_args}},
                {"role": "tool", "content": "200 OK", "tool_call_id": "c1"}]
    o = {"trace_id": "t", "model": {"id": "m"}, "request": "summarize",
         "retrieved": [{"id": "d1", "source": "web", "content": content_doc}], "messages": msgs}
    return AT.from_open_agent_trace(o)


def test_credential_in_retrieved_content_is_scrubbed(tmp_path):
    t = _trace_with("leaked token ghp_ABCDEFGHIJKLMNOP1234 and key AKIAABCDEFGHIJKLMNOP")
    IB.build_bundle(str(tmp_path / "b"), trace=t)
    blob = _blob(str(tmp_path / "b"))
    assert "ghp_ABCDEFGHIJKLMNOP1234" not in blob and "AKIAABCDEFGHIJKLMNOP" not in blob
    assert "[SCRUBBED:" in blob


def test_token_embedded_in_tool_arguments_is_scrubbed(tmp_path):
    t = _trace_with("benign doc", tool_args="POST Authorization: Bearer ghp_SECRETSECRETSECRET99 to api")
    IB.build_bundle(str(tmp_path / "b"), trace=t)
    assert "ghp_SECRETSECRETSECRET99" not in _blob(str(tmp_path / "b"))


def test_sensitive_key_name_is_redacted_regardless_of_value(tmp_path):
    t = _trace_with("benign")
    # a value that the credential regex would NOT match, but the KEY name is sensitive
    IB.build_bundle(str(tmp_path / "b"), trace=t,
                    evidence_refs=[{"password": "hunter2plain", "note": "ok", "api_key": "xyz-not-regex"}])
    blob = _blob(str(tmp_path / "b"))
    assert "hunter2plain" not in blob and "xyz-not-regex" not in blob
    assert "[REDACTED:sensitive-key]" in blob


def test_nested_secret_in_coverage_is_redacted(tmp_path):
    t = _trace_with("benign")
    IB.build_bundle(str(tmp_path / "b"), trace=t,
                    coverage_metrics={"deep": {"deeper": {"secret": "s3cr3t-value-here"}}})
    assert "s3cr3t-value-here" not in _blob(str(tmp_path / "b"))


def test_oversized_and_deeply_nested_structures_are_bounded(tmp_path):
    t = _trace_with("benign")
    deep = {}
    cur = deep
    for _ in range(50):
        cur["n"] = {}
        cur = cur["n"]
    big_list = list(range(IB.MAX_EXPORT_LIST + 500))
    man = IB.build_bundle(str(tmp_path / "b"), trace=t,
                          coverage_metrics={"deep": deep, "big": big_list,
                                            "longstr": "Z" * (IB.MAX_EXPORT_STR + 100)})
    stats = man["export_redaction"]["stats"]
    assert stats.get("depth_dropped", 0) >= 1
    assert stats.get("list_truncated", 0) >= 1
    assert stats.get("strings_truncated", 0) >= 1


def test_manifest_discloses_redaction_is_not_a_guarantee(tmp_path):
    t = _trace_with("benign")
    man = IB.build_bundle(str(tmp_path / "b"), trace=t)
    disc = man["export_redaction"]["disclaimer"].lower()
    assert "not a guarantee" in disc
    assert "custody" in man["custody_note"].lower()


def test_unknown_top_level_keys_are_dropped_by_schema(tmp_path):
    t = _trace_with("benign")
    # inject an unexpected top-level key into the trace; it must not survive into the exported trace
    t["surprise_field"] = "SHOULD_NOT_EXPORT_marker"
    man = IB.build_bundle(str(tmp_path / "b"), trace=t)
    assert "SHOULD_NOT_EXPORT_marker" not in _blob(str(tmp_path / "b"))
    assert man["export_redaction"]["stats"].get("top_keys_dropped", 0) >= 1


def test_malicious_archive_member_rejected():
    for bad in ("../x.json", "/etc/passwd", "a/../../b.json"):
        with pytest.raises(EV.UnsafeExportPath):
            EV.assert_safe_archive_member(bad)


def test_symlink_and_nonempty_destinations_rejected(tmp_path):
    t = _trace_with("benign")
    ne = tmp_path / "ne"; ne.mkdir(); (ne / "x").write_text("hi")
    with pytest.raises(EV.UnsafeExportPath):
        IB.build_bundle(str(ne), trace=t)
    real = tmp_path / "real"; real.mkdir()
    link = tmp_path / "link"; link.symlink_to(real)
    with pytest.raises(EV.UnsafeExportPath):
        IB.build_bundle(str(link), trace=t)


def test_malformed_manifest_is_unverifiable(tmp_path):
    t = _trace_with("benign")
    dest = str(tmp_path / "b")
    IB.build_bundle(dest, trace=t)
    with open(os.path.join(dest, "manifest.json"), "w") as fh:
        fh.write("{ this is not valid json")
    rep = IB.verify_bundle(dest)
    assert rep["ok"] is False and any("unparseable" in p for p in rep["problems"])


def test_crypto_consistency_is_kept_distinct_from_custody(tmp_path):
    t = _trace_with("benign")
    a = TA.analyze(t)
    dest = str(tmp_path / "b")
    IB.build_bundle(dest, trace=t, analysis=a)
    rep = IB.verify_bundle(dest)
    assert rep["ok"] is True
    assert "does not attest independent" in rep["custody_note"]
