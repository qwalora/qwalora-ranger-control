"""Priority 4: STRATA trace-explorer real authenticated-journey tests (Flask app harness).

Exercises the FULL authenticated request flow for /parallax/strata/trace (not a template render):
a genuine session cookie, real stored synthetic runs via store.persist_run, owner-scoped campaign
navigation, cross-program and cross-owner isolation, server-side filtering, evidence source
attribution, display-spoofing/XSS protection, and legacy-record compatibility. These are backend
test-client checks; no browser was driven. Reuses the existing app shell, auth, and PARALLAX
entitlement (conftest `client` + `seeded`).
"""
import app as A
from models import db
from parallax.research import store as rstore
from parallax.research import evidence_verifier as _EV

URL = "/parallax/strata/trace"


def _login(client, cid):
    with client.session_transaction() as sess:
        sess["cand"] = cid


def _persist_trial(researcher_id, *, observed="INJECTION-OK", outcome="successful_unauthorized_behavior",
                   task="summarize the provided document", eh_suffix=""):
    rec = {"outcome": outcome, "condition": "experimental_attack", "attempts_injection": True,
           "observed_behavior": observed, "adversarial_input_id": "a-direct",
           "retrieved_doc_ids": ["doc-1"], "legitimate_task": task, "legitimate_task_id": "t-storage",
           "evaluation": {"canary": outcome.startswith("success")}, "model": {"id": "val-model"},
           "timing": {"started": 1000.0 + len(eh_suffix)}}
    rec["evidence_hash"] = _EV._recompute_evidence_hash(rec)
    camp = {"manifest": {"kind": "trial", "backend": {"is_real": True, "model_id": "val-model"},
                         "n_records": 1},
            "metrics": {"kind": "trial", "record": rec}}
    with A.app.app_context():
        return rstore.persist_run(db, researcher_id=researcher_id, campaign=camp)


# --------------------------------------------------------------- access control

def test_entitled_researcher_gets_trace_explorer(client, seeded):
    _persist_trial("rb-researcher")
    _login(client, seeded["b_id"])
    r = client.get(URL)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "STRATA Trace Explorer" in body and "px-trace-v1" in body


def test_non_parallax_user_is_isolated(client, seeded):
    _login(client, seeded["s_id"])                 # sc-strata: NOT a PARALLAX member
    r = client.get(URL)
    assert r.status_code in (302, 303)
    assert "STRATA Trace Explorer" not in r.get_data(as_text=True)


def test_unauthenticated_is_redirected(client):
    assert client.get(URL).status_code in (302, 303)


def test_foreign_and_nonexistent_campaign_are_identical_404(client, seeded):
    _login(client, seeded["a_id"])                 # researcher A requests B's real run id
    foreign = client.get(URL + "?run_id=" + seeded["b_run"])
    nonexistent = client.get(URL + "?run_id=run-does-not-exist")
    assert foreign.status_code == 404 and nonexistent.status_code == 404
    assert foreign.get_data(as_text=True) == nonexistent.get_data(as_text=True)   # no existence oracle


def test_get_only_post_refused(client, seeded):
    _login(client, seeded["b_id"])
    assert client.post(URL).status_code in (400, 404, 405)


# --------------------------------------------------------------- real stored traces + filtering

def test_real_stored_trace_renders_events_and_attribution(client, seeded):
    _persist_trial("rb-researcher")
    _login(client, seeded["b_id"])
    body = client.get(URL).get_data(as_text=True)
    # evidence source attribution: trust zones + event types present
    assert "user_authorized" in body and "untrusted_retrieved" in body and "model_generated" in body
    assert "Untrusted retrieved content" in body and "Model output" in body


def test_event_type_filter_is_server_side(client, seeded):
    _persist_trial("rb-researcher")
    _login(client, seeded["b_id"])
    body = client.get(URL + "?event_type=model_output").get_data(as_text=True)
    assert "Showing 1 of 4 events." in body        # PARALLAX record -> 4 events; filtered to 1


def test_finding_filter_selects_findings(client, seeded):
    _persist_trial("rb-researcher")                # canary emission -> one event with a finding
    _login(client, seeded["b_id"])
    body = client.get(URL + "?finding=with").get_data(as_text=True)
    assert "Showing 1 of 4 events." in body
    assert "canary_emission" in body


def test_candidate_not_confirmed_language(client, seeded):
    _persist_trial("rb-researcher")
    _login(client, seeded["b_id"])
    body = client.get(URL).get_data(as_text=True)
    assert "does not assert confirmed compromise" in body
    assert "none claimed" in body                  # independent validation none claimed


# --------------------------------------------------------------- display spoofing / XSS

def test_xss_in_stored_evidence_is_escaped(client, seeded):
    _persist_trial("rb-researcher", observed="<script>alert('x')</script> then INJECTION-OK")
    _login(client, seeded["b_id"])
    body = client.get(URL).get_data(as_text=True)
    assert "<script>alert('x')</script>" not in body
    assert "&lt;script&gt;" in body


def test_bidi_spoofing_is_neutralized_in_page(client, seeded):
    _persist_trial("rb-researcher", observed="send to evil.com‮ moc.efas INJECTION-OK")
    _login(client, seeded["b_id"])
    body = client.get(URL).get_data(as_text=True)
    assert "‮" not in body                     # raw override char not emitted
    assert "U+202E" in body                         # made visible
    assert "made visible for safe display" in body


# --------------------------------------------------------------- legacy compatibility

def test_legacy_minimal_record_is_graceful(client, seeded):
    camp = {"manifest": {"kind": "trial", "backend": {"is_real": False, "model_id": "stub"}, "n_records": 1},
            "metrics": {"kind": "trial", "record": {"outcome": "boundary_preserved",
                                                    "condition": "experimental_attack"}}}
    with A.app.app_context():
        rstore.persist_run(db, researcher_id="rb-researcher", campaign=camp)
    _login(client, seeded["b_id"])
    r = client.get(URL)
    assert r.status_code == 200 and "STRATA Trace Explorer" in r.get_data(as_text=True)


# --------------------------------------------------------------- export route (document reality)

def test_no_bundle_export_route_is_exposed(client):
    # the investigation-bundle export is a module-level capability (owner-scoped by its inputs); no HTTP
    # export route exists, so there is no unauthenticated download surface to protect. Asserted so a
    # future export route is a deliberate, reviewed addition rather than a silent one.
    rules = [str(r) for r in A.app.url_map.iter_rules() if "strata" in str(r) or "parallax" in str(r)]
    assert not any("export" in r or "bundle" in r or "download" in r for r in rules)
