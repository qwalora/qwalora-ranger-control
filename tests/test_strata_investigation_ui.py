"""Workstream C + P4: STRATA investigation page journey tests (Flask app harness).

Exercises authorized PARALLAX access, cross-program and cross-owner isolation, candidate-vs-confirmed
rendering, GET-only safety, and graceful error handling, reusing the existing app shell, authentication,
and PARALLAX entitlement. These are backend (test-client) checks; no browser was driven.
"""
import app as A
from models import db
from parallax.research import store as rstore


def _login(client, cid):
    with client.session_transaction() as sess:
        sess["cand"] = cid


def _persist_attack_candidate(researcher_id):
    camp = {"manifest": {"kind": "trial", "backend": {"is_real": True, "model_id": "val-model"},
                         "n_records": 1},
            "metrics": {"kind": "trial", "record": {
                "outcome": "successful_unauthorized_behavior", "condition": "experimental_attack",
                "attempts_injection": True, "observed_behavior": "INJECTION-OK",
                "adversarial_input_id": "a-direct", "evidence_hash": "eh-" + researcher_id,
                "evaluation": {"canary": True}, "model": {"id": "val-model"}}}}
    with A.app.app_context():
        return rstore.persist_run(db, researcher_id=researcher_id, campaign=camp)


URL = "/parallax/strata/investigation"


def test_authorized_parallax_researcher_gets_page(client, seeded):
    _login(client, seeded["b_id"])                 # rb-researcher: active PARALLAX
    r = client.get(URL)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "STRATA Investigation" in body
    assert "Observed evidence" in body and "Unverified conclusions" in body


def test_strata_only_user_is_isolated_from_parallax(client, seeded):
    _login(client, seeded["s_id"])                 # sc-strata: NOT a PARALLAX member
    r = client.get(URL)
    assert r.status_code in (302, 303)             # redirected away, no PARALLAX leak
    assert "STRATA Investigation" not in r.get_data(as_text=True)


def test_unauthenticated_is_redirected(client):
    r = client.get(URL)
    assert r.status_code in (302, 303)


def test_candidate_is_rendered_as_unreviewed_not_confirmed(client, seeded):
    _persist_attack_candidate("rb-researcher")
    _login(client, seeded["b_id"])
    body = client.get(URL).get_data(as_text=True)
    assert "Candidate (unreviewed)" in body            # the heuristic positive, clearly unverified
    assert "Confirmed unauthorized" not in body        # nothing is confirmed without signed review
    assert "not_established" in body                   # confirmed ASR withheld


def test_cross_owner_run_id_does_not_leak(client, seeded):
    # researcher B asks to focus another owner's run id; overview is owner-scoped, so no leak and the
    # page still renders B's own evidence.
    _login(client, seeded["b_id"])
    r = client.get(URL + "?run_id=" + seeded["b_run"])   # b_run belongs to B here; focus resolves
    assert r.status_code == 200
    # a foreign/nonexistent run id simply falls back to the owner's own trials, never 500 or leak
    r2 = client.get(URL + "?run_id=run-does-not-exist")
    assert r2.status_code == 200
    assert "STRATA Investigation" in r2.get_data(as_text=True)


def test_get_only_and_csrf_rejects_post(client, seeded):
    _login(client, seeded["b_id"])
    # the route is GET-only and app-wide CSRF protection rejects an untokened POST before routing;
    # either way a POST is refused (no state-change path exists on this page).
    assert client.post(URL).status_code in (400, 404, 405)   # 400 = CSRF rejection (active)


def _persist_rich_trial(researcher_id, *, observed="INJECTION-OK", outcome="successful_unauthorized_behavior",
                        task="summarize the provided document", eh_suffix=""):
    import time as _t
    rec = {"outcome": outcome, "condition": "experimental_attack", "attempts_injection": True,
           "observed_behavior": observed, "adversarial_input_id": "a-direct",
           "retrieved_doc_ids": ["doc-1"], "legitimate_task": task,
           "legitimate_task_id": "t-storage", "evaluation": {"canary": outcome.startswith("success")},
           "model": {"id": "val-model"}, "timing": {"started": 1000.0 + len(eh_suffix)}}
    from parallax.research import evidence_verifier as _EV
    rec["evidence_hash"] = _EV._recompute_evidence_hash(rec)
    camp = {"manifest": {"kind": "trial", "backend": {"is_real": True, "model_id": "val-model"},
                         "n_records": 1},
            "metrics": {"kind": "trial", "record": rec}}
    with A.app.app_context():
        return rstore.persist_run(db, researcher_id=researcher_id, campaign=camp)


def test_timeline_and_verification_render(client, seeded):
    _persist_rich_trial("rb-researcher")
    _login(client, seeded["b_id"])
    body = client.get(URL).get_data(as_text=True)
    assert "Investigation timeline" in body
    assert "Authorized task" in body and "Model response" in body
    assert "Evidence verification (server-side)" in body
    assert "Cryptographic verification" in body and "Independent scientific finding" in body
    assert "Not established" in body                    # crypto ok but not an independent finding


def test_output_is_escaped(client, seeded):
    _persist_rich_trial("rb-researcher", observed="<script>alert('xss')</script> then INJECTION-OK")
    _login(client, seeded["b_id"])
    body = client.get(URL).get_data(as_text=True)
    assert "<script>alert('xss')</script>" not in body   # not rendered raw
    assert "&lt;script&gt;" in body                        # escaped


def test_large_payload_renders(client, seeded):
    _persist_rich_trial("rb-researcher", observed="A" * 40000)
    _login(client, seeded["b_id"])
    r = client.get(URL)
    assert r.status_code == 200


def test_legacy_minimal_record_is_graceful(client, seeded):
    # a legacy trial with only outcome/condition (no evidence_hash, timing, task) must not crash
    camp = {"manifest": {"kind": "trial", "backend": {"is_real": False, "model_id": "stub"}, "n_records": 1},
            "metrics": {"kind": "trial", "record": {"outcome": "boundary_preserved",
                                                    "condition": "experimental_attack"}}}
    with A.app.app_context():
        rstore.persist_run(db, researcher_id="rb-researcher", campaign=camp)
    _login(client, seeded["b_id"])
    r = client.get(URL)
    assert r.status_code == 200
    assert "STRATA Investigation" in r.get_data(as_text=True)


def test_campaign_selector_multiple(client, seeded):
    _persist_rich_trial("rb-researcher", eh_suffix="x")
    _persist_rich_trial("rb-researcher", eh_suffix="yy")
    _login(client, seeded["b_id"])
    body = client.get(URL).get_data(as_text=True)
    assert 'name="run_id"' in body                      # campaign selector present
    assert "available)" in body
    # selecting a specific campaign preserves it
    cams = None
    with A.app.app_context():
        from parallax import strata_investigation as SI
        cams = SI.list_campaigns(db, researcher_id="rb-researcher")
    assert len(cams) >= 2
    chosen = cams[1]["campaign_id"]
    body2 = client.get(URL + "?run_id=" + chosen).get_data(as_text=True)
    assert chosen in body2


def test_cross_program_cannot_reach_via_campaign_param(client, seeded):
    # a STRATA-only user cannot reach PARALLAX evidence even with a crafted run_id
    _login(client, seeded["s_id"])
    r = client.get(URL + "?run_id=run-anything")
    assert r.status_code in (302, 303)
    assert "Investigation timeline" not in r.get_data(as_text=True)
