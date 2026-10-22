"""Release-readiness acceptance: STRATA and PARALLAX end-to-end journeys + isolation (test client).

Authenticated journeys against the real routes with real session cookies and seeded principals. These
are backend acceptance checks (no live model backend is reachable from the test environment; the live
model trial is verified only on the deployed service and is NOT simulated here).
"""
import app as A
from models import db, Candidate, ProgramMembership
from parallax.research import store as rstore
from parallax.research import evidence_verifier as _EV


def _login(client, cid):
    with client.session_transaction() as sess:
        sess["cand"] = cid


# --------------------------------------------------------------- STRATA user journey (section 4)

def test_strata_journey_signin_nav_mission_workspace_dataset(client, seeded):
    _login(client, seeded["s_id"])                 # approved STRATA-only user
    # 2. sees STRATA program + authorized navigation
    home = client.get("/me")
    assert home.status_code == 200
    body = home.get_data(as_text=True)
    assert "SOC workspace" in body or "Mission brief" in body
    assert "Research console" not in body          # no PARALLAX nav
    # 3. mission instructions load
    assert client.get("/me/mission").status_code == 200
    # 4. SOC workspace opens
    assert client.get("/me/workspace").status_code == 200
    # 5. assigned alert dataset loads (own, answer-free)
    data = client.get("/me/workspace/data", headers={"Accept": "application/json"})
    assert data.status_code == 200
    # 9. cannot access PARALLAX via STRATA membership
    for url in ("/parallax/research/investigations", "/parallax/research/traces", "/parallax/workspace"):
        assert client.get(url).status_code in (302, 303)


# --------------------------------------------------------------- PARALLAX user journey (section 5)

def test_parallax_journey_console_investigation_trace_evidence(client, seeded):
    # persist a real signed trial so investigation/trace have content
    rec = {"outcome": "successful_unauthorized_behavior", "condition": "experimental_attack",
           "attempts_injection": True, "observed_behavior": "Certainly: INJECTION-OK",
           "adversarial_input_id": "a-direct", "retrieved_doc_ids": ["doc-1"],
           "legitimate_task": "What file formats are supported?", "legitimate_task_id": "t1",
           "evaluation": {"canary": True}, "model": {"id": "val-model"}, "timing": {"started": 1000.0}}
    rec["evidence_hash"] = _EV._recompute_evidence_hash(rec)
    camp = {"manifest": {"kind": "trial", "backend": {"is_real": True, "model_id": "val-model"}, "n_records": 1},
            "metrics": {"kind": "trial", "record": rec}}
    with A.app.app_context():
        run_id = rstore.persist_run(db, researcher_id="rb-researcher", campaign=camp).run_id
    _login(client, seeded["b_id"])                 # approved PARALLAX researcher
    # 2. Research Console opens in the Ranger shell
    console = client.get("/parallax/workspace")
    assert console.status_code == 200 and "AI Security Research" in console.get_data(as_text=True)
    # 9/10. investigation opens; campaign/timeline/findings/verification render
    inv = client.get("/parallax/research/investigations")
    assert inv.status_code == 200
    ib = inv.get_data(as_text=True)
    assert "Investigation timeline" in ib and "Evidence verification (server-side" in ib
    # 11. Trace Explorer loads actual recorded events
    tr = client.get("/parallax/research/traces")
    assert tr.status_code == 200
    tb = tr.get_data(as_text=True)
    assert "Trace Explorer" in tb and "model_generated" in tb and "canary_emission" in tb
    # 8. signed evidence persisted + retrievable, verifies
    with A.app.app_context():
        full = rstore.get_run(db, run_id=run_id, authenticated_researcher_id="rb-researcher")
    assert full is not None and full.get("signature_verifies") is True
    # 14. cannot access STRATA via PARALLAX membership
    assert client.get("/me/workspace").status_code in (302, 303)


# --------------------------------------------------------------- isolation / revocation (section 8)

def test_revoked_parallax_membership_denies_next_request(client, seeded):
    _login(client, seeded["b_id"])
    assert client.get("/parallax/research/traces").status_code == 200
    with A.app.app_context():
        pm = ProgramMembership.query.filter_by(candidate_id=seeded["b_id"], program="parallax").first()
        prev = pm.status; pm.status = "revoked"; db.session.commit()
    try:
        assert client.get("/parallax/research/traces").status_code in (302, 303)   # re-checked each request
    finally:
        with A.app.app_context():
            pm = ProgramMembership.query.filter_by(candidate_id=seeded["b_id"], program="parallax").first()
            pm.status = prev; db.session.commit()


def test_live_model_backend_not_simulated_locally(client, seeded):
    # The local test backend is a stub (is_real False); it must be labelled simulated, never presented
    # as a live model run. This asserts the honesty invariant the release depends on.
    from parallax.research import model_backend as mb
    ident = mb.from_config().identity()
    assert ident["is_real"] is False          # local/default backend is a stub
    # the Research Console surfaces backend provenance truthfully
    _login(client, seeded["b_id"])
    body = client.get("/parallax/workspace").get_data(as_text=True)
    assert "simulated" in body                # provenance shown as simulated, not a live claim
