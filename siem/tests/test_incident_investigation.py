"""STRATA Board-1 ADVANCED: multi-step incident investigation. Entitlement + ownership scoped,
answer-free, server-side graded, SIGNED and NON-GATING (does not touch Board-1 objective scoring or
the 95% qualification gate). Exercises the real WSGI round-trip.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "incident-ws-test")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

_JSON = {"Accept": "application/json"}
_POST = {"Accept": "application/json", "X-CSRF-Token": "t"}
_ENV_KEYS = ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV", "RANGER_STRATA_PORTFOLIOS")


@pytest.fixture()
def ctx():
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    for k in _ENV_KEYS:
        os.environ.pop(k, None)
    import importlib
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, Cohort, ProgramMembership
    application = appmod.create_app()
    c = application.app_context(); c.push()
    db.drop_all(); db.create_all()
    db.session.add(Cohort(name="2026-A", sequence=1, status="active", pathway="strata")); db.session.commit()

    def mk(h, board=1):
        x = Candidate(handle=h, name=h, email=h + "@e", cohort="2026-A", github_id=h,
                      status="active", current_board=board, token="t-" + h)
        db.session.add(x); db.session.commit(); return x

    def mem(x, p, s):
        db.session.add(ProgramMembership(candidate_id=x.id, program=p, status=s, cohort="2026-A")); db.session.commit()

    p = {}
    p["strata"] = mk("i_strata"); mem(p["strata"], "strata", "active")
    p["strata2"] = mk("i_strata2"); mem(p["strata2"], "strata", "active")
    p["px"] = mk("i_px"); mem(p["px"], "parallax", "active")
    p["susp"] = mk("i_susp"); mem(p["susp"], "strata", "suspended")
    yield application, db, p
    c.pop()
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _sess(application, cid):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear(); s["cand"] = cid; s["csrf"] = "t"
    return cl


def _seed_of(c):
    from models import ScenarioAssignment
    a = (ScenarioAssignment.query.filter_by(github_id=c.github_id, board=1, cohort=c.cohort)
         .order_by(ScenarioAssignment.id.desc()).first())
    return a.seed if a else None


def _ideal(seed):
    from siem import incident_investigation as II
    sc = II.generate_incident(seed)
    out = []
    for k in sc["_incidents"]:
        out.append({"alert_ids": list(k["alert_ids"]), "entry_alert_id": k["entry_alert_id"],
                    "technique_chain": list(k["technique_chain"]),
                    "affected_hosts": list(k["affected_hosts"]),
                    "affected_accounts": list(k["affected_accounts"]),
                    "evidence": [k["actor_account"]] + list(k["affected_hosts"])})
    return {"incidents": out}


def test_incident_page_entitlement(ctx):
    application, db, p = ctx
    assert _sess(application, p["strata"].id).get("/me/workspace/incident").status_code == 200
    # parallax-only and suspended STRATA cannot reach it
    assert _sess(application, p["px"].id).get("/me/workspace/incident").status_code in (302, 403)
    assert _sess(application, p["susp"].id).get("/me/workspace/incident").status_code in (302, 403)
    # unauthenticated
    assert application.test_client().get("/me/workspace/incident").status_code in (301, 302, 401)


def test_incident_data_is_answer_free(ctx):
    application, db, p = ctx
    r = _sess(application, p["strata"].id).get("/me/workspace/incident/data", headers=_JSON)
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] and body["alerts"]
    allowed = {"id", "timestamp", "host", "signal", "raw"}
    for a in body["alerts"]:
        assert set(a.keys()) <= allowed, "dataset leaks fields: %s" % set(a.keys())
    blob = r.get_data(as_text=True).lower()
    # no answer key / grouping / actor labels leak
    assert "_key" not in blob and "_incident" not in blob
    assert "actor_account" not in blob and "actor_src" not in blob and "technique_chain" not in blob
    assert "true_positive" not in blob and "verdict" not in blob


def test_incident_data_entitlement(ctx):
    application, db, p = ctx
    assert _sess(application, p["px"].id).get("/me/workspace/incident/data", headers=_JSON).status_code in (302, 403)
    assert _sess(application, p["susp"].id).get("/me/workspace/incident/data", headers=_JSON).status_code in (302, 403, 409)


def test_grading_rewards_correlation_and_penalizes_lumping(ctx):
    application, db, p = ctx
    cl = _sess(application, p["strata"].id)
    cl.get("/me/workspace/incident/data", headers=_JSON)   # assigns the seed
    c = p["strata"]
    seed = _seed_of(c)
    assert seed
    # ideal, key-derived submission scores high
    r = cl.post("/me/workspace/incident/submit", headers=_POST, json={"submission": _ideal(seed)})
    assert r.status_code == 200
    good = r.get_json()
    assert good["ok"] and good["score"] >= 80.0
    # per-incident flags are correctness flags only (no key values)
    for pi in good["per_incident"]:
        assert set(pi.keys()) <= {"incident", "matched", "grouping_ok", "entry_ok", "chain_ok", "evidence_ok"}
    # one-giant-incident (lump every alert together) scores poorly
    from siem import incident_investigation as II
    sc = II.generate_incident(seed)
    allids = [a["id"] for a in sc["alerts"]]
    giant = {"incidents": [{"alert_ids": allids, "entry_alert_id": allids[0],
                            "technique_chain": ["T1078"], "affected_hosts": ["x"],
                            "affected_accounts": ["y"], "evidence": ["guess"]}]}
    r2 = cl.post("/me/workspace/incident/submit", headers=_POST, json={"submission": giant})
    assert r2.status_code == 200
    assert r2.get_json()["score"] < good["score"] - 30


def test_signed_record_persisted_and_gate_untouched(ctx):
    application, db, p = ctx
    from models import IncidentAssessment, BoardResult
    c = p["strata"]
    cl = _sess(application, c.id)
    cl.get("/me/workspace/incident/data", headers=_JSON)
    seed = _seed_of(c)
    cl.post("/me/workspace/incident/submit", headers=_POST, json={"submission": _ideal(seed)})
    row = IncidentAssessment.query.filter_by(candidate_id=c.id, board=1).first()
    assert row is not None and row.signature and row.signing_kid and row.record_hash
    assert row.attempts >= 1
    # the 95% gate is untouched: incident submit creates no Board-1 objective result and no promotion
    assert BoardResult.query.filter_by(candidate_id=c.id).count() == 0
    db.session.refresh(c)
    assert c.current_board == 1   # not promoted by the incident assessment


def test_csrf_required_on_submit(ctx):
    application, db, p = ctx
    cl = _sess(application, p["strata"].id)
    cl.get("/me/workspace/incident/data", headers=_JSON)
    # POST without the CSRF header is rejected
    r = cl.post("/me/workspace/incident/submit", headers={"Accept": "application/json"},
                json={"submission": {"incidents": []}})
    assert r.status_code in (400, 403)


def test_ownership_two_candidates_get_distinct_fields(ctx):
    application, db, p = ctx
    a = _sess(application, p["strata"].id).get("/me/workspace/incident/data", headers=_JSON).get_json()
    b = _sess(application, p["strata2"].id).get("/me/workspace/incident/data", headers=_JSON).get_json()
    # different seeds -> different alert id/content fields; no client-supplied handle/seed is honored
    assert [x["raw"] for x in a["alerts"]] != [x["raw"] for x in b["alerts"]]
