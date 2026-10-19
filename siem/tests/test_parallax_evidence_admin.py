"""Admin-only, read-only PARALLAX evidence-integrity verifier.

Covers authorization (only an authorized admin; candidate/anonymous denied; ownership never
bypassed for candidates), cryptographic correctness (valid record verifies; a DB-level tamper and
an in-memory negative control both fail), strict read-only behavior (the stored row is byte-for-byte
unchanged after verification; no model run), CSRF, rate limiting, and audit logging.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px-evidence-admin")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402

AJSON = {"Accept": "application/json"}


@pytest.fixture()
def ctx():
    import importlib
    # Scope auth/flag env to this fixture and restore on teardown so it never leaks into other
    # test modules in a combined run (ADMIN_TOKEN leaking would change admin-auth behavior elsewhere).
    saved = {k: os.environ.get(k) for k in
             ("ADMIN_TOKEN", "DISABLE_ADMIN_TOKEN", "RANGER_PARALLAX_LABA", "RANGER_PARALLAX_LABA_ENV")}
    os.environ["ADMIN_TOKEN"] = "admintoken"           # makes admin sign-in available
    os.environ.pop("DISABLE_ADMIN_TOKEN", None)
    os.environ["RANGER_PARALLAX_LABA"] = "1"
    os.environ["RANGER_PARALLAX_LABA_ENV"] = "test"
    import app as appmod
    importlib.reload(appmod)
    from models import db, Candidate, ProgramMembership
    application = appmod.create_app()
    appctx = application.app_context()
    appctx.push()
    db.create_all()
    # one PARALLAX researcher + one persisted, signed research run (stub backend => simulated)
    c = Candidate(handle="gh-res", name="R", email="r@e", cohort="2026-A", github_id="gh-res",
                  status="active", current_board=1)
    db.session.add(c); db.session.commit()
    db.session.add(ProgramMembership(candidate_id=c.id, program="parallax", status="active",
                                     cohort="2026-A")); db.session.commit()
    from parallax.research import store as rstore
    campaign = {"manifest": {"kind": "trial", "backend": {"is_real": False, "model_id": "stub-x",
                "runtime": "n/a", "backend": "deterministic_stub"}, "n_records": 1},
                "metrics": {"kind": "trial", "record": {"condition": "baseline_benign",
                "model": {"id": "stub-x"}, "observed_behavior": "hello world",
                "evaluation": {"canary": False, "task_ok": True}, "outcome": "boundary_preserved"}}}
    row = rstore.persist_run(db, researcher_id="gh-res", campaign=campaign)
    db.session.commit()
    yield application, db, row.run_id
    appctx.pop()
    for k, v in saved.items():                 # restore prior env so nothing leaks to other modules
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _admin(application):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear(); s["admin"] = True; s["admin_gid"] = "gh-admin"; s["csrf"] = "t"
    return cl


def _candidate(application, cid):
    cl = application.test_client()
    with cl.session_transaction() as s:
        s.clear(); s["cand"] = cid; s["csrf"] = "t"
    return cl


def _verify(cl, run_id, csrf="t"):
    headers = dict(AJSON)
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    return cl.post("/admin/evidence/verify", headers=headers,
                   data={"run_id": run_id, "csrf": (csrf or "")})


# ------------------------------- authorization -------------------------------

def test_anonymous_bad_token_denied_401(ctx):
    application, _db, rid = ctx
    cl = application.test_client()
    # header-token auth path bypasses CSRF and hits admin_required directly: a bad token => 401
    r = cl.post("/admin/evidence/verify",
                headers={"Accept": "application/json", "Authorization": "Bearer wrong"},
                data={"run_id": rid})
    assert r.status_code == 401


def test_anonymous_cookie_post_blocked(ctx):
    application, _db, rid = ctx
    cl = application.test_client()               # no session, no csrf
    r = cl.post("/admin/evidence/verify", headers=AJSON, data={"run_id": rid})
    assert r.status_code != 200                  # CSRF (400) stops it before the handler runs


def test_candidate_session_denied(ctx):
    application, _db, rid = ctx
    from models import Candidate
    cid = Candidate.query.filter_by(handle="gh-res").first().id
    r = _verify(_candidate(application, cid), rid)
    # a researcher/candidate session is not an admin: redirected to admin login (or 401), never run
    assert r.status_code in (301, 302, 303, 401)
    assert b"VERIFIED" not in r.data and b"\"result\"" not in r.data


def test_admin_allowed_and_verifies(ctx):
    application, _db, rid = ctx
    r = _verify(_admin(application), rid)
    assert r.status_code == 200
    res = r.get_json()["result"]
    assert res["exists"] and res["hash_match"] and res["signature_valid"]
    assert res["kid_trusted"] and res["signed_run_id_matches"]
    assert res["tamper_negative_control_fails"] is True
    assert res["all_checks_pass"] is True
    # simulated backend => not an empirical finding, but integrity still verifies
    assert res["is_empirical"] is False
    # sanitized: never leak signature/keys/full payload
    assert "signature" not in res and "run_record" not in res and "observed_behavior" not in res
    assert len(res.get("key_fingerprint16") or "") in (0, 16)


def test_get_page_renders_for_admin(ctx):
    application, _db, _rid = ctx
    r = _admin(application).get("/admin/evidence")
    assert r.status_code == 200
    body = r.data.decode()
    assert "Evidence integrity console" in body
    # uses the scoped full-width console wrapper, not the 460px global .card column
    assert "ev-wrap" in body and 'class="input mono"' in body


def test_result_page_has_responsive_console_layout(ctx):
    application, _db, rid = ctx
    # render the HTML result (not JSON) and confirm the console structure is present
    r = _admin(application).post("/admin/evidence/verify",
                                 headers={"X-CSRF-Token": "t"}, data={"run_id": rid, "csrf": "t"})
    assert r.status_code == 200
    body = r.data.decode()
    assert "ev-verdict" in body and "ev-grid" in body          # verdict banner + two-column grid
    assert "Cryptographic integrity" in body and "Research provenance" in body
    assert "ev-stat" in body                                   # per-check status chips
    assert "Public key fingerprint" in body and "Tampering negative control" in body
    # accessible status: text label present, not color alone
    assert ("PASS" in body or "FAIL" in body) and "VERIFIED" in body


def test_css_has_responsive_breakpoints_and_no_global_card_change():
    import io
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    css = io.open(os.path.join(root, "static", "app.css"), encoding="utf-8").read()
    # desktop two-column grid collapses on tablet/mobile
    assert ".ev-grid{" in css and "grid-template-columns:1fr 1fr" in css
    assert "@media(max-width:860px){.ev-grid{grid-template-columns:1fr}" in css
    assert "@media(max-width:560px)" in css
    # the scoped console card removes the narrow cap; the global login card stays 460px
    assert ".ev-card{" in css and "max-width:none" in css
    assert ".card{width:100%;max-width:460px;" in css


# ------------------------------- cryptographic -------------------------------

def test_unknown_run_id_reports_absent(ctx):
    application, _db, _rid = ctx
    res = _verify(_admin(application), "run-does-not-exist").get_json()["result"]
    assert res["exists"] is False


def test_db_level_tamper_fails_verification(ctx):
    application, db, rid = ctx
    from models import ParallaxResearchRun
    row = ParallaxResearchRun.query.filter_by(run_id=rid).first()
    rec = json.loads(row.run_record)
    rec["metrics"]["record"]["observed_behavior"] = "MALICIOUSLY ALTERED"
    row.run_record = json.dumps(rec)      # altered bytes, signature NOT regenerated
    db.session.commit()
    res = _verify(_admin(application), rid).get_json()["result"]
    assert res["signature_valid"] is False and res["all_checks_pass"] is False


def test_verification_is_read_only(ctx):
    application, db, rid = ctx
    from models import ParallaxResearchRun
    before = ParallaxResearchRun.query.filter_by(run_id=rid).first()
    snap = (before.run_record, before.signature, before.record_hash, before.signing_kid)
    _verify(_admin(application), rid)
    after = ParallaxResearchRun.query.filter_by(run_id=rid).first()
    assert (after.run_record, after.signature, after.record_hash, after.signing_kid) == snap


# ------------------------------- CSRF, rate limit, audit -------------------------------

def test_csrf_required(ctx):
    application, _db, rid = ctx
    cl = _admin(application)
    # cookie-authed admin POST without a CSRF token is rejected
    r = cl.post("/admin/evidence/verify", headers=AJSON, data={"run_id": rid})
    assert r.status_code == 400


def test_audit_event_appended(ctx):
    application, _db, rid = ctx
    _verify(_admin(application), rid)
    from models import ParallaxAuditEvent
    assert ParallaxAuditEvent.query.filter_by(action="research_evidence_verified",
                                              subject_ref=rid).count() >= 1


def test_rate_limited(ctx):
    application, _db, rid = ctx
    cl = _admin(application)
    saw_429 = False
    for _ in range(62):                      # limit is 60/60s per IP
        if _verify(cl, rid).status_code == 429:
            saw_429 = True
            break
    assert saw_429
