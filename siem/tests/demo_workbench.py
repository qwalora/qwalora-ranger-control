"""F5 - end-to-end Candidate Workbench demonstration (development only).

Walks the full authorized flow with a SYNTHETIC candidate and a SYNTHETIC PARALLAX test case, using
the real app, models, evidence contracts and signing. Prints a step-by-step transcript and renders
screenshots of the real rendered pages (via the Flask test client + Playwright/Chromium). No
production access, no PARALLAX qualification activation, no Lab A/B.
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "wb-demo")
os.environ.setdefault("DEFAULT_COHORT", "2026-P")
os.environ["RANGER_EVIDENCE_DIR"] = os.path.join(ROOT, "instance", "wb_demo_evidence")
for f in ("RANGER_WORKBENCH", "RANGER_WORKBENCH_CASE_ACCESS", "RANGER_WORKBENCH_EVIDENCE_SUBMIT",
          "RANGER_WORKBENCH_ASSESSMENT_VISIBILITY"):
    os.environ[f] = "1"
os.environ.pop("RANGER_PARALLAX_QUALIFICATION_ACTIVE", None)   # qualification stays INACTIVE
import json as _json
os.environ["RANGER_WB_REVIEWERS"] = _json.dumps({"rev-demo": {"cohorts": ["2026-P"], "pathway": "parallax"}})

import workbench_core as wc  # noqa: E402

AGENT_TRACE = _json.dumps({"schema": "ranger-agent-trace/1", "events": [
    {"type": "model_request", "ts": "2026-02-01T10:00:00Z"},
    {"type": "api_authorization", "ts": "2026-02-01T10:00:02Z", "principal": "agent-7",
     "resource": "s3://prod-secrets", "decision": "deny"},
    {"type": "data_access", "ts": "2026-02-01T10:00:03Z", "boundary": "tenant-A->tenant-B",
     "crossed": True}]}).encode()

SHOTS = []


def _login(client, cand_id=None, admin=None, admin_login=None):
    with client.session_transaction() as s:
        s.clear()
        if cand_id is not None:
            s["cand"] = cand_id
        if admin:
            s["admin"] = True; s["admin_login"] = admin_login or "rev-demo"
        s["csrf"] = "t"


def _shot(client, path, name, width=1320, height=1000):
    """Render a real page and screenshot it with Playwright (CSS inlined; fonts fall back)."""
    r = client.get(path)
    html = r.data.decode("utf-8", "replace")
    # inline BOTH stylesheets (app.css + workbench.css) so file:// rendering is faithful; the live
    # app serves both via /static, this is only for the offline screenshot.
    app_css = open(os.path.join(ROOT, "static", "app.css")).read()
    wb_css = open(os.path.join(ROOT, "static", "workbench.css")).read()
    html = re.sub(r'<link[^>]*app\.css[^>]*>', f"<style>{app_css}</style>", html)
    html = re.sub(r'<link[^>]*workbench\.css[^>]*>', f"<style>{wb_css}</style>", html)
    out_html = os.path.join(os.environ["RANGER_EVIDENCE_DIR"], name + ".html")
    os.makedirs(os.path.dirname(out_html), exist_ok=True)
    open(out_html, "w").write(html)
    png = os.path.join(ROOT, "_preview", "workbench_" + name + ".png")
    os.makedirs(os.path.dirname(png), exist_ok=True)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            b = pw.chromium.launch()
            pg = b.new_page(viewport={"width": width, "height": height}, device_scale_factor=2)
            pg.goto("file://" + out_html)
            pg.wait_for_timeout(250)
            pg.screenshot(path=png, full_page=True)
            b.close()
        SHOTS.append(png)
        return png
    except Exception as e:  # noqa
        print(f"   (screenshot skipped for {name}: {type(e).__name__}: {e})")
        return None


def run():
    import app as appmod
    from models import db, Candidate, Cohort, Case
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.create_all()
    print("=== F5 Candidate Workbench - end-to-end demonstration (development) ===\n")

    co = Cohort.query.filter_by(name="2026-P").first()
    if not co:
        db.session.add(Cohort(name="2026-P", pathway="parallax", status="active"))
    else:
        co.pathway = "parallax"
    if not Cohort.query.filter_by(name="2026-S").first():
        db.session.add(Cohort(name="2026-S", pathway="strata", status="active"))
    db.session.commit()

    # a synthetic candidate begins as an applicant (pending), plus an unrelated STRATA candidate
    cand = Candidate(handle="demo-ranger", name="Demo Ranger", email="demo@e", cohort="2026-P",
                     github_id="gid-demo", status="pending", current_board=1)
    strata = Candidate(handle="demo-strata", name="Other", email="o@e", cohort="2026-S",
                       github_id="gid-strata", status="active", current_board=2)
    applicant = Candidate(handle="demo-appl", name="Applicant", email="ap@e", cohort="2026-P",
                          github_id="gid-appl", status="pending", current_board=1)
    db.session.add_all([cand, strata, applicant]); db.session.commit()
    client = application.test_client()

    # 1. administrator approves the synthetic candidate (pending -> active)
    cand.status = "active"; db.session.commit()
    print(f"1. Admin approved candidate @{cand.handle}: status -> {cand.status}")

    # a synthetic PARALLAX test case is assigned (+ one piece of authorized evidence to review)
    case = Case(candidate_id=cand.id, board=1, cohort="2026-P", plane="qualification",
                workflow="qualification", seed="HIDDEN_TRUTH_SEED", scenario_version=1,
                index_name="wb-demo", status="assigned", scenario_ref="parallax-agent-authz")
    db.session.add(case); db.session.commit()
    store = wc.evidence_store()
    provided = wc.submit_evidence(db, store, case, cand, "parallax", io.BytesIO(AGENT_TRACE),
                                  evidence_type="agent_trace", source_identity="authorized-material")
    print(f"   Assigned PARALLAX case #{case.id}; provided evidence {provided['evidence_id']} to review")

    # 2. candidate authenticates
    _login(client, cand.id)
    r = client.get("/workbench")
    print(f"2. Candidate authenticated; GET /workbench -> {r.status_code}")

    # 3. candidate sees ONLY the assigned PARALLAX case
    seen = client.get("/workbench").data
    print(f"3. Overview shows pathway PARALLAX={b'PARALLAX' in seen}, assigned Case #{case.id}="
          f"{str(case.id).encode() in seen}")
    _shot(client, "/workbench", "overview")

    # 4. candidate reviews permitted evidence (their scoped workspace)
    ws = client.get(f"/workbench/case/{case.id}")
    print(f"4. Workspace GET -> {ws.status_code}; shows provided evidence="
          f"{provided['evidence_id'].encode() in ws.data}")

    # 5. candidate records a technical finding
    client.post(f"/workbench/case/{case.id}/draft", data={
        "csrf": "t", "action": "add_finding",
        "claim": "The agent was denied access to prod secrets and crossed a tenant boundary",
        "significance": "A cross-tenant data-access boundary crossing is recorded in the trace",
        "methodology": "Parsed the authorized agent trace; cited the deny + crossed events",
        "observed_outcome": "api_authorization=deny; data_access crossed=true",
        "limitations": "Observation of the trace as submitted; not an authoritative finding",
        "finding_evidence_refs": provided["evidence_id"]})
    print("5. Candidate recorded a technical finding (claim + methodology + significance + limits)")

    # 6. candidate attaches typed evidence (uploads their own agent trace)
    up = client.post(f"/workbench/case/{case.id}/evidence", data={
        "evidence_type": "agent_trace", "csrf": "t",
        "file": (io.BytesIO(AGENT_TRACE), "my_trace.json")}, content_type="multipart/form-data")
    from models import EvidenceArtifact
    evs = EvidenceArtifact.query.filter_by(candidate_id=cand.id, case_id=case.id).all()
    print(f"6. Candidate attached typed evidence -> {up.status_code}; evidence items now={len(evs)} "
          f"(all needs_review/unscanned={all(e.validation_state=='needs_review' and e.scan_state=='unscanned' for e in evs)})")

    # reference both evidence items in the package, then submit
    refs = [e.evidence_id for e in evs]
    client.post(f"/workbench/case/{case.id}/draft", data={
        "csrf": "t", "action": "save",
        "approach": "Trace-based characterization of agent authorization + data access",
        "evidence_refs": refs})
    _shot(client, f"/workbench/case/{case.id}", "case")
    _shot(client, f"/workbench/case/{case.id}", "case_mobile", width=390, height=1600)

    # 7-8. candidate submits the package; Ranger records an immutable signed receipt
    pathway = wc.resolve_pathway(db, cand)
    sub, receipt = wc.finalize_submission(db, store, Case.query.get(case.id), cand, pathway)
    print(f"7. Candidate submitted the investigation package -> submission_status={sub.submission_status}")
    print(f"8. Immutable signed receipt recorded: hash={receipt['record']['receipt_hash'][:16]}... "
          f"verifies={wc.verify_receipt(sub)}")

    # 9. an authorized reviewer (scoped to 2026-P) inspects the package
    _login(client, admin=True, admin_login="rev-demo")
    det = client.get(f"/workbench/review/submission/{sub.id}")
    print(f"9. In-scope reviewer inspected submission #{sub.id} -> {det.status_code}")
    _shot(client, f"/workbench/review/submission/{sub.id}", "review")

    # 10. candidate sees the permitted submission status
    _login(client, cand.id)
    stv = wc.assessment_status_view(Case.query.get(case.id), sub, pathway)
    print(f"10. Candidate-visible status: state={stv['state']}")

    # 11. protected truth remains inaccessible
    page = client.get(f"/workbench/case/{case.id}").data
    print(f"11. Hidden truth inaccessible: 'HIDDEN_TRUTH_SEED' in any candidate view={b'HIDDEN_TRUTH_SEED' in page}")

    # 12. PARALLAX qualification remains inactive
    print(f"12. PARALLAX qualification active={stv.get('qualification_active')}, qualified={stv.get('qualified')}")

    # negative: unapproved applicant and unrelated STRATA candidate cannot access the case
    _login(client, applicant.id)
    a1 = client.get("/workbench").status_code
    a2 = client.get(f"/workbench/case/{case.id}").status_code
    _login(client, strata.id)
    s1 = client.get(f"/workbench/case/{case.id}").status_code
    print(f"\nNegative controls: unapproved applicant /workbench={a1} (403), case={a2} (403); "
          f"unrelated STRATA candidate case={s1} (404)")

    ctx.pop()
    print("\nScreenshots:")
    for p in SHOTS:
        print("  " + p)
    ok = (r.status_code == 200 and sub.submission_status == "submitted" and wc.verify_receipt(sub)
          and b"HIDDEN_TRUTH_SEED" not in page and stv.get("qualified") is False
          and a1 == 403 and a2 == 403 and s1 == 404)
    print("\nDEMO " + ("OK" if ok else "FAILED"))
    return ok


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
