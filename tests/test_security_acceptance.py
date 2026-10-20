"""Security acceptance negative tests (design-completion mandate section 11).

Complements test_parallax_ui.py (unauth, cross-program, cross-owner, reviewer-only) and
test_research_execution.py (host-authorization, provenance). Adds CSRF, malformed ids,
invalid/missing signatures, and model-backend failure surfacing.
"""
import json
import re

import pytest

from conftest import login


def _csrf(client):
    page = client.get("/parallax/workspace").get_data(as_text=True)
    m = re.search(r"var CSRF\s*=\s*(\"[^\"]*\")", page)
    return json.loads(m.group(1)) if m else ""


def test_csrf_required_on_trial_post(client, seeded):
    login(client, seeded["a_id"])
    # no CSRF header -> rejected (400) before the view executes
    r = client.post("/parallax/research/trial", json={"task_id": "t-storage"})
    assert r.status_code == 400
    # with a valid CSRF token the request is accepted by CSRF (may then 400/502 on content/backend,
    # but NOT a CSRF rejection) - proves the protection is real, not blanket-blocking
    r2 = client.post("/parallax/research/trial", json={"task_id": "t-storage"},
                     headers={"X-CSRF-Token": _csrf(client)})
    assert r2.status_code != 400 or b"CSRF" not in r2.data


def test_malformed_record_id_export_is_404(client, seeded):
    login(client, seeded["a_id"])
    for bad in ["not-a-real-id", "run-%2e%2e%2f", "run-'; DROP TABLE x;--"]:
        r = client.get("/parallax/research/evidence/%s.json" % bad)
        assert r.status_code == 404  # never leaks existence; never errors out


def test_invalid_signature_is_not_infrastructure_backed(seeded):
    """A real-model run whose stored signature is tampered must report signature_verifies=False and
    must NOT be classified infrastructure-backed / empirical."""
    import app as A
    from models import db, ParallaxResearchRun
    from parallax.research import store as rstore
    rid = "sig-researcher"
    camp = {"manifest": {"kind": "trial",
                         "backend": {"is_real": True, "model_id": "cap-model", "runtime": "http",
                                     "backend": "http"}, "n_records": 1},
            "metrics": {"kind": "trial", "record": {"outcome": "boundary_preserved",
                        "condition": "baseline_benign", "evaluation": {"canary": False}}}}
    with A.app.app_context():
        row = rstore.persist_run(db, researcher_id=rid, campaign=camp)
        run_id = row.run_id
        r = ParallaxResearchRun.query.filter_by(run_id=run_id).first()
        r.signature = (r.signature or "")[:-4] + "AAAA"   # tamper the stored signature
        db.session.commit()
        items = rstore.overview_for(db, authenticated_researcher_id=rid)
    bad = [i for i in items if i["run_id"] == run_id][0]
    assert bad["signature_verifies"] is False
    assert bad["infrastructure_backed"] is False
    assert bad["is_empirical_finding"] is False


def test_model_backend_failure_is_surfaced_not_faked():
    """A dead model endpoint must produce an infrastructure_failure outcome, never a fabricated output."""
    from parallax.research import model_backend as mb, harness, corpus as corpus_mod, protocol as P
    be = mb.HTTPBackend("http://127.0.0.1:1", model_id="dead")  # closed loopback port
    rec = harness.run_trial(be, corpus_mod.default_corpus(),
                            task={"task_id": "t", "task": "answer", "expected_contains": ["x"]},
                            variant=None, condition=P.CONDITION_BASELINE, repetition=1)
    assert rec["observed_behavior"] is None            # no fabricated output
    assert rec["infra_error"] and "model_backend_error" in rec["infra_error"]
    assert rec["outcome"] in ("infrastructure_failure", "evaluation_error")
