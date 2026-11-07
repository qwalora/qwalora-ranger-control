"""Unified SOC console for the answer-free triage boards (1/3/4, soc-dataset).

Proves that /soc/launch for a soc-dataset board loads THIS candidate's own scenario (the same
seed the triage worksheet grades) into their own private per-candidate index on the shared
OpenSearch, tagged for DLS, and reachable only through the candidate's scoped role. Uses the
in-process FakeCluster double, like the Board 2 gateway test, so no live cluster is required.
"""
import base64
import json as _json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from siem.fake_cluster import FakeCluster  # noqa: E402


def _rsa_pem():
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption())


def test_soc_dataset_launch_loads_private_candidate_index():
    import soc_gateway as _soc
    import scenarios
    from siem import authz
    cluster = FakeCluster()
    flags = {"RANGER_SOC_TEST_KEY": "soc-test-key",
             "RANGER_JWT_PRIVATE_B64": base64.b64encode(_rsa_pem()).decode(),
             "OPENSEARCH_ADMIN_PASSWORD": "x"}
    saved = {k: os.environ.get(k) for k in flags}
    os.environ.update(flags)
    import app as appmod
    from models import db, Candidate, Cohort
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    _soc.set_cluster_factory(lambda: cluster)
    try:
        db.create_all()
        if not Cohort.query.filter_by(name="2026-A").first():
            db.session.add(Cohort(name="2026-A", pathway="strata", status="active"))
            db.session.commit()
        client = application.test_client()

        def _launch(handle, gid):
            c = Candidate.query.filter_by(handle=handle).first()
            if c is None:
                c = Candidate(handle=handle, name=handle, email=handle + "@e", token="tok-" + handle)
                db.session.add(c)
            c.cohort = "2026-A"; c.github_id = gid; c.status = "active"; c.current_board = 1
            db.session.commit()
            r = client.get(f"/soc-test/login?key=soc-test-key&cand={handle}", follow_redirects=False)
            assert r.status_code in (301, 302)
            # test-login forces the SIEM board; this is a soc-dataset board candidate.
            c = Candidate.query.filter_by(handle=handle).first()
            c.current_board = 1; c.cohort = "2026-A"; db.session.commit()
            r = client.get("/soc/launch", follow_redirects=False)
            assert r.status_code in (301, 302), r.data
            return c

        a = _launch("soc-a", "test-soc-a")
        slug_a = authz._slug(a.github_id)
        idx_a = authz.index_name("2026-A", slug_a, 1)

        # 1. the candidate's own board-1 index exists and holds their scenario alerts
        assert cluster.index_exists(idx_a)
        n = cluster.count(idx_a)
        assert n == len(scenarios.dataset(1, _current_seed(application, a)).get("alerts", [])) > 0

        # 2. every doc is DLS-tagged to this candidate, with a usable @timestamp
        docs = cluster.search(idx_a)
        assert docs and all(d["ranger"]["candidate_id"] == slug_a for d in docs)
        assert all(d.get("@timestamp") for d in docs)

        # 3. the console shows the SAME alerts the triage worksheet grades (same seed)
        graded = scenarios.dataset(1, _current_seed(application, a))
        assert {d["id"] for d in docs} == {al["id"] for al in graded["alerts"]}

        # 4. the candidate reads their own index through their scoped role
        cand_user = authz.user_name(slug_a)
        assert cluster.count(idx_a, auth=(cand_user, "pw")) == n

        # 5. isolation: a second candidate cannot read the first candidate's index
        b = _launch("soc-b", "test-soc-b")
        slug_b = authz._slug(b.github_id)
        idx_b = authz.index_name("2026-A", slug_b, 1)
        assert cluster.index_exists(idx_b)
        user_b = authz.user_name(slug_b)
        from siem.live import AuthzError
        raised = False
        try:
            cluster.count(idx_a, auth=(user_b, "pw"))
        except AuthzError:
            raised = True
        assert raised, "candidate B must not read candidate A's SOC index"
    finally:
        _soc.set_cluster_factory(None)
        ctx.pop()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _current_seed(application, cand):
    """Resolve the candidate's board-1 seed the same way the portal does (the seed ledger is keyed
    by github_id/board/cohort), so the test can regenerate the exact graded dataset."""
    from models import ScenarioAssignment
    gid = cand.github_id or cand.handle
    row = (ScenarioAssignment.query
           .filter_by(github_id=gid, board=1, cohort=cand.cohort)
           .order_by(ScenarioAssignment.id.desc()).first())
    assert row is not None, "launch should have ensured a seed"
    return row.seed
