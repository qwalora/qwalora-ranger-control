"""STRATA S6 section 17 - flag-placement account pinning. The qwalora_flags role must lock each
flag's ACL to the SAME account the approved scenario names, never the role's fixed defaults, and must
be told the correct board placement map. The portal now passes that pinned config via templateVars.
Offline tests (the role itself needs a Windows range); here we prove the portal supplies the right
pinned config and the provisioner hands it to the broker.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("LUDUS_API_URL", None)

import scenarios as sc  # noqa: E402
import broker  # noqa: E402


def test_placement_vars_pin_scenario_accounts_board5():
    # For every seed, the pinned svc/asrep match what generate_board5 actually chose (so the ACL lock
    # can never reference a different account than the scenario names).
    for seed in ("s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"):
        t = sc.generate_board5(seed)["targets"]
        pv = sc.placement_vars(5, seed)
        assert pv["qwalora_flags_board"] == 5
        assert pv["qwalora_svc_account"] == t["kerberoast_account"]
        assert pv["qwalora_asrep_account"] == t["asrep_user"]
        assert pv["qwalora_domain"] == "sevenkingdoms.local"
        assert "kingslanding" in pv["qwalora_dc_hostnames"]


def test_placement_vars_prove_the_fix_matters():
    # At least one seed must choose a service account OTHER than the role's old fixed default
    # ('sql_svc'); for that seed the pinned value must follow the scenario, not the default.
    seeds = [f"seed-{i}" for i in range(40)]
    svc_values = {sc.placement_vars(5, s)["qwalora_svc_account"] for s in seeds}
    asrep_values = {sc.placement_vars(5, s)["qwalora_asrep_account"] for s in seeds}
    assert svc_values - {"sql_svc"}, "no seed selected a non-default svc account; fix would be moot"
    assert asrep_values - {"brandon.stark"}, "no seed selected a non-default AS-REP user"
    # and every value is a legitimate account from the scenario pool
    assert svc_values <= set(sc._B5_SVC_ACCTS)
    assert asrep_values <= set(sc._B5_ASREP_USERS)


def test_placement_vars_board6_sets_board_and_none_for_non_flag_boards():
    pv6 = sc.placement_vars(6, "x")
    assert pv6["qwalora_flags_board"] == 6 and pv6["qwalora_domain"] == "sevenkingdoms.local"
    for n in (1, 2, 3, 4):
        assert sc.placement_vars(n, "x") is None


def test_provisioner_hands_pinned_accounts_to_broker():
    """Driving the real /labs/start route, the broker's set_range_config must receive the per-seed
    flags AND the pinned placement accounts for the candidate's board-5 scenario."""
    import app as appmod
    from models import db, Cohort, Candidate
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    captured = {}
    saved = broker.set_range_config
    broker.set_range_config = lambda c, template=None, user_key=None, template_vars=None: (
        captured.update({"template": template, "vars": template_vars}) or (True, "mock captured"))
    try:
        db.create_all()
        if not Cohort.query.filter_by(name="2026-A").first():
            db.session.add(Cohort(name="2026-A", pathway="strata", status="active")); db.session.commit()
        c = Candidate(handle="fp", name="fp", email="fp@e", cohort="2026-A", github_id="g-fp",
                      status="active", current_board=5, token="tok-fp")
        db.session.add(c); db.session.commit()
        client = application.test_client()
        hdr = {"X-Candidate-Token": c.token}
        # assign the seed
        assert client.post("/labs/dataset", json={"handle": c.handle}, headers=hdr).status_code == 200
        from models import ScenarioAssignment
        seed = (ScenarioAssignment.query.filter_by(github_id="g-fp", board=5).first()).seed
        exp = sc.generate_board5(seed)["targets"]
        # start the lab -> provisioner builds templateVars and calls broker.set_range_config
        r = client.post("/labs/start", json={"handle": c.handle}, headers=hdr)
        assert r.status_code == 200, r.data
        v = captured.get("vars") or {}
        assert "ranger_flags" in v and v["ranger_flags"], "per-seed flags must be handed to the range"
        assert v.get("qwalora_flags_board") == 5
        assert v.get("qwalora_svc_account") == exp["kerberoast_account"]
        assert v.get("qwalora_asrep_account") == exp["asrep_user"]
    finally:
        broker.set_range_config = saved
        ctx.pop()
