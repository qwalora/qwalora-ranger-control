"""STRATA S6 section 14 (part 1) - board 5/6 scenario families are MATERIALLY diverse and the
variant-aware generators preserve the legacy seed-only behaviour. Governance plumbing (catalog/spec/
assignment/app wiring + two-cohort integration) lands in part 2; this proves the families and
generators are sound first.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "s6fam")

import scenarios as sc  # noqa: E402
from siem import board_variants as bv  # noqa: E402


def _divergent_axes(a, b):
    keys = set(a) | set(b)
    n = 0
    for k in keys:
        av, bv_ = a.get(k), b.get(k)
        if isinstance(av, list) or isinstance(bv_, list):
            if sorted(av or []) != sorted(bv_ or []):
                n += 1
        elif av != bv_:
            n += 1
    return n


def test_board5_legacy_seed_only_unchanged():
    # gp=None must reproduce and grade exactly as before (backward compatibility).
    s = sc.generate_board5("legacy-x")
    assert s == sc.generate_board5("legacy-x")
    assert "_flags" not in sc.public_board5(s) and "_flags" not in str(sc.public_board5(s))
    full, _ = sc.score_board5(s, {"flags": dict(s["_flags"])})
    empty, _ = sc.score_board5(s, {"flags": {}})
    assert full == 100.0 and empty < 95.0
    assert s["targets"]["escalation_edge"] is None   # no family -> generic world


def test_board5_families_are_materially_diverse():
    fams = bv.variants_for(5)
    assert len(fams) >= 3
    # pairwise declared-axis divergence >= 2 (the governance rule)
    for i in range(len(fams)):
        for j in range(i + 1, len(fams)):
            d = _divergent_axes(bv.diversity_axes(5, fams[i]), bv.diversity_axes(5, fams[j]))
            assert d >= 2, f"{fams[i]} vs {fams[j]} diverge on only {d} axes"


def test_board5_generator_reflects_family_gen_params():
    # Each family's generated world honors its pinned escalation edge and account pools, and two
    # families on the SAME seed produce materially different worlds (not a reskin).
    seed = "shared-seed"
    worlds = {}
    for fam in bv.variants_for(5):
        gp = bv.gen_params(5, fam)
        w = sc.generate_board5(seed, gp)
        t = w["targets"]
        assert t["escalation_edge"] == gp["escalation_edge"]
        assert t["kerberoast_account"] in gp["svc_pool"]
        assert t["asrep_user"] in gp["asrep_pool"]
        assert t["lateral_host"] in gp["lateral_pool"]
        # the aclabuse objective brief names the family's specific edge
        acl = next(o for o in w["objectives"] if o["id"] == "aclabuse")
        assert gp["escalation_edge"] in acl["hint"]
        worlds[fam] = (t["escalation_edge"], t["kerberoast_account"], t["lateral_host"])
    assert len(set(worlds.values())) == len(worlds), "families must yield distinct worlds on one seed"
    # reproducible per (seed, family)
    gp0 = bv.gen_params(5, bv.variants_for(5)[0])
    assert sc.generate_board5(seed, gp0) == sc.generate_board5(seed, gp0)


def test_board6_families_diverse_and_generator_reflects_them():
    fams = bv.variants_for(6)
    assert len(fams) >= 3
    for i in range(len(fams)):
        for j in range(i + 1, len(fams)):
            d = _divergent_axes(bv.diversity_axes(6, fams[i]), bv.diversity_axes(6, fams[j]))
            assert d >= 2, f"{fams[i]} vs {fams[j]} diverge on only {d} axes"
    seed = "b6-seed"
    seen = set()
    for fam in fams:
        gp = bv.gen_params(6, fam)
        w = sc.generate_board6(seed, gp)
        t = w["targets"]
        assert t["trust_topology"] == gp["trust_topology"]
        assert t["crown_location"] == gp["crown_location"]
        assert t["escalation"] == gp["escalation"]
        assert "_flags" not in sc.public_board6(w) and "_flags" not in str(sc.public_board6(w))
        seen.add((t["trust_topology"], t["crown_location"], t["escalation"]))
    assert len(seen) == len(fams), "board-6 families must yield distinct worlds"


def test_board6_legacy_seed_only_unchanged():
    s = sc.generate_board6("legacy-6")
    assert s == sc.generate_board6("legacy-6")
    full, _ = sc.score_board6(s, {"flags": dict(s["_flags"])})
    assert full == 100.0
    assert s["targets"]["trust_topology"] is None
