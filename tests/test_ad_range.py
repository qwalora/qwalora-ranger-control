"""Phase 2 AD range engine: determinism, answer-free enumeration, grader discrimination,
and BloodHound-export fidelity of the planted attack path."""
import ad_range as AR
import ad_bloodhound as BH

SEEDS = ["adr-%04d" % i for i in range(12)]


def test_deterministic_and_unique():
    a = AR.generate_domain("adr-0001")
    b = AR.generate_domain("adr-0001")
    assert a["intended_path"] == b["intended_path"] and a["domain"] == b["domain"]
    others = {AR.generate_domain(s)["domain"]["name"] + AR.generate_domain(s)["foothold"]["sam"]
              for s in SEEDS}
    assert len(others) >= len(SEEDS) - 1  # effectively unique per candidate


def test_public_view_is_answer_free():
    m = AR.generate_domain("adr-0003")
    pv = AR.public_view(m)
    assert "intended_path" not in pv
    assert all("crackable" not in u for u in pv["users"])
    assert all("intended" not in a for a in pv["aces"])
    # but the graph is fully enumerable: SPNs, AS-REP flags, ACLs all visible
    assert any(u.get("spns") for u in pv["users"])
    assert any(u.get("asrep") for u in pv["users"])
    assert pv["aces"] and pv["foothold"]["sam"]


def test_intended_path_is_consistent_with_graph():
    m = AR.generate_domain("adr-0004")
    intended = [a for a in m["aces"] if a["intended"]]
    # every planted ACE references principals that exist in the model
    sams = {u["sam"] for u in m["users"]} | {g["sam"] for g in m["groups"]} \
        | {c["sam"] for c in m["computers"]} | {m["domain"]["name"]}
    for a in intended:
        assert a["source_sam"] in sams and a["target_sam"] in sams


def test_grader_discriminates():
    for seed in SEEDS:
        m = AR.generate_domain(seed)
        ref = {"path": [{"source": h["source"], "technique": h["technique"], "target": h["target"]}
                        for h in m["intended_path"]]}
        assert AR.grade(seed, ref)[0] >= 99.0
        assert AR.grade(seed, {"path": []})[0] == 0.0
        # decoy-only (AS-REP + delegation, not on the path) must fail hard
        decoy = {"path": [{"source": "a", "technique": "AS-REP roasting", "target": "b"},
                          {"source": "c", "technique": "unconstrained delegation", "target": "d"}]}
        assert AR.grade(seed, decoy)[0] < 50.0
        # right nodes/techniques but reversed order must stay below the 95 objective bar
        assert AR.grade(seed, {"path": list(reversed(ref["path"]))})[0] < 95.0


def test_bloodhound_export_encodes_path():
    m = AR.generate_domain("adr-0001")
    files = BH.build(m)
    users = {u["ObjectIdentifier"]: u for u in files["users.json"]["data"]}
    fh = next(u for u in m["users"] if u["sam"] == m["foothold"]["sam"])
    # hop 1: ForceChangePassword from foothold lands as an ACE on the service-account target
    svc_targets = [a["target_sid"] for a in m["aces"]
                   if a["intended"] and a["right"] == "ForceChangePassword"]
    assert svc_targets
    svc_aces = users[svc_targets[0]]["Aces"]
    assert any(a["PrincipalSID"] == fh["sid"] and a["RightName"] == "ForceChangePassword"
               for a in svc_aces)
    # hop 4: DCSync replication rights on the domain object
    dom = files["domains.json"]["data"][0]
    assert {"GetChanges", "GetChangesAll"} <= {a["RightName"] for a in dom["Aces"]}
    z = BH.zip_bytes(m)
    assert z[:2] == b"PK" and len(z) > 500
