"""Phase 2 AD range engine: a per-candidate Active Directory estate with planted,
GOAD-style attack paths, graded the Ranger way.

Boards 5-6 teach Active Directory attack tradecraft. Running real Windows AD (GOAD) is
heavy and cannot live on Railway, so this engine generates, from a per-candidate seed, a
unique and internally-consistent AD domain whose misconfigurations form a designed
foothold-to-Domain-Admin path: Kerberoastable service accounts, AS-REP-roastable users,
dangerous DACLs (GenericAll / WriteDacl / ForceChangePassword / AddMember), unconstrained
delegation, nested privileged groups, and a DCSync finish. The full graph is exposed for
real enumeration and BloodHound analysis (see ad_bloodhound). The *intended* path and which
service-account passwords are actually crackable are the hidden key, re-derived server-side
at grade time, exactly like the Phase 1 boards. Nothing here is answer-leaking: an attacker
who enumerates everything still has to reason out the path.

generate_domain(seed) -> full model (public graph + hidden objective)
public_view(model)     -> what the candidate may enumerate (no hidden flags, no intended path)
grade(seed, submission)-> (score 0..100, feedback) for a submitted attack path
"""
from __future__ import annotations

import random as _random

# Domain themes: a believable enterprise, seed-picked. Names are cosmetic; the graph is what matters.
_ORGS = [
    ("northwind", "Northwind Trading"), ("contoso", "Contoso Group"),
    ("initech", "Initech Systems"), ("umbrella", "Umbrella Industries"),
    ("stark", "Stark Manufacturing"), ("wayne", "Wayne Enterprises"),
    ("acme", "Acme Logistics"), ("globex", "Globex Petroleum"),
    ("soylent", "Soylent Foods"), ("hooli", "Hooli Networks"),
]
_FIRST = ["james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
          "david", "elizabeth", "william", "barbara", "richard", "susan", "joseph", "jessica",
          "thomas", "sarah", "charles", "karen", "chris", "nancy", "daniel", "lisa", "matthew",
          "betty", "anthony", "sandra", "mark", "ashley", "paul", "kimberly", "steven", "donna"]
_LAST = ["smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis",
         "rodriguez", "martinez", "hernandez", "lopez", "gonzalez", "wilson", "anderson",
         "thomas", "taylor", "moore", "jackson", "martin", "lee", "perez", "thompson", "white",
         "harris", "sanchez", "clark", "ramirez", "lewis", "robinson", "walker", "young", "allen"]
_SVC = [("svc_sql", "MSSQLSvc", "SQL01"), ("svc_web", "HTTP", "WEB01"),
        ("svc_backup", "CIFS", "FILE01"), ("svc_vmware", "STS", "VC01"),
        ("svc_exchange", "exchangeMDB", "MAIL01"), ("svc_app", "HTTP", "APP01")]
# Server-side only. Governs whether a kerberoasted/AS-REP hash actually cracks in the scenario.
_CRACKABLE_HINT = "weak service-account password (seasonal pattern)"


def _sid(domain_sid, rid):
    return "%s-%d" % (domain_sid, rid)


def _mk_domain_sid(r):
    return "S-1-5-21-%d-%d-%d" % (r.randint(1_000_000_000, 4_000_000_000),
                                  r.randint(1_000_000_000, 4_000_000_000),
                                  r.randint(1_000_000_000, 4_000_000_000))


def generate_domain(seed):
    """Deterministic AD estate for a candidate seed. Returns a model whose `users`, `groups`,
    `computers` and `aces` are fully enumerable, plus hidden `intended_path` and `crackable`
    flags used only for grading."""
    r = _random.Random("ad-range:v1:%s" % seed)
    org_key, org_name = r.choice(_ORGS)
    netbios = org_key.upper()
    fqdn = "%s.local" % org_key
    dsid = _mk_domain_sid(r)
    rid = [1100]

    def next_rid():
        rid[0] += 1
        return rid[0]

    users, groups, computers, aces = [], [], [], []
    by_sam = {}

    def add_user(sam, display, **kw):
        u = {"sam": sam, "name": "%s@%s" % (sam, fqdn), "display": display,
             "sid": _sid(dsid, next_rid()), "enabled": True, "spns": [], "asrep": False,
             "admincount": False, "memberof": [], "description": "", "crackable": False}
        u.update(kw)
        users.append(u); by_sam[sam] = u
        return u

    def add_group(sam, display, rid_fixed=None, **kw):
        g = {"sam": sam, "display": display,
             "sid": _sid(dsid, rid_fixed) if rid_fixed else _sid(dsid, next_rid()),
             "members": [], "memberof": []}
        g.update(kw)
        groups.append(g); by_sam[sam] = g
        return g

    def add_computer(sam, **kw):
        c = {"sam": sam, "name": "%s.%s" % (sam.rstrip("$").lower(), fqdn),
             "sid": _sid(dsid, next_rid()), "os": "Windows Server 2019",
             "unconstrained": False, "rbcd": [], "memberof": []}
        c.update(kw)
        computers.append(c); by_sam[sam] = c
        return c

    def ace(src, right, dst, intended=False):
        aces.append({"source_sam": src["sam"], "source_sid": src["sid"],
                     "right": right, "target_sam": dst["sam"], "target_sid": dst["sid"],
                     "intended": intended})

    # --- privileged groups ---
    g_da = add_group("Domain Admins", "Domain Admins", rid_fixed=512)
    add_group("Enterprise Admins", "Enterprise Admins", rid_fixed=519)
    g_admins = add_group("Administrators", "Administrators", rid_fixed=544)
    g_da["memberof"].append("Administrators")

    # --- DC + member servers ---
    dc = add_computer("DC01$", os="Windows Server 2022", is_dc=True)
    srv_names = ["SQL01$", "WEB01$", "FILE01$", "APP01$", "MAIL01$", "VC01$"]
    r.shuffle(srv_names)
    servers = [add_computer(n) for n in srv_names[:4]]
    workstations = [add_computer("WS%02d$" % i) for i in range(1, r.randint(4, 7))]

    # --- population of ordinary users (noise) ---
    used = set()
    def fresh_name():
        for _ in range(50):
            f, l = r.choice(_FIRST), r.choice(_LAST)
            sam = "%s.%s" % (f, l)
            if sam not in used:
                used.add(sam); return sam, "%s %s" % (f.title(), l.title())
        sam = "user%d" % next_rid(); used.add(sam); return sam, sam
    for _ in range(r.randint(26, 40)):
        sam, disp = fresh_name()
        add_user(sam, disp)

    # some AS-REP roastable users (DONT_REQ_PREAUTH), one of which is noise, one adjacent to a path
    asrep_pool = r.sample(users, k=min(3, len(users)))
    for u in asrep_pool:
        u["asrep"] = True
        u["description"] = "legacy account; pre-auth disabled for an old scanner"

    # service accounts with SPNs (Kerberoastable); a subset crackable
    svc_defs = r.sample(_SVC, k=3)
    svcs = []
    for sam, spn_class, host in svc_defs:
        u = add_user(sam, sam, spns=["%s/%s.%s" % (spn_class, host.lower(), fqdn)],
                     description="service account for %s" % host)
        svcs.append(u)

    # custom groups with nesting (some privileged-adjacent)
    g_it = add_group("IT Support", "IT Support")
    g_server = add_group("Server Admins", "Server Admins")
    g_sql = add_group("SQL Admins", "SQL Admins")
    g_help = add_group("Helpdesk", "Helpdesk")
    g_backup = add_group("Backup Operators", "Backup Operators", rid_fixed=551)
    # noise memberships
    for u in r.sample(users, k=min(8, len(users))):
        grp = r.choice([g_it, g_help, g_sql])
        grp["members"].append(u["sid"]); u["memberof"].append(grp["sam"])

    # =========================================================================
    # PLANTED INTENDED PATH: foothold -> ACL -> kerberoast -> ACL -> priv group -> DCSync -> DA
    # Each actor and edge below is real and enumerable; only `intended=True` + `crackable` hide.
    # =========================================================================
    foothold = r.choice([u for u in users if u["sam"] not in {s["sam"] for s in svcs}
                         and not u["asrep"]])
    foothold["description"] = "standard domain user (your assumed initial access)"

    # Hop 1: foothold has ForceChangePassword over a kerberoastable service account
    target_svc = r.choice(svcs)
    target_svc["crackable"] = True
    target_svc["description"] = "service account; %s" % _CRACKABLE_HINT
    ace(foothold, "ForceChangePassword", target_svc, intended=True)

    # Hop 2 (kerberoast target_svc) -> target_svc has GenericAll on a privileged custom group
    priv_group = g_server
    ace(target_svc, "GenericAll", priv_group, intended=True)

    # Hop 3: priv_group has AdminTo the DC OR DCSync rights -> grant DCSync on the domain
    ace(priv_group, "GetChangesAll", {"sam": fqdn, "sid": dsid}, intended=True)  # DCSync on domain
    # priv_group members are local admins on a server (realism / lateral option)
    ace(priv_group, "AdminTo", r.choice(servers), intended=True)

    intended_path = [
        {"step": 1, "source": foothold["sam"], "technique": "ForceChangePassword",
         "target": target_svc["sam"],
         "detail": "Abuse the DACL to reset the service account's password."},
        {"step": 2, "source": target_svc["sam"], "technique": "Kerberoasting",
         "target": target_svc["sam"],
         "detail": "The service account has an SPN and a crackable password; roast and crack it "
                   "(or use the reset credentials) to control it."},
        {"step": 3, "source": target_svc["sam"], "technique": "ACL abuse: GenericAll -> AddMember",
         "target": priv_group["sam"],
         "detail": "Use GenericAll over the group to add yourself as a member."},
        {"step": 4, "source": priv_group["sam"], "technique": "DCSync",
         "target": fqdn,
         "detail": "The group holds replication rights (DS-Replication-Get-Changes-All); DCSync "
                   "the domain to extract krbtgt / Domain Admin hashes."},
    ]

    # --- noise ACEs (dangerous-looking but not on the intended path) ---
    noise_rights = ["GenericWrite", "WriteOwner", "ReadLAPSPassword", "AddKeyCredentialLink"]
    for _ in range(r.randint(5, 9)):
        src = r.choice(users + groups)
        dst = r.choice(users + groups + computers)
        if src is dst:
            continue
        ace(src, r.choice(noise_rights), dst, intended=False)
    # one unconstrained-delegation server (an alternate path; realism)
    r.choice(servers)["unconstrained"] = True

    # place foothold membership + ensure path actors are enumerable in a benign group
    g_it["members"].append(foothold["sid"]); foothold["memberof"].append("IT Support")

    model = {
        "domain": {"name": fqdn, "netbios": netbios, "org": org_name, "sid": dsid,
                   "functional_level": "2016"},
        "users": users, "groups": groups, "computers": computers, "aces": aces,
        "foothold": {"sam": foothold["sam"], "name": foothold["name"],
                     "note": "You have valid credentials for this standard user."},
        "intended_path": intended_path,
        "stats": {"users": len(users), "groups": len(groups), "computers": len(computers),
                  "aces": len(aces)},
    }
    return model


def _domain_block(r, fqdn, netbios, is_root, n_users=14):
    """Build one domain's objects (users, groups, computers) tagged with their domain and SID.
    Returns (dsid, objects dict, index of key principals) for the forest wiring."""
    dsid = _mk_domain_sid(r)
    rid = [1100]

    def nr():
        rid[0] += 1
        return rid[0]

    users, groups, computers = [], [], []
    used = set()

    def name():
        for _ in range(40):
            f, l = r.choice(_FIRST), r.choice(_LAST)
            s = "%s.%s" % (f, l)
            if s not in used:
                used.add(s); return s, "%s %s" % (f.title(), l.title())
        s = "user%d" % nr(); used.add(s); return s, s

    def add_user(sam, display, **kw):
        u = {"sam": sam, "name": "%s@%s" % (sam, fqdn), "display": display, "domain": fqdn,
             "domainsid": dsid, "sid": _sid(dsid, nr()), "enabled": True, "spns": [],
             "asrep": False, "admincount": False, "memberof": [], "description": "", "crackable": False}
        u.update(kw); users.append(u); return u

    def add_group(sam, display, rid_fixed=None, **kw):
        g = {"sam": sam, "display": display, "domain": fqdn, "domainsid": dsid,
             "sid": _sid(dsid, rid_fixed) if rid_fixed else _sid(dsid, nr()),
             "members": [], "memberof": []}
        g.update(kw); groups.append(g); return g

    def add_comp(sam, **kw):
        c = {"sam": sam, "name": "%s.%s" % (sam.rstrip("$").lower(), fqdn), "domain": fqdn,
             "domainsid": dsid, "sid": _sid(dsid, nr()), "os": "Windows Server 2019",
             "unconstrained": False, "rbcd": [], "memberof": []}
        c.update(kw); computers.append(c); return c

    g_da = add_group("Domain Admins (%s)" % netbios, "Domain Admins", rid_fixed=512)
    g_ea = add_group("Enterprise Admins", "Enterprise Admins", rid_fixed=519) if is_root else None
    g_custom = add_group("%s Server Admins" % netbios, "%s Server Admins" % netbios)
    dc = add_comp("%s-DC01$" % netbios, os="Windows Server 2022", is_dc=True)
    for _ in range(r.randint(1, 2)):
        add_comp("%s-SRV%02d$" % (netbios, r.randint(1, 9)))
    for _ in range(n_users):
        s, d = name(); add_user(s, d)
    # a service account with an SPN (Kerberoastable) in this domain
    svc_sam, spn_class, host = r.choice(_SVC)
    svc = add_user("%s_%s" % (svc_sam, netbios.lower()), svc_sam,
                   spns=["%s/%s.%s" % (spn_class, host.lower(), fqdn)],
                   description="service account for %s" % host)
    idx = {"dsid": dsid, "da": g_da, "ea": g_ea, "custom": g_custom, "dc": dc, "svc": svc,
           "users": users, "groups": groups, "computers": computers}
    return dsid, {"users": users, "groups": groups, "computers": computers}, idx


def generate_forest(seed):
    """Board 6 capstone: a multi-domain forest. A child domain (dev.<root>) and its parent forest
    root, plus a second forest reached over a trust. The planted path runs foothold -> child Domain
    Admin -> parent Enterprise Admin via intra-forest trust abuse (SID history) -> forest persistence
    (DCSync) -> cross-forest pivot. Same model shape and grader as board 5; the intended path and
    crackable flags are hidden."""
    r = _random.Random("ad-forest:v1:%s" % seed)
    (k1, root_name), (k2, _f2name) = r.sample(_ORGS, 2)
    root_fqdn, root_nb = "%s.local" % k1, k1.upper()
    child_fqdn, child_nb = "dev.%s.local" % k1, "DEV"
    f2_fqdn, f2_nb = "%s.local" % k2, k2.upper()

    cs, cobj, ci = _domain_block(r, child_fqdn, child_nb, is_root=False)
    ps, pobj, pi = _domain_block(r, root_fqdn, root_nb, is_root=True)
    fs, fobj, fi = _domain_block(r, f2_fqdn, f2_nb, is_root=True)

    users = cobj["users"] + pobj["users"] + fobj["users"]
    groups = cobj["groups"] + pobj["groups"] + fobj["groups"]
    computers = cobj["computers"] + pobj["computers"] + fobj["computers"]
    aces = []

    def ace(src, right, dst, intended=False):
        aces.append({"source_sam": src["sam"], "source_sid": src["sid"], "right": right,
                     "target_sam": dst["sam"], "target_sid": dst["sid"], "intended": intended})

    # intra-child path: foothold -> ForceChangePassword -> child svc (kerberoastable) ->
    # GenericAll -> child privileged group -> DCSync child
    foothold = r.choice([u for u in ci["users"] if u is not ci["svc"]])
    foothold["description"] = "standard user in the child domain (your assumed initial access)"
    child_svc = ci["svc"]; child_svc["crackable"] = True
    child_svc["description"] = "service account; %s" % _CRACKABLE_HINT
    child_grp = ci["custom"]   # distinct privileged group that holds replication on the child
    ace(foothold, "ForceChangePassword", child_svc, intended=True)
    ace(child_svc, "GenericAll", child_grp, intended=True)
    ace(child_grp, "GetChangesAll", {"sam": child_fqdn, "sid": cs}, intended=True)
    # parent EA holds replication on the parent (DCSync); represent the right for BloodHound
    ace(pi["ea"], "GetChangesAll", {"sam": root_fqdn, "sid": ps}, intended=True)

    trusts = [
        {"from": child_fqdn, "to": root_fqdn, "type": "ParentChild", "transitive": True,
         "sid_filtering": False},
        {"from": root_fqdn, "to": f2_fqdn, "type": "Forest", "transitive": True,
         "sid_filtering": False},
    ]

    intended_path = [
        {"step": 1, "source": foothold["sam"], "technique": "ForceChangePassword",
         "target": child_svc["sam"], "detail": "Abuse the DACL to reset the service account."},
        {"step": 2, "source": child_svc["sam"], "technique": "Kerberoasting",
         "target": child_svc["sam"], "detail": "Crack the roastable service account."},
        {"step": 3, "source": child_svc["sam"], "technique": "ACL abuse: GenericAll -> AddMember",
         "target": child_grp["display"], "detail": "Use GenericAll to join the privileged group."},
        {"step": 4, "source": child_grp["display"], "technique": "DCSync",
         "target": child_fqdn, "detail": "DCSync the child to reach child Domain Admin."},
        {"step": 5, "source": "Domain Admins (%s)" % child_nb,
         "technique": "Trust abuse: SID history / ExtraSids", "target": "Enterprise Admins",
         "detail": "Forge an inter-realm TGT adding the parent Enterprise Admins SID (no SID "
                   "filtering on the parent-child trust)."},
        {"step": 6, "source": "Enterprise Admins", "technique": "DCSync",
         "target": root_fqdn, "detail": "DCSync the forest root (krbtgt) for forest persistence."},
        {"step": 7, "source": "Enterprise Admins", "technique": "Cross-forest trust abuse",
         "target": f2_fqdn, "detail": "Abuse the forest trust (SID filtering off) to pivot into "
                                      "the second forest."},
    ]

    foothold_blk = {"sam": foothold["sam"], "name": foothold["name"],
                    "note": "Valid credentials for a standard user in %s." % child_fqdn}
    model = {
        "domain": {"name": root_fqdn, "netbios": root_nb, "org": root_name, "sid": ps,
                   "functional_level": "2016", "forest": True},
        "domains": [
            {"name": child_fqdn, "netbios": child_nb, "sid": cs, "role": "child"},
            {"name": root_fqdn, "netbios": root_nb, "sid": ps, "role": "forest-root"},
            {"name": f2_fqdn, "netbios": f2_nb, "sid": fs, "role": "second-forest"},
        ],
        "trusts": trusts,
        "users": users, "groups": groups, "computers": computers, "aces": aces,
        "foothold": foothold_blk, "intended_path": intended_path,
        "stats": {"domains": 3, "users": len(users), "groups": len(groups),
                  "computers": len(computers), "aces": len(aces)},
    }
    return model


_HIDDEN_USER_FIELDS = ("crackable",)


def public_view(model):
    """The enumerable graph: everything a real attacker could collect, minus the hidden grading
    flags and the intended path. SPNs, AS-REP flags, group membership, DACLs and delegation are
    all visible - that is the point; the skill is reasoning the path from them."""
    def strip(d, hide):
        return {k: v for k, v in d.items() if k not in hide}
    out = {
        "domain": model["domain"],
        "foothold": model["foothold"],
        "users": [strip(u, _HIDDEN_USER_FIELDS) for u in model["users"]],
        "groups": model["groups"],
        "computers": model["computers"],
        "aces": [strip(a, ("intended",)) for a in model["aces"]],
        "stats": model["stats"],
    }
    if "domains" in model:   # forest (board 6)
        out["domains"] = model["domains"]
        out["trusts"] = model.get("trusts", [])
    return out


# --- grading -----------------------------------------------------------------
_TECH_CATS = {
    "forcechangepassword": ["forcechange", "force change", "reset password", "reset the password",
                            "password reset", "targeted kerberoast"],
    "kerberoasting": ["kerberoast", "roasting", "roast", "spn", "service ticket", "tgs"],
    "acl-abuse": ["genericall", "generic all", "writedacl", "write dacl", "addmember", "add member",
                  "add self", "acl abuse", "acl", "dacl", "writeowner", "add to group", "group member"],
    "dcsync": ["dcsync", "dc sync", "drsuapi", "replication", "getchanges", "get changes",
               "ds-replication", "secretsdump", "krbtgt dump"],
    # forest-capstone (board 6) tradecraft
    "trust-abuse": ["sid history", "sidhistory", "extrasids", "extra sids", "inter-realm",
                    "interrealm", "trust key", "trust ticket", "child to parent", "child-to-parent",
                    "sid filtering", "intra-forest trust", "parent trust"],
    "golden-ticket": ["golden ticket", "golden-ticket", "forest persistence", "krbtgt golden",
                      "forge tgt", "forged tgt"],
    "cross-forest": ["cross forest", "cross-forest", "forest trust", "foreign", "inter-forest",
                     "sid-filtering bypass", "external trust"],
}
# decoy categories a candidate might name that are NOT on the intended path
_DECOY_CATS = {"asrep": ["asrep", "as-rep", "as rep"], "delegation": ["unconstrained", "delegation",
              "rbcd", "constrained"]}


def _tech_cat(text):
    t = str(text or "").lower()
    for cat, needles in _TECH_CATS.items():
        if any(n in t for n in needles):
            return cat
    for cat, needles in _DECOY_CATS.items():
        if any(n in t for n in needles):
            return cat
    return None


def _norm_principal(text):
    t = str(text or "").strip().lower()
    t = t.split("@")[0].rstrip("$").strip()
    return " ".join(t.split())


def _set_f1(got, want):
    if not want:
        return 1.0
    if not got:
        return 0.0
    inter = len(got & want)
    prec = inter / len(got)
    rec = inter / len(want)
    return 0.0 if (prec + rec) == 0 else 2 * prec * rec / (prec + rec)


def _lcs_ratio(a, b):
    """Longest common subsequence length / len(b): rewards correct ordering of the intended steps."""
    if not b:
        return 1.0
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            dp[i][j] = dp[i + 1][j + 1] + 1 if a[i] == b[j] else max(dp[i + 1][j], dp[i][j + 1])
    return dp[0][0] / m


def grade(seed, submission):
    """Score a board-5 (single-domain) attack path against the hidden intended path."""
    return _grade_model(generate_domain(seed), submission)


def grade_forest(seed, submission):
    """Score a board-6 (multi-domain forest) attack path against the hidden intended path."""
    return _grade_model(generate_forest(seed), submission)


def _grade_model(model, submission):
    """Score a submitted attack path against a model's hidden intended path.

    submission = {"path": [{"source","technique","target"}, ...]}  (ordered, foothold -> DA)
    Returns (score 0..100, feedback dict). Weights: key principals 0.35, techniques 0.40,
    ordering 0.25. A candidate who identifies the full chain with the right techniques in order
    scores 100; naming decoy abuses (AS-REP, delegation) that are not on the path does not help
    and dilutes precision.
    """
    path = model["intended_path"]
    dom = model["domain"]["name"]

    # intended key principals and technique sequence
    foothold = _norm_principal(model["foothold"]["sam"])
    want_nodes = set()
    want_cats = []
    for hop in path:
        want_cats.append(_tech_cat(hop["technique"]))
        want_nodes.add(_norm_principal(hop["source"]))
        want_nodes.add(_norm_principal(hop["target"]))
    want_nodes.discard("")
    # the DCSync target is the domain itself; accept common spellings
    domain_aliases = {_norm_principal(dom), "domain", "dc", "dc01", "krbtgt", dom.split(".")[0]}

    sub_path = (submission or {}).get("path") or []
    got_nodes, got_cats = set(), []
    for hop in sub_path:
        cat = _tech_cat(hop.get("technique"))
        if cat:
            got_cats.append(cat)
        for key in ("source", "target"):
            p = _norm_principal(hop.get(key))
            if not p:
                continue
            got_nodes.add("__domain__" if p in domain_aliases else p)
    # fold the intended domain node into the alias token for matching
    want_nodes_folded = {"__domain__" if n in domain_aliases else n for n in want_nodes}

    node_f1 = _set_f1(got_nodes, want_nodes_folded)
    want_cat_set = {c for c in want_cats if c}
    got_cat_set = {c for c in got_cats if c}
    tech_f1 = _set_f1(got_cat_set, want_cat_set)
    order = _lcs_ratio([c for c in got_cats if c in want_cat_set], [c for c in want_cats if c])

    score = round(100.0 * (0.35 * node_f1 + 0.40 * tech_f1 + 0.25 * order), 1)
    hit = sorted(got_cat_set & want_cat_set)
    missing_count = len(want_cat_set - got_cat_set)
    decoys = sorted(got_cat_set & set(_DECOY_CATS))
    feedback = {
        "score": score,
        "key_principals": {"identified": len(got_nodes & want_nodes_folded),
                           "required": len(want_nodes_folded)},
        "techniques": {"correct": hit, "missing_count": missing_count},
        "ordering": round(order, 2),
        "off_path": decoys,  # abuses named that are not on the intended path
        "note": ("Full domain-compromise path reconstructed." if score >= 95 else
                 "Keep refining: confirm each hop with BloodHound, make sure the abuses chain in "
                 "order from your foothold to a Domain Admin / DCSync primitive, and drop any "
                 "abuses that do not advance the path."),
    }
    return score, feedback

