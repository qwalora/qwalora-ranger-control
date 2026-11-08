"""Export a seeded ad_range domain to BloodHound CE ingest JSON.

Candidates analyze their unique domain in real BloodHound Community Edition: same tool, same
workflow (shortest-path-to-Domain-Admins, pre-built queries, Kerberoastable/AS-REP views) they
would use on a live engagement. We generate the ingest files directly from the model, so no
live DC or collector is needed. BloodHound derives edges from these primitives: ACEs on each
target object (who has rights over it), group Members, SPN/pre-auth user properties, computer
delegation flags, LocalAdmins (AdminTo), and DS-Replication rights on the domain (DCSync).

build(model) -> {filename: json_obj}         (users/groups/computers/domains .json)
zip_bytes(model) -> bytes                     (a .zip BloodHound CE ingests directly)

NOTE: the schema targets BloodHound CE (version 5). Ingestion must be validated against a live
BloodHound CE instance before a candidate relies on it; the raw graph (ad_range.public_view) is
the always-available source of truth for enumeration and grading regardless.
"""
from __future__ import annotations

import io
import json
import zipfile

_VERSION = 5


def _type_map(model):
    t = {model["domain"]["sid"]: "Domain"}
    for u in model["users"]:
        t[u["sid"]] = "User"
    for g in model["groups"]:
        t[g["sid"]] = "Group"
    for c in model["computers"]:
        t[c["sid"]] = "Computer"
    return t


# RightName mapping from our model's ACE rights to BloodHound edge rights.
_RIGHT = {
    "ForceChangePassword": "ForceChangePassword", "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite", "WriteDacl": "WriteDacl", "WriteOwner": "WriteOwner",
    "AddMember": "AddMember", "AddKeyCredentialLink": "AddKeyCredentialLink",
    "ReadLAPSPassword": "ReadLAPSPassword", "GetChangesAll": "GetChangesAll",
    "GetChanges": "GetChanges",
}


def _aces_for(target_sid, model, tmap):
    out = []
    for a in model["aces"]:
        if a["target_sid"] != target_sid:
            continue
        rn = _RIGHT.get(a["right"])
        if not rn:
            continue
        out.append({"PrincipalSID": a["source_sid"],
                    "PrincipalType": tmap.get(a["source_sid"], "Base"),
                    "RightName": rn, "IsInherited": False})
    return out


def _meta(kind, count):
    return {"methods": 0, "type": kind, "count": count, "version": _VERSION}


def build(model):
    tmap = _type_map(model)
    dom = model["domain"]
    dsid, dname = dom["sid"], dom["name"].upper()

    # DCSync: synthesize GetChanges + GetChangesAll on the domain for any source granted either,
    # so BloodHound renders the DCSync edge.
    dcsync_srcs = {a["source_sid"] for a in model["aces"]
                   if a["target_sid"] == dsid and a["right"] in ("GetChanges", "GetChangesAll")}
    domain_aces = []
    for s in sorted(dcsync_srcs):
        for rn in ("GetChanges", "GetChangesAll"):
            domain_aces.append({"PrincipalSID": s, "PrincipalType": tmap.get(s, "Group"),
                                "RightName": rn, "IsInherited": False})

    # AdminTo -> computer LocalAdmins
    admin_to = {}
    for a in model["aces"]:
        if a["right"] == "AdminTo":
            admin_to.setdefault(a["target_sid"], []).append(
                {"ObjectIdentifier": a["source_sid"], "ObjectType": tmap.get(a["source_sid"], "Group")})

    def _du(obj):
        return (obj.get("domain") or dom["name"]).upper()

    def _ds(obj):
        return obj.get("domainsid") or dsid

    users = []
    for u in model["users"]:
        du, ds = _du(u), _ds(u)
        users.append({
            "ObjectIdentifier": u["sid"],
            "Properties": {
                "name": "%s@%s" % (u["sam"].upper(), du), "domain": du, "domainsid": ds,
                "distinguishedname": "CN=%s,DC=%s" % (u["sam"], ",DC=".join((u.get("domain") or dom["name"]).split("."))),
                "enabled": u.get("enabled", True), "hasspn": bool(u.get("spns")),
                "dontreqpreauth": bool(u.get("asrep")), "admincount": bool(u.get("admincount")),
                "serviceprincipalnames": u.get("spns", []),
                "description": u.get("description", ""), "unconstraineddelegation": False,
            },
            "PrimaryGroupSID": "%s-513" % ds,
            "Aces": _aces_for(u["sid"], model, tmap),
            "SPNTargets": [], "HasSIDHistory": [], "AllowedToDelegate": [],
        })

    groups = []
    for g in model["groups"]:
        du, ds = _du(g), _ds(g)
        groups.append({
            "ObjectIdentifier": g["sid"],
            "Properties": {"name": "%s@%s" % (g["display"].upper().replace(" ", ""), du),
                           "domain": du, "domainsid": ds},
            "Members": [{"ObjectIdentifier": sid, "ObjectType": tmap.get(sid, "Base")}
                        for sid in g.get("members", [])],
            "Aces": _aces_for(g["sid"], model, tmap),
        })

    computers = []
    for c in model["computers"]:
        du, ds = _du(c), _ds(c)
        computers.append({
            "ObjectIdentifier": c["sid"],
            "Properties": {"name": "%s@%s" % (c["sam"].rstrip("$").upper(), du),
                           "domain": du, "domainsid": ds,
                           "operatingsystem": c.get("os", "Windows Server 2019"),
                           "unconstraineddelegation": bool(c.get("unconstrained")),
                           "enabled": True},
            "PrimaryGroupSID": "%s-515" % ds,
            "Aces": _aces_for(c["sid"], model, tmap),
            "AllowedToDelegate": [],
            "AllowedToAct": [{"ObjectIdentifier": s, "ObjectType": tmap.get(s, "Computer")}
                             for s in c.get("rbcd", [])],
            "Sessions": {"Results": [], "Collected": True, "FailureReason": None},
            "LocalAdmins": {"Results": admin_to.get(c["sid"], []), "Collected": True,
                            "FailureReason": None},
        })

    # one or more domains (a forest exports every domain with its trusts)
    dom_list = model.get("domains") or [{"name": dom["name"], "netbios": dom.get("netbios", ""),
                                         "sid": dsid}]
    by_dsid_trusts = {}
    for t in model.get("trusts", []):
        src_sid = next((d["sid"] for d in dom_list if d["name"] == t["from"]), None)
        tgt = next((d for d in dom_list if d["name"] == t["to"]), None)
        if src_sid and tgt:
            by_dsid_trusts.setdefault(src_sid, []).append({
                "TargetDomainSid": tgt["sid"], "TargetDomainName": tgt["name"].upper(),
                "IsTransitive": bool(t.get("transitive", True)), "TrustDirection": "Inbound",
                "TrustType": t.get("type", "ParentChild"),
                "SidFilteringEnabled": bool(t.get("sid_filtering", False))})
    domains = []
    for d in dom_list:
        dsid_i = d["sid"]
        children = ([{"ObjectIdentifier": u["sid"], "ObjectType": "User"} for u in model["users"] if _ds(u) == dsid_i]
                    + [{"ObjectIdentifier": g["sid"], "ObjectType": "Group"} for g in model["groups"] if _ds(g) == dsid_i]
                    + [{"ObjectIdentifier": c["sid"], "ObjectType": "Computer"} for c in model["computers"] if _ds(c) == dsid_i])
        # DCSync aces specific to this domain object
        d_srcs = {a["source_sid"] for a in model["aces"]
                  if a["target_sid"] == dsid_i and a["right"] in ("GetChanges", "GetChangesAll")}
        d_aces = []
        for s in sorted(d_srcs):
            for rn in ("GetChanges", "GetChangesAll"):
                d_aces.append({"PrincipalSID": s, "PrincipalType": tmap.get(s, "Group"),
                               "RightName": rn, "IsInherited": False})
        domains.append({
            "ObjectIdentifier": dsid_i,
            "Properties": {"name": d["name"].upper(), "domain": d["name"].upper(), "domainsid": dsid_i,
                           "distinguishedname": "DC=" + ",DC=".join(d["name"].split(".")),
                           "functionallevel": "2016 Functional Level"},
            "ChildObjects": children,
            "Trusts": by_dsid_trusts.get(dsid_i, []), "Links": [], "Aces": d_aces,
            "GPOChanges": {"LocalAdmins": [], "RemoteDesktopUsers": [], "DcomUsers": [],
                           "PSRemoteUsers": [], "AffectedComputers": []},
        })

    return {
        "users.json": {"data": users, "meta": _meta("users", len(users))},
        "groups.json": {"data": groups, "meta": _meta("groups", len(groups))},
        "computers.json": {"data": computers, "meta": _meta("computers", len(computers))},
        "domains.json": {"data": domains, "meta": _meta("domains", len(domains))},
    }


def zip_bytes(model):
    """A .zip of the ingest files, ready to drag into BloodHound CE."""
    files = build(model)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, obj in files.items():
            z.writestr(name, json.dumps(obj, separators=(",", ":")))
    return buf.getvalue()
