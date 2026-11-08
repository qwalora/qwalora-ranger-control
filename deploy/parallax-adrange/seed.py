#!/usr/bin/env python3
"""Plant the GOAD-style attack path into the live Samba AD DC.

Idempotent: safe to run on every boot. The chain mirrors ad_range.generate_domain():

    foothold (ForceChangePassword) -> Kerberoastable service account
      -> group with DCSync rights -> DCSync of the domain

Planted objects
---------------
  ranger        foothold the candidate is given creds for; holds User-Force-Change-Password
                over svc_mssql (ACL-abuse hop 1)
  svc_mssql     Kerberoastable service account (SPN MSSQLSvc/...), weak crackable password, so the
                candidate can reach it by Kerberoast+crack OR by ForceChangePassword (hop 2)
  TierAdmins    group svc_mssql belongs to; granted DS-Replication-Get-Changes[-All] on the domain
                head, i.e. DCSync rights (hop 3 -> DCSync)
  svc_legacy    AS-REP-roastable DECOY (DONT_REQ_PREAUTH) that is NOT on the intended path
  helpdesk      filler / decoy with a normal account

Nothing here is secret to the candidate except the two passwords (ranger's, which they are given, is
excluded). The domain is fully enumerable; only compromise yields the Administrator/krbtgt hashes.
"""
import os
import subprocess
import sys

from samba.auth import system_session
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

SMB_CONF = "/etc/samba/smb.conf"
SAMDB_PATH = "/var/lib/samba/private/sam.ldb"

REALM = os.environ.get("ADRANGE_REALM", "QWALORA.RANGE").lower()
FOOTHOLD_USER = os.environ.get("ADRANGE_FOOTHOLD_USER", "ranger")
FOOTHOLD_PASS = os.environ["ADRANGE_FOOTHOLD_PASSWORD"]

# Extended-right GUIDs.
GUID_FORCE_CHANGE_PW = "00299570-246d-11d0-a768-00aa006e0529"   # User-Force-Change-Password
GUID_DS_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"    # DS-Replication-Get-Changes
GUID_DS_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes-All

# userAccountControl bits.
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_DONT_REQ_PREAUTH = 0x400000

# Filler users so the directory looks like a real org, not a 4-object toy.
FILLER = ["jwilson", "agarcia", "mpatel", "schen", "dokafor", "lnguyen", "rkhan", "tbrooks"]


def samdb():
    lp = LoadParm()
    lp.load(SMB_CONF)
    return SamDB(url=SAMDB_PATH, session_info=system_session(), lp=lp)


def _exists(db, sam):
    res = db.search(base=db.domain_dn(), expression="(sAMAccountName=%s)" % sam, attrs=["dn"])
    return len(res) == 1


def _sid(db, sam):
    res = db.search(base=db.domain_dn(), expression="(sAMAccountName=%s)" % sam, attrs=["objectSid"])
    if not res:
        raise SystemExit("could not resolve SID for %s" % sam)
    return str(ndr_unpack(security.dom_sid, res[0]["objectSid"][0]))


def _dn(db, sam):
    res = db.search(base=db.domain_dn(), expression="(sAMAccountName=%s)" % sam, attrs=["dn"])
    return str(res[0].dn)


def ensure_user(db, sam, password, *, desc=None):
    if not _exists(db, sam):
        db.newuser(sam, password, description=desc)
        print("[seed] created user %s" % sam)
    _set_uac(db, sam, add=UAC_DONT_EXPIRE_PASSWORD)


def ensure_group(db, name):
    if not _exists(db, name):
        # newgroup defaults to a global security group, which is what we want for TierAdmins.
        db.newgroup(name)
        print("[seed] created group %s" % name)


def add_member(db, group, member):
    try:
        db.add_remove_group_members(group, [member], add_members_operation=True)
        print("[seed] %s -> %s" % (member, group))
    except Exception as e:  # already a member, etc.
        if "already" not in str(e).lower():
            raise


def _set_uac(db, sam, *, add=0, remove=0):
    import ldb
    dn = _dn(db, sam)
    res = db.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["userAccountControl"])
    cur = int(res[0]["userAccountControl"][0])
    new = (cur | add) & ~remove
    if new != cur:
        m = ldb.Message()
        m.dn = ldb.Dn(db, dn)
        m["userAccountControl"] = ldb.MessageElement(str(new), ldb.FLAG_MOD_REPLACE,
                                                     "userAccountControl")
        db.modify(m)
        print("[seed] UAC %s: %d -> %d" % (sam, cur, new))


def set_spn(db, sam, spn):
    import ldb
    dn = _dn(db, sam)
    res = db.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["servicePrincipalName"])
    have = [str(v) for v in res[0].get("servicePrincipalName", [])]
    if spn in have:
        return
    m = ldb.Message()
    m.dn = ldb.Dn(db, dn)
    m["servicePrincipalName"] = ldb.MessageElement(spn, ldb.FLAG_MOD_ADD, "servicePrincipalName")
    db.modify(m)
    print("[seed] SPN on %s: %s" % (sam, spn))


def dsacl_add(object_dn, trustee_sid, right_guids):
    """Append extended-right allow ACEs to object_dn for trustee_sid via samba-tool dsacl set."""
    sddl = "".join("(OA;;CR;%s;;%s)" % (g, trustee_sid) for g in right_guids)
    subprocess.run(
        ["samba-tool", "dsacl", "set", "--objectdn=%s" % object_dn, "--sddl=%s" % sddl],
        check=True, capture_output=True, text=True,
    )
    print("[seed] ACE(s) %s on %s -> %s" % (",".join(right_guids), object_dn, trustee_sid))


def main():
    db = samdb()
    domain_dn = db.domain_dn()

    # Foothold + service/decoy accounts. Passwords are complex enough for AD policy; svc_mssql's is
    # also in common wordlists so it is genuinely Kerberoast-crackable.
    ensure_user(db, FOOTHOLD_USER, FOOTHOLD_PASS,
                desc="Help desk operator (range foothold)")
    ensure_user(db, "svc_mssql", "Password123!",
                desc="SQL Server service account")
    ensure_user(db, "svc_legacy", "Legacy#Svc#2021",
                desc="Legacy batch service (pre-auth not required)")
    ensure_user(db, "helpdesk", "H3lpD3sk!2026", desc="Help desk shared account")
    for i, u in enumerate(FILLER):
        ensure_user(db, u, "Autumn2026!%d" % i, desc="Staff")

    # svc_legacy is the AS-REP-roastable DECOY (off the intended path).
    _set_uac(db, "svc_legacy", add=UAC_DONT_REQ_PREAUTH)

    # svc_mssql is Kerberoastable.
    set_spn(db, "svc_mssql", "MSSQLSvc/sql.%s:1433" % REALM)

    # Tiered group that holds DCSync; svc_mssql is a member (hop 2 -> 3).
    ensure_group(db, "TierAdmins")
    add_member(db, "TierAdmins", "svc_mssql")

    # Hop 1: foothold can ForceChangePassword svc_mssql.
    dsacl_add(_dn(db, "svc_mssql"), _sid(db, FOOTHOLD_USER), [GUID_FORCE_CHANGE_PW])

    # Hop 3: TierAdmins holds DCSync (replication) rights on the domain head.
    dsacl_add(domain_dn, _sid(db, "TierAdmins"), [GUID_DS_GET_CHANGES, GUID_DS_GET_CHANGES_ALL])

    print("[seed] attack path planted OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
