# parallax-adrange - live-execution Active Directory range

A **real Active Directory Domain Controller** (Samba AD DS) that candidates attack on boards 5-6.
This is the Railway-native equivalent of a GOAD/Ludus Windows range: Railway has no Windows and no
nested virtualization, so a Windows DC VM is impossible here, but a Samba AD DC gives a genuine,
attackable domain - real LDAP, Kerberos, SMB and DNS, with real users, SPNs, group memberships and
ACLs.

## The planted attack path (mirrors `ad_range.generate_domain`)

```
ranger (foothold)                      <- candidate is given these creds
  --[ForceChangePassword ACE]-->  svc_mssql (Kerberoastable, SPN MSSQLSvc/...)
  svc_mssql  --[memberOf]-->       TierAdmins
  TierAdmins --[DS-Replication-Get-Changes(-All)]--> domain head  == DCSync
  DCSync  ==> Administrator / krbtgt NT hashes
```

Decoys off the path: `svc_legacy` (AS-REP roastable), `helpdesk`, plus filler staff accounts.

## What the candidate runs (real tooling, over the Railway TCP proxy)

- `bloodhound-python` / RustHound -> collect the graph over LDAP (389)
- `GetUserSPNs.py` -> Kerberoast svc_mssql (TGS-REP, 88)
- `GetNPUsers.py` -> AS-REP roast the decoy (88)
- `bloodyAD` / `dacledit.py` -> abuse the ForceChangePassword ACE (389/445)
- `secretsdump.py -just-dc` -> **DCSync over the SMB `\drsuapi` named pipe (445)** - works through a
  single fixed proxied port, unlike EPM-negotiated RPC

## Proof of compromise

The objective is to DCSync the domain and recover the **Administrator NT hash**. The candidate never
learns the password, so the hash is obtainable only by real compromise. The portal verifies the
submitted hash against `MD4(UTF-16LE(ADRANGE_ADMIN_PASSWORD))`; an exact match is cryptographic proof
of a real domain compromise and cannot be faked. This becomes the signed, governed range attestation
(mode `real`) that credits the isolated-board live objective.

## Ports

Candidate-facing, exposed via Railway TCP proxy: `53, 88, 389, 445, 636, 3268`.
Private-only (never proxied): `9443` - the portal's proof/validation endpoint
(`/validate`, token-gated), used for a real technical-validation probe and to read the expected proof
material.

## Deploy (nonprod only)

1. Create the service from `deploy/parallax-adrange/Dockerfile`.
2. Set secrets: `ADRANGE_ADMIN_PASSWORD`, `ADRANGE_FOOTHOLD_PASSWORD`, `ADRANGE_PROOF_TOKEN`
   (and the non-secret `ADRANGE_REALM`, `ADRANGE_NETBIOS`, `ADRANGE_FOOTHOLD_USER`).
3. Add TCP proxies for `53, 88, 389, 445, 636, 3268`.
4. Wire the portal with `ADRANGE_ENABLED=1` and the matching `ADRANGE_*` values (see
   `railway.service.json` -> `portal_wiring`). The deterministic engine keeps working; the live range
   is the governed upgrade.

The domain re-provisions fresh on every boot; the Administrator proof hash is stable as long as
`ADRANGE_ADMIN_PASSWORD` is unchanged.

## Going live for governed credit (operator smoke test)

Everything except the live attack is verified automatically: the portal's
`/admin/adrange?token=<ADRANGE_PROOF_TOKEN>` runs a real probe of the DC over the
private network and must report `validation.ok: true` with all seven path checks
true. The one step that needs a box with open internet (not the build container)
is proving the attack chain works through the SOCKS pivot:

1. Put the SOCKS pivot in `/etc/proxychains4.conf` (strict_chain):
   `socks5 <ADRANGE_HOST> <ADRANGE_SOCKS_PORT> <ADRANGE_SOCKS_USER> <ADRANGE_SOCKS_PASSWORD>`
2. Enumerate:   `proxychains bloodhound-python -d qwalora.range -u ranger -p '<foothold pw>' -ns 127.0.0.1 --dns-tcp -c all`
3. Take svc_mssql (ACL abuse or Kerberoast), then DCSync:
   `proxychains secretsdump.py qwalora.range/svc_mssql:'<pw>'@127.0.0.1 -just-dc-user Administrator`
4. The recovered Administrator NT hash, pasted into the board 5/6 workspace
   "Submit proof" box, must verify. (It equals `MD4(UTF-16LE(ADRANGE_ADMIN_PASSWORD))`.)

Once that passes, set `ADRANGE_ADAPTER_VERIFIED=1` on the portal so a verified
live compromise can back isolated-board credit under governance (mirrors
`LUDUS_ADAPTER_VERIFIED`). Until then the range is fully usable and the proof is
recorded, but it is not counted as a governed real-range award (fail-closed).
