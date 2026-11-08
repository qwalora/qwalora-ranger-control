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

## Ports and the scoped pivot

The ONLY public endpoint is the Railway TCP proxy on `1080`, the scoped SOCKS5 pivot. It ignores the
client's requested host (always lands on the DC loopback) and scopes each credential to disjoint
ports:

- the **candidate** cred (`ADRANGE_SOCKS_USER/PASSWORD`) reaches only the AD service ports the attack
  chain needs: `53, 88, 135, 389, 445, 464, 636, 3268, 3269`;
- the **validator** cred (`ADRANGE_VALIDATOR_USER/PASSWORD`, portal-only) reaches only the token-gated
  proof server `9443`, nothing else.

So the portal can run its real `/validate` probe through the authenticated pivot WITHOUT the DC ever
sitting on the portal's private network (isolated-project deployment), and a candidate holding the
attack cred cannot reach `9443` at all. The `/validate` response carries structural checks only; the
Administrator NT hash is never returned (the portal derives the expected hash itself).

## Deploy

Two supported topologies:

- **nonprod (same environment as the portal):** simplest. The portal validates over private
  networking. Wire `ADRANGE_INTERNAL_URL=http://<dc-service>.railway.internal:9443`.
- **isolated prod (recommended for an ATO posture):** the DC lives in its OWN Railway project, off
  the production portal's private segment, so a candidate who fully compromises the range DC cannot
  reach the production portal or database. The portal validates through the authenticated pivot
  instead of private DNS: leave `ADRANGE_INTERNAL_URL` UNSET and set the validator cred.

Steps:

1. Create the service from `deploy/parallax-adrange/Dockerfile` (root directory
   `deploy/parallax-adrange`). For isolated prod, create it in a dedicated project.
2. Set secrets: `ADRANGE_ADMIN_PASSWORD`, `ADRANGE_FOOTHOLD_PASSWORD`, `ADRANGE_PROOF_TOKEN`,
   `ADRANGE_SOCKS_PASSWORD`, `ADRANGE_VALIDATOR_PASSWORD` (and the non-secret `ADRANGE_REALM`,
   `ADRANGE_NETBIOS`, `ADRANGE_FOOTHOLD_USER`, `ADRANGE_SOCKS_USER`, `ADRANGE_VALIDATOR_USER`).
3. Add ONE TCP proxy on the SOCKS port `1080`. Note the public endpoint, e.g.
   `host.proxy.rlwy.net:NNNNN`.
4. Wire the portal with `ADRANGE_ENABLED=1`, `ADRANGE_HOST`/`ADRANGE_SOCKS_PORT` (the public SOCKS
   endpoint), `ADRANGE_SOCKS_USER`/`ADRANGE_SOCKS_PASSWORD` (candidate cred),
   `ADRANGE_VALIDATOR_USER`/`ADRANGE_VALIDATOR_PASSWORD` (portal-only, for the validation pivot),
   `ADRANGE_PROOF_TOKEN`, `ADRANGE_ADMIN_PASSWORD`, `ADRANGE_REALM`,
   `ADRANGE_FOOTHOLD_USER`/`ADRANGE_FOOTHOLD_PASSWORD`. Set `ADRANGE_INTERNAL_URL` ONLY for the
   same-environment (nonprod) topology; omit it for the isolated pivot topology. The deterministic
   engine keeps working; the live range is the governed upgrade.

The domain re-provisions fresh on every boot; the Administrator proof hash is stable as long as
`ADRANGE_ADMIN_PASSWORD` is unchanged. Residual hardening note: the validator pivot carries the proof
token inside the (unencrypted) SOCKS tunnel; it gates only structural validation and no secret is
returned, but pinning TLS on the proof server is a reasonable future step.

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
