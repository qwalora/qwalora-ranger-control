# qwalora.flags

An Ansible role that plants a ranger's per-seed flags into their GOAD range so
that capturing a flag proves the matching objective was actually completed. It
runs after `badsectorlabs.ludus_goad` (the domain, accounts, SPNs and shares
must already exist) and is applied to every Windows host in the range.

## Input

- `qwalora_flags` — a dict of objective id -> flag token, injected by the portal
  as `templateVars.ranger_flags` at deploy time (the same tokens the portal's
  grader re-derives from the ranger's seed). Empty means the role no-ops.
- `qwalora_flags_board` — 5 or 6, selects which objective set is in play.

## Objective -> location map

Placement is the contract: each flag must be unreachable without performing its
objective. If you retheme GOAD or rename accounts, keep that property.

| Objective | Host | Location | Gate |
|-----------|------|----------|------|
| recon / recon_forest | kingslanding | `C:\shares\public\welcome.txt` | any authenticated user |
| foothold | castelblack | `C:\Users\Public\Documents\notes.txt` | a session on the box |
| asreproast | winterfell | `…\ranger\asrep.flag` | ACL: the no-preauth user |
| kerberoast / roast_forest | winterfell | `…\ranger\svc.flag` | ACL: the service account |
| lateral | castelblack/meereen | `…\ranger\lateral.flag` | code exec on the pivot |
| credaccess | castelblack | `…\ranger\creds.flag` | ACL: SYSTEM / local admin |
| aclabuse | winterfell | `…\ranger\acl.flag` | owning the abused object |
| domainadmin / child_da | winterfell | `C:\Users\Administrator\Desktop\flag.txt` | Domain Admin |
| trust_abuse | kingslanding | `…\ranger\trust.flag` | crossing the trust |
| parent_ea | kingslanding | `…\Administrator\Desktop\enterprise.txt` | Enterprise Admin |
| dcsync / forest_persist | kingslanding | `C:\Windows\NTDS\ranger.flag` | DCSync / DA on the root |
| cross_forest | meereen | `…\ranger\crossforest.flag` | pivot into essos |
| forest2_da | braavos | `C:\Users\Administrator\Desktop\flag.txt` | Domain Admin of essos |
| crown | kingslanding | `C:\Windows\NTDS\crown.flag` | exfil from the root DC |

The ACLs are enforced with `win_acl` + `win_acl_inheritance` so a flag that is
"restricted to X" really is readable only by X. A ranger who lands the account
or privilege reads it; anyone else gets access denied.

## Matching your GOAD version (the one thing that breaks)

The role ACL-locks some flags to named GOAD accounts (`sql_svc`,
`brandon.stark`). If your installed `badsectorlabs.ludus_goad` version seeds
different names, those flags would be planted unreadable. Three guards make that
fail loud instead of silent:

- **Preflight** (`qwalora_flags_preflight`, default on): on a DC, every
  referenced account is resolved with `Get-ADUser` before anything is planted.
  A missing name stops the run with the exact fix (set `qwalora_svc_account` /
  `qwalora_asrep_account` and redeploy). The loot directory is also checked
  writable.
- **Readback** (`qwalora_flags_verify`, default on): after planting, the
  ACL-restricted flags are `win_stat`-ed and the run fails if any did not land.
- **Dry-check**: run `ludus/validate-flags.yml` against a freshly built template
  before enrolling rangers. It runs only the preflight (no planting), so a
  version mismatch surfaces up front. Override names with
  `-e qwalora_svc_account=... -e qwalora_asrep_account=...`.

Set the names (and `qwalora_goad_variant`) as role vars to match your GOAD
build; the defaults target the stock `GOAD` variant.

## Why planting, not checking

The role never verifies or reports anything back. The portal is the sole grader:
the ranger submits the flags they captured, and the portal checks them against
the seed-derived expected set. That keeps the range dumb and the grading
authoritative, and means a compromised range can never award a pass.
