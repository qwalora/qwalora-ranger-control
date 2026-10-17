# STRATA S6 - Cost and capacity model (Raider / Vanguard isolated ranges)

Repository: `qwalora/qwalora-ranger-control`
Branch: `feature/strata-s6-goad-ranges`
Scope: the operating cost and concurrency capacity of the boards 5/6 isolated GOAD ranges only. The
blue boards (1-4) and the control plane are covered by the portal's own small always-on footprint and
are out of scope here except as the combined-budget check at the end.

**Every figure below is a current-list ESTIMATE to confirm at provisioning time, not a quote, and the
range timings themselves are category-D UNVERIFIED without a live Ludus/Proxmox host.** No paid
infrastructure is provisioned by this branch; this is a planning model.

## 1. What a range actually costs

The cost lever for S6 is the GOAD **host** (a Ludus/Proxmox node) plus the **RAM-hours** consumed by
concurrently powered-on ranges. Ludus ranges are per-user and isolated; the host persists, individual
ranges come and go (deploy / suspend / resume / destroy).

| Board | Template | Topology | Typical powered-on footprint (estimate) |
|---|---|---|---|
| 5 Raider | `goad` | single-domain GOAD (2 DCs + member servers) | ~5 VMs, ~24-28 GB RAM, ~120-160 GB disk |
| 6 Vanguard | `goad-capstone` | multi-forest (parent + child + trusted forest) | ~7-8 VMs, ~36-48 GB RAM, ~200-260 GB disk |

A powered-OFF (suspended) range consumes **disk only**, no RAM. A destroyed range consumes nothing.
These footprints are the dominant variable; the GOAD images are heavy AD VMs, not containers.

## 2. Capacity math (tied to the actual controls)

Concurrency is bounded server-side by `MAX_CONCURRENT_RANGES` (default **2**), counted across
reserved + provisioning + deployed ranges per host. The lifecycle controls that shape RAM demand:

| Control (env) | Default | Effect on cost |
|---|---|---|
| `MAX_CONCURRENT_RANGES` | 2 | hard ceiling on simultaneously powered-on ranges per host |
| `RANGE_IDLE_HOURS` | 8 | idle ranges are reclaimed (suspended under an evidence hold, else destroyed) |
| `RANGE_MAX_AGE_HOURS` | 48 | hard age cap; same reclaim path |
| `RANGE_EVIDENCE_HOLD_HOURS` | 72 | after a submission, reclamation SUSPENDS (power-off) rather than destroys, so disk persists but RAM is freed |

**Theoretical RAM sum vs genuinely provisioned capacity.** A host's advertised RAM is not all
schedulable: the hypervisor/host OS reserves ~4-8 GB, and these are Windows AD VMs where memory
ballooning is unreliable, so each range must be sized at its full footprint, not an optimistic
average. Provisioned capacity on a host is therefore roughly `(host_RAM - host_overhead) /
per_range_RAM`, rounded DOWN, with no over-commit.

Correcting the earlier arithmetic on a **~64 GB** host (host overhead ~6 GB, ~58 GB schedulable):

| Range type | Per-range RAM (est.) | Concurrent ranges a 64 GB host genuinely holds |
|---|---|---|
| Raider (board 5) | ~24-28 GB | **2** (48-56 GB, fits within ~58 GB) |
| Vanguard capstone (board 6) | ~36-48 GB | **1** (a second would need 72-96 GB; it does NOT fit) |

So `MAX_CONCURRENT=2` is realistic on a 64 GB host **only for Raider ranges**. It is NOT valid for two
concurrent capstones - the earlier model's claim that a 64 GB host supports two capstones was wrong.
Two concurrent capstones need roughly a **96-128 GB** host. For a single 64 GB host, either run one
capstone at a time (an effective per-host cap of 1 for board 6), or size up. The control
(`MAX_CONCURRENT_RANGES`) must be set per the host RAM and the board mix actually running, and the host
must refuse to over-commit; the counter alone does not create RAM that is not there.

The §16 suspend-on-reclaim behaviour keeps RAM demand at or below the real cap even when more
candidates are mid-assessment than the cap: only actively-worked ranges stay powered on; idle ones
suspend (power-off) and free their RAM while preserving disk + evidence for the 72h window.

Throughput, not instantaneous capacity, is the real constraint. A single host serves a cohort serially:
a candidate deploys, works, is suspended when idle, resumes on return; anyone over the cap queues
(`queued_slot`) until a slot frees - surfaced to the candidate, never an over-subscription.

## 3. Projected monthly cost (estimates)

| Component | Host (estimate) | Est. $/mo |
|---|---|---|
| GOAD/Ludus host, ~64 GB (holds 2 concurrent Raider OR 1 capstone) | Hetzner dedicated (EX/AX class) | $45-60 |
| Snapshots / extra volumes / egress for the ranges | Hetzner | $3-10 |
| **S6 range subtotal** | | **~$50-70/mo** |

Combined with the control plane and shared SIEM covered elsewhere (~$20-50/mo together), the whole
platform baseline is **well inside the $300/mo target**, with headroom. The dominant and most variable
cost is the GOAD host. The most likely overage trigger is needing **concurrent capstones** or serving
a larger cohort: because one 64 GB host holds only a single capstone (see section 2), two concurrent
capstones require either a **~96-128 GB host** or a **second host**. Either step roughly doubles the
range subtotal to ~$100-130/mo - still inside $300/mo, but surfaced for approval before being added,
never provisioned automatically. A single 64 GB host with board 6 effectively capped at one concurrent
capstone needs no extra spend; it just serializes capstone candidates (throughput, not a cost).

## 4. Honest trade-offs

- **No scale-to-zero for an active range.** A powered-off Proxmox VM still occupies disk and is still
  billed on a dedicated host; only destroy frees everything. "Suspend" (§16) saves RAM, not the host
  bill. The host is the fixed cost; ranges are the variable RAM/disk load on it.
- **Suspend/resume preserves evidence at a disk cost.** Holding suspended ranges for the 72h evidence
  window trades disk (cheap) for the guarantee that a candidate's evidence survives reclamation. If a
  cohort submits faster than ranges age out, suspended-range disk can accumulate; the age cap and the
  bounded hold window keep this finite, and destroy reclaims disk once the window closes.
- **Capacity vs cost is one dial, and the counter is not RAM.** `MAX_CONCURRENT_RANGES` must be set to
  what the host's schedulable RAM genuinely holds for the board mix running (2 Raider or 1 capstone on
  a 64 GB host), and the host must refuse over-commit. Setting the counter higher than the RAM supports
  does not create capacity; it would oversubscribe. Real additional capacity means a bigger or second
  host and another ~$50-70/mo.
- **Rebuild is expensive, resume is cheap.** A rebuild (destroy + deploy) re-runs the full GOAD
  provisioning (tens of minutes of host CPU); resume (power-on) is seconds. The lifecycle prefers
  resume for a returning candidate precisely to avoid paying rebuild cost (and to preserve evidence).

## 5. Unverified

Range VM counts, RAM/disk footprints, deploy/resume timings, and therefore the RAM-hours math are
estimates pending a live Ludus/Proxmox host (category D). Provider list prices are current estimates to
confirm at stand-up. This model gates no spend by itself; actual provisioning, host sizing, and any
second-host overage require explicit approval under the $300/mo budget.
