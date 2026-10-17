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

Sizing a single GOAD host to the capstone footprint (the larger of the two): a **~64 GB** host holds
~2 concurrent capstone ranges (or more Raider ranges), which matches `MAX_CONCURRENT=2`. The §16
suspend-on-reclaim behaviour is what keeps RAM demand at or below the cap even when more candidates
are mid-assessment than the cap: only actively-worked ranges stay powered on; idle ones suspend and
free their slot while preserving evidence for the 72h window.

Throughput, not just instantaneous capacity, is the real constraint. With a 2-range cap and ranges
that are suspended after 8h idle, a single host serves a cohort serially: a candidate deploys, works,
is suspended when idle, resumes on return. A cohort larger than ~2 simultaneously-active red-teamers
queues (`queued_slot`) until a slot frees - correct behaviour, surfaced to the candidate, never an
oversubscription.

## 3. Projected monthly cost (estimates)

| Component | Host (estimate) | Est. $/mo |
|---|---|---|
| GOAD/Ludus host, ~64 GB, hosts ~2 concurrent GOAD at `MAX_CONCURRENT=2` | Hetzner dedicated (EX/AX class) | $45-60 |
| Snapshots / extra volumes / egress for the ranges | Hetzner | $3-10 |
| **S6 range subtotal** | | **~$50-70/mo** |

Combined with the control plane and shared SIEM covered elsewhere (~$20-50/mo together), the whole
platform baseline is **well inside the $300/mo target**, with headroom. The dominant and most variable
cost is the GOAD host; a **second GOAD host** (to raise concurrent capacity beyond ~2 capstone ranges
for a larger cohort) is the most likely overage trigger and would roughly double the range subtotal to
~$100-130/mo - still inside $300/mo, but it is surfaced for approval before being added rather than
provisioned automatically.

## 4. Honest trade-offs

- **No scale-to-zero for an active range.** A powered-off Proxmox VM still occupies disk and is still
  billed on a dedicated host; only destroy frees everything. "Suspend" (§16) saves RAM, not the host
  bill. The host is the fixed cost; ranges are the variable RAM/disk load on it.
- **Suspend/resume preserves evidence at a disk cost.** Holding suspended ranges for the 72h evidence
  window trades disk (cheap) for the guarantee that a candidate's evidence survives reclamation. If a
  cohort submits faster than ranges age out, suspended-range disk can accumulate; the age cap and the
  bounded hold window keep this finite, and destroy reclaims disk once the window closes.
- **Capacity vs cost is one dial.** Raising `MAX_CONCURRENT` beyond what one host's RAM supports would
  oversubscribe and is refused by the host sizing, not just the counter; real additional capacity means
  another host and another ~$50-70/mo.
- **Rebuild is expensive, resume is cheap.** A rebuild (destroy + deploy) re-runs the full GOAD
  provisioning (tens of minutes of host CPU); resume (power-on) is seconds. The lifecycle prefers
  resume for a returning candidate precisely to avoid paying rebuild cost (and to preserve evidence).

## 5. Unverified

Range VM counts, RAM/disk footprints, deploy/resume timings, and therefore the RAM-hours math are
estimates pending a live Ludus/Proxmox host (category D). Provider list prices are current estimates to
confirm at stand-up. This model gates no spend by itself; actual provisioning, host sizing, and any
second-host overage require explicit approval under the $300/mo budget.
