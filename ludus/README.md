# Qwalora Ranger — Ludus configuration

This directory is the range side of the program: the Ludus range blueprints for
the isolated boards and the Ansible role that plants each ranger's flags. The
portal (this repo's Flask app) is the control plane; Ludus runs the ranges.

## How the two sides connect

Each ranger maps to exactly one Ludus **user**, which owns exactly one **range**
(isolated, per-ranger, reachable only over that user's WireGuard). When a ranger
starts an isolated board, the portal's broker calls Ludus:

1. `set_range_config(candidate, template, template_vars)` — selects the blueprint
   for the board and passes `template_vars.ranger_flags`, the candidate's
   per-seed flags (`scenarios.flags_for_board(board, seed)`).
2. `deploy_range(candidate)` — builds the range.
3. `wireguard_config(candidate)` — the config the ranger downloads from `/me`.

The board → blueprint map (from `program.py` `template_of`):

| Board | Role | `template` | Blueprint |
|------|------|-----------|-----------|
| 5 | Red Teamer (Raider) | `goad` | `goad-range.yml` |
| 6 | Capstone (Vanguard) | `goad-capstone` | `capstone-range.yml` |

The flags the portal sends are the **same** values its grader re-derives from the
seed, so the planted flag and the expected flag always agree. The portal never
depends on Ludus to grade; Ludus only has to plant what it is given.

## One-time Ludus server setup

```bash
# 1. Install Ludus (see https://docs.ludus.cloud). Then, as the Ludus admin:
# 2. Add the GOAD role (deploys Game of Active Directory) and our flag role.
ludus ansible role add badsectorlabs.ludus_goad
ludus ansible role add -d ./roles/qwalora_flags qwalora.flags

# 3. Pull the Windows/Kali templates GOAD needs (once; takes a while).
ludus templates build   # or: ludus templates list, then build the ones GOAD uses
```

Point the portal at the server by setting these on the portal service
(Railway → Variables), which flips the broker from mock to live:

```
LUDUS_API_URL=https://<your-ludus-host>:8080
LUDUS_API_KEY=<a Ludus admin API key>     # stored Fernet-encrypted at rest
LUDUS_VERIFY_TLS=1
```

With `LUDUS_API_URL` unset the broker stays in mock mode: the full
enroll → promote → deploy → WireGuard pipeline runs and is gradeable, no
hardware required. That is how boards 1-6 were built and tested.

## Per-ranger provisioning and capacity

A range is per-ranger, so a cohort of N rangers on the red boards needs N ranges.
The portal caps concurrent deploys per host (`MAX_CONCURRENT_RANGES`) and queues
the rest as `queued_slot`, reconciling when a slot frees. Size the Ludus host(s)
for the peak number of rangers you expect on boards 5-6 at once, not the whole
cohort. The cohort view's **By organization** panel shows, per org, how many
ranges are needed vs deployed right now, so you can watch an org's batch drain
through the queue. To add capacity, stand up another Ludus host and set the
range's `host` field; the slot accounting is per host.

## Sharing a range across an org? No.

Rangers from the same org are grouped for enrollment, progress and capacity
planning (see the org model), but they do **not** share a range on the red
boards. Each ranger's range is isolated and holds that ranger's own seed-bound
flags; a shared attack range would leak flags and let one member's actions
show up as another's. Grouping is organizational, not a shared environment. The
only shared environments in the program are the instrumented blue boards (1-4),
which are per-candidate datasets, not VMs.

## Files

- `goad-range.yml` — board 5 blueprint: the GOAD forest (`sevenkingdoms.local`
  + `north.sevenkingdoms.local`), with the `qwalora.flags` role planting the
  board-5 flags.
- `capstone-range.yml` — board 6 blueprint: the full multi-forest estate (adds
  the `essos.local` forest and its trust), planting the board-6 flags.
- `roles/qwalora_flags/` — the Ansible role that plants `ranger_flags` at the
  right location for each objective (see its README for the objective → location
  map).
