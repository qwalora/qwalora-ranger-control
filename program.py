"""Qwalora Ranger program plan: the six boards, their roles, badges, and tiers.

This is the single source of truth for the SOC-to-capstone progression. The
promotion engine reads it; changing a board's role, badge, or tier is a one-line
edit here. Scale does not touch this file: 10 or 1000 candidates run the same
six-board ladder.

Tier decides the resource cost:
  shared    - many candidates share one instrumented environment (cheap). The
              per-candidate dataset is seeded so answers differ per ranger.
  isolated  - one Ludus range per candidate (RAM-bound). Counts against the
              host concurrency cap.
"""

PASS_BAR = 95.0  # objective score (0..100) a board requires

# board number -> metadata. Badge names are the rank earned by CLEARING that board.
BOARD_PLAN = [
    {"n": 1, "role": "soc-analyst",         "badge": "Sentinel",  "tier": "shared",   "template": "soc-triage"},
    {"n": 2, "role": "threat-hunter",       "badge": "Tracker",   "tier": "shared",   "template": "threat-hunt"},
    {"n": 3, "role": "detection-engineer",  "badge": "Warden",    "tier": "shared",   "template": "detection"},
    {"n": 4, "role": "incident-responder",  "badge": "Reclaimer", "tier": "shared",   "template": "ir-forensics"},
    {"n": 5, "role": "red-teamer",          "badge": "Raider",    "tier": "isolated", "template": "goad"},
    {"n": 6, "role": "capstone",            "badge": "Vanguard",  "tier": "isolated", "template": "goad-capstone"},
]
LAST_BOARD = BOARD_PLAN[-1]["n"]

CERTIFIED = {"level": "certified", "name": "Qwalora Ranger", "role": "graduate"}

# Phase 1 defensive core: boards 1-4 (SOC triage, enterprise hunt, detection, IR).
# Clearing all four earns a real, standalone intermediate credential. Phase 2 (the
# isolated GOAD capstone, boards 5-6) is the remaining path to the full Ranger cert.
DEFENSIVE_CORE = (1, 2, 3, 4)
PHASE2_BOARDS = (5, 6)
# Intermediate credential minted on clearing the last defensive-core board (4). It
# certifies the blue-team core on its own; a candidate can earn and verify it before
# the Phase 2 capstone exists for them.
STRATA_DEFENDER = {"level": "defender", "name": "Qwalora STRATA Defender",
                   "role": "strata-defender", "at_board": DEFENSIVE_CORE[-1]}
MILESTONES = [STRATA_DEFENDER]


def milestone_for_board(n):
    """The intermediate credential earned by CLEARING board n, or None. The ladder is
    sequential, so clearing board 4 means boards 1-4 are all cleared."""
    return next((m for m in MILESTONES if int(m["at_board"]) == int(n)), None)


def is_phase2(n):
    return int(n) in PHASE2_BOARDS


_BY_N = {b["n"]: b for b in BOARD_PLAN}
ROLES = [b["role"] for b in BOARD_PLAN]
ROLE_TITLES = {
    "soc-analyst": "SOC Analyst", "threat-hunter": "Threat Hunter",
    "detection-engineer": "Detection Engineer", "incident-responder": "Incident Responder",
    "red-teamer": "Red Teamer", "capstone": "Capstone",
    "strata-defender": "STRATA Defender", "graduate": "Qwalora Ranger",
}


def board_meta(n):
    return _BY_N.get(int(n))


def role_of(n):
    m = board_meta(n)
    return m["role"] if m else None


def badge_for(n):
    m = board_meta(n)
    return (str(n), m["badge"], m["role"]) if m else None


def tier_of(n):
    m = board_meta(n)
    return m["tier"] if m else None


def is_isolated(n):
    return tier_of(n) == "isolated"


def template_of(n):
    m = board_meta(n)
    return m["template"] if m else None


def bstr(n):
    """int board number -> the 'boardN' string the Report model uses."""
    return f"board{int(n)}"


def bint(s):
    """'boardN' -> int N (or None)."""
    try:
        return int(str(s).replace("board", ""))
    except (ValueError, TypeError):
        return None
