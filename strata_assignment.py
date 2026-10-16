"""S3/S4 - controlled, randomized candidate scenario assignment.

The assignment model is: approved scenario portfolio -> cohort-specific selection -> candidate-specific
qualification instance. It is the runtime half of the cohort-aware system (strata_catalog is the
governance half).

Guarantees:
  * Only APPROVED, calibrated, eligible catalog entries are selectable (strata_catalog.eligible).
  * Selection among eligible variants uses CRYPTOGRAPHICALLY SECURE randomness (secrets), so a
    candidate's variant is unpredictable beforehand.
  * The binding is durable (models.ScenarioBinding): selected spec_id, spec_version, immutable
    content_hash, structural variant, incident family and a per-candidate seed are stored.
  * Idempotent + concurrency-safe: one binding per (candidate, board, attempt); a race loses to the
    UNIQUE constraint and re-reads the winner.
  * No-repeat: a returning candidate never repeats a previously bound variant where alternatives
    exist; scenario-family reuse has a cooldown.
  * Exhaustion is EXPLICIT: when no eligible, non-repeat variant remains, assignment raises
    AssignmentExhausted. It NEVER silently falls back to a generic scenario in qualification.
  * Version-pinned + reproducible: generation and grading use the pinned (variant, seed); an existing
    binding stays reproducible even after new catalog versions are published.
  * The selected scenario does not change during an active case (the binding is immutable once made).

Operational SOC collaboration (the /soc gateway) is a separate surface; a ScenarioBinding is a
graded qualification instance, not an operational session.
"""
from __future__ import annotations

import secrets

import scenarios as sc
import strata_catalog as cat
from siem import board_variants as bv
from siem import enterprise

FAMILY_COOLDOWN = 1   # a person will not get the same family within this many of their recent bindings


class AssignmentError(RuntimeError):
    pass


class AssignmentExhausted(AssignmentError):
    """No eligible, non-repeat variant remains for this candidate. Explicit, never a silent generic
    fallback in a qualification workflow."""


_csprng = secrets.SystemRandom()


def set_cohort_portfolio(db, cohort, board, variant_ids, *, coverage=None, difficulty=None):
    """Persist a cohort's approved portfolio for a board (the admin-declared set of variants a cohort
    draws from). Stored on models.CohortScenarioPlan (notes holds the variant list). This is what
    makes two cohorts receive different approved portfolios."""
    import json as _j
    from models import CohortScenarioPlan
    row = CohortScenarioPlan.query.filter_by(cohort=cohort, board=int(board)).first()
    if row is None:
        row = CohortScenarioPlan(cohort=cohort, board=int(board))
        db.session.add(row)
    row.variant = (variant_ids[0][:40] if variant_ids else None)
    row.notes = _j.dumps({"portfolio": list(variant_ids)})
    if coverage:
        row.coverage = coverage[:400]
    if difficulty:
        row.difficulty = difficulty
    db.session.commit()
    return row


def cohort_portfolio(db, cohort, board):
    """The cohort's declared portfolio for a board (list of variant ids), or None (= all eligible)."""
    import json as _j
    from models import CohortScenarioPlan
    row = CohortScenarioPlan.query.filter_by(cohort=cohort, board=int(board)).first()
    if not row or not row.notes:
        return None
    try:
        pf = _j.loads(row.notes).get("portfolio")
        return pf or None
    except Exception:  # noqa: BLE001
        return None


def _eligible_variants(db, board, portfolio=None):
    """Approved+eligible variant ids for a board, optionally restricted to a cohort PORTFOLIO. A
    portfolio entry that is not eligible is rejected (never assigned)."""
    elig = {cat.entry_variant(e): e for e in cat.eligible(db, board)}
    if portfolio is not None:
        bad = [v for v in portfolio if v not in elig]
        if bad:
            raise AssignmentError(f"portfolio references non-eligible variants: {bad}")
        return {v: elig[v] for v in portfolio}
    return elig


def _prior_bindings(db, github_id, board):
    from models import ScenarioBinding
    return (ScenarioBinding.query.filter_by(github_id=github_id, board=board)
            .order_by(ScenarioBinding.id.desc()).all())


def _select(db, candidate, board, portfolio):
    """Pick an eligible catalog entry for this candidate: exclude previously bound variants
    (no-repeat) and recently used families (cooldown), then choose with CSPRNG. Raises
    AssignmentExhausted when nothing eligible remains."""
    gid = candidate.github_id or candidate.handle
    elig = _eligible_variants(db, board, portfolio)
    if not elig:
        raise AssignmentExhausted(f"no approved eligible scenarios for board {board}")
    prior = _prior_bindings(db, gid, board)
    used_variants = {b.variant_id for b in prior}
    recent_families = {b.family for b in prior[:FAMILY_COOLDOWN]}

    pool = {v: e for v, e in elig.items() if v not in used_variants}
    if not pool:
        raise AssignmentExhausted(
            f"candidate {gid} has completed every eligible board-{board} variant; "
            f"author/approve a new variant (no silent generic fallback)")
    # prefer variants whose family is not in cooldown; fall back to the no-repeat pool if cooldown
    # would empty it (no-repeat is the hard rule, cooldown is a soft preference).
    cooled = {v: e for v, e in pool.items() if cat.entry_family(e) not in recent_families}
    choose_from = cooled or pool
    variant_id = _csprng.choice(sorted(choose_from))     # CSPRNG over a stable candidate list
    return variant_id, choose_from[variant_id]


def assign(db, candidate, board, *, cohort=None, attempt=1, portfolio=None):
    """Idempotently bind a candidate's qualification attempt to an approved scenario variant.
    Concurrency-safe via the ScenarioBinding UNIQUE(candidate, board, attempt) constraint."""
    from models import ScenarioBinding
    gid = candidate.github_id or candidate.handle
    cohort = cohort or candidate.cohort
    existing = ScenarioBinding.query.filter_by(candidate_id=candidate.id, board=board,
                                               attempt=attempt).first()
    if existing:
        return existing
    variant_id, entry = _select(db, candidate, board, portfolio)
    seed = secrets.token_hex(16)                         # CSPRNG, unique per attempt
    binding = ScenarioBinding(
        candidate_id=candidate.id, github_id=gid, board=board, cohort=cohort, attempt=attempt,
        spec_id=entry.spec_id, spec_version=entry.spec_version, content_hash=entry.content_hash,
        variant_id=variant_id, family=cat.entry_family(entry), seed=seed, status="bound")
    db.session.add(binding)
    try:
        db.session.commit()
    except Exception:                                    # a concurrent writer won the attempt
        db.session.rollback()
        won = ScenarioBinding.query.filter_by(candidate_id=candidate.id, board=board,
                                              attempt=attempt).first()
        if won:
            return won
        raise
    return binding


# ============================ generation + grading against the pinned binding ==============
def resolve(binding):
    """The pinned generation inputs for a binding: (board, variant_id, seed, gen_params). Uses the
    structural variant + seed, so it reproduces regardless of newer catalog versions."""
    board = binding.board
    gp = bv.gen_params(board, binding.variant_id)
    if gp is None:
        raise AssignmentError(f"bound variant {binding.variant_id} is unknown to the generator")
    return board, binding.variant_id, binding.seed, gp


def generate(binding, *, candidate_id=None):
    """Produce the scenario bound to this attempt. Boards 1/3/4 return the full scenario (hidden key
    for server-side grading); board 2 returns (events, truth) from the enterprise generator. The
    candidate-facing projection is via candidate_view()."""
    board, variant_id, seed, gp = resolve(binding)
    if board == 2:
        return enterprise.generate(candidate_id or binding.github_id, 2, seed,
                                   gp.get("profile", "B"), families=gp["families"])
    return {1: sc.generate_board1, 3: sc.generate_board3, 4: sc.generate_board4}[board](seed, gp)


def candidate_view(binding, scenario):
    """The candidate-facing projection (no hidden truth). For board 2 the candidate reads the live
    index; the 'scenario' there is (events, truth) and only events are candidate-visible."""
    board = binding.board
    if board == 2:
        events, _truth = scenario
        return {"board": 2, "events": events}
    return {1: sc.public_board1, 3: sc.public_board3, 4: sc.public_board4}[board](scenario)


def grade(binding, submission):
    """Grade a submission against the PINNED variant+seed (boards 1/3/4). Board 2 qualification is
    graded through its established signed-citation workflow (case_contract), not here."""
    board, variant_id, seed, gp = resolve(binding)
    if board == 2:
        raise AssignmentError("board 2 qualification is graded via the signed-citation workflow "
                              "(case_contract), not the generic grader")
    scenario = {1: sc.generate_board1, 3: sc.generate_board3, 4: sc.generate_board4}[board](seed, gp)
    return {1: sc.score_board1, 3: sc.score_board3, 4: sc.score_board4}[board](scenario, submission)


def board2_truth(binding, *, candidate_id=None):
    """The hidden truth for a board-2 binding, for server-side grading only (never candidate-facing)."""
    _events, truth = generate(binding, candidate_id=candidate_id)
    return truth


def mark_completed(db, binding):
    binding.status = "completed"
    db.session.add(binding)
    db.session.commit()
    return binding
