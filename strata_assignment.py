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

import json
import secrets

import scenarios as sc
import strata_catalog as cat
from siem import board_variants as bv
from siem import enterprise
from siem import schema as _schema

FAMILY_COOLDOWN = 1   # a person will not get the same family within this many of their recent bindings


class AssignmentError(RuntimeError):
    pass


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _gen_hash(contract: dict) -> str:
    """Integrity MAC over the pinned generation contract. This is a KEYED HMAC (under the server
    secret), not a bare SHA-256: a bare digest only detects ACCIDENTAL change, because a privileged
    database writer who can alter the stored contract can also recompute and store a matching plain
    digest. A keyed MAC is tamper-EVIDENT against such a writer - they cannot forge a valid MAC for
    an altered contract without the server secret. (If the server secret itself is compromised the
    guarantee degrades; that is a broader-compromise case documented in the threat model.)"""
    return _schema.keyed_mac(_canonical(contract).encode("utf-8"))


def _build_contract(entry, board, variant_id):
    """The immutable generation contract pinned on a binding at assignment time. It captures the
    EXACT generation inputs (gen_params) plus the approved spec identity, so replay reproduces the
    original world regardless of later edits to the live variant code."""
    gp = bv.gen_params(board, variant_id)
    if gp is None:
        raise AssignmentError(f"variant {board}/{variant_id} is unknown to the generator")
    contract = {
        "board": int(board),
        "variant_id": variant_id,
        "spec_id": entry.spec_id,
        "spec_version": int(entry.spec_version),
        "content_hash": entry.content_hash,
        "gen_params": gp,
    }
    return contract, _gen_hash(contract)


class AssignmentExhausted(AssignmentError):
    """No eligible, non-repeat variant remains for this candidate. Explicit, never a silent generic
    fallback in a qualification workflow."""


_csprng = secrets.SystemRandom()


def set_cohort_portfolio(db, cohort, board, variant_ids, *, admin=None, coverage=None,
                         difficulty=None):
    """Persist a cohort's approved portfolio for a board under authenticated admin authorization.

    Gap 4/6 corrections:
      * Requires a real authorized administrator (strata_catalog._is_authorized_admin); a bare string
        or an unauthenticated caller is refused.
      * Validates the portfolio up front: a non-empty list whose every entry is an APPROVED, eligible
        catalog variant for THIS board. A cross-board, unknown, revoked or unapproved id is rejected
        here so a bad portfolio can never be stored, let alone assigned.
      * Stores the portfolio in the DEDICATED CohortScenarioPlan.portfolio_json column, so the admin
        `notes`, `coverage`, `difficulty` and `variant` metadata are never clobbered (only updated
        when explicitly provided)."""
    import datetime as _dt
    from models import CohortScenarioPlan
    ok, who = cat._is_authorized_admin(admin)
    if not ok:
        raise AssignmentError("setting a cohort portfolio requires an authenticated authorized "
                              "administrator (AdminUser); a bare string is not accepted")
    vids = list(variant_ids or [])
    if not vids:
        raise AssignmentError("a cohort portfolio must list at least one approved variant")
    if len(set(vids)) != len(vids):
        raise AssignmentError(f"cohort portfolio has duplicate variants: {vids}")
    elig = {cat.entry_variant(e): e for e in cat.eligible(db, board)}
    bad = [v for v in vids if v not in elig]
    if bad:
        raise AssignmentError(f"portfolio references variants that are not approved+eligible for "
                              f"board {board}: {bad}")
    row = CohortScenarioPlan.query.filter_by(cohort=cohort, board=int(board)).first()
    if row is None:
        row = CohortScenarioPlan(cohort=cohort, board=int(board))
        db.session.add(row)
    row.portfolio_json = json.dumps({
        "portfolio": vids, "set_by": who,
        "set_at": _dt.datetime.now(_dt.timezone.utc).isoformat()})
    if coverage:
        row.coverage = coverage[:400]
    if difficulty:
        row.difficulty = difficulty
    db.session.commit()
    return row


def cohort_portfolio(db, cohort, board):
    """The cohort's stored portfolio for a board as a list of variant ids, or None when none is
    configured. Reads the DEDICATED portfolio_json column; a legacy value once stored in `notes` is
    also honored for backward compatibility but never written there anymore. Malformed stored JSON
    raises (fail-closed) rather than silently reading as 'no portfolio'."""
    from models import CohortScenarioPlan
    row = CohortScenarioPlan.query.filter_by(cohort=cohort, board=int(board)).first()
    if not row:
        return None
    raw = getattr(row, "portfolio_json", None)
    if not raw:
        # backward-compat: a portfolio written by an earlier build into notes
        legacy = (row.notes or "").strip()
        if legacy.startswith("{"):
            try:
                pf = json.loads(legacy).get("portfolio")
                return list(pf) if pf else None
            except (ValueError, TypeError):
                return None   # free-text admin notes, not a portfolio
        return None
    try:
        pf = json.loads(raw).get("portfolio")
    except (ValueError, TypeError) as e:
        raise AssignmentError(f"cohort {cohort} board {board} portfolio is malformed: {e}")
    if pf is None:
        return None
    if not isinstance(pf, list) or not all(isinstance(x, str) for x in pf):
        raise AssignmentError(f"cohort {cohort} board {board} portfolio is malformed (not a list of ids)")
    return pf or None


def resolve_portfolio(db, cohort, board, *, required):
    """Return the validated portfolio variant-id list for (cohort, board), or raise AssignmentError.

    Fail-closed: when `required` (cohort-aware qualification), a missing, empty or malformed portfolio
    is an explicit error - assignment NEVER silently expands to the whole eligible catalog. Every id
    listed must still be an approved+eligible variant for this board (a revoked/removed entry drops
    out and is rejected)."""
    pf = cohort_portfolio(db, cohort, board)   # raises on malformed
    if not pf:
        if required:
            raise AssignmentError(
                f"no approved cohort portfolio is configured for cohort {cohort!r} board {board}; "
                f"cohort-aware qualification requires an explicit approved portfolio (fail-closed)")
        return None
    elig = {cat.entry_variant(e) for e in cat.eligible(db, board)}
    bad = [v for v in pf if v not in elig]
    if bad:
        raise AssignmentError(
            f"cohort {cohort!r} board {board} portfolio references variants that are not "
            f"approved+eligible (revoked/unknown/unapproved): {bad}")
    return pf


def _eligible_variants(db, board, portfolio=None):
    """Approved+eligible variant ids for a board, optionally restricted to a cohort PORTFOLIO. A
    portfolio entry that is not eligible is rejected (never assigned). An EMPTY portfolio is rejected
    rather than treated as 'all eligible' (fail-closed)."""
    elig = {cat.entry_variant(e): e for e in cat.eligible(db, board)}
    if portfolio is not None:
        if not portfolio:
            raise AssignmentError("an empty cohort portfolio cannot be assigned (fail-closed)")
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


def assign(db, candidate, board, *, cohort=None, attempt=1, portfolio=None, require_portfolio=False):
    """Idempotently bind a candidate's qualification attempt to an approved scenario variant.
    Concurrency-safe via the ScenarioBinding UNIQUE(candidate, board, attempt) constraint.

    When `require_portfolio` (cohort-aware qualification), `portfolio` must be a non-empty validated
    list; a None/empty portfolio fails closed rather than selecting across the whole eligible
    catalog. The binding pins an immutable generation contract (gen_contract/gen_hash) so replay
    reproduces the original world even if the variant is later edited (Gap 5)."""
    from models import ScenarioBinding
    gid = candidate.github_id or candidate.handle
    cohort = cohort or candidate.cohort
    existing = ScenarioBinding.query.filter_by(candidate_id=candidate.id, board=board,
                                               attempt=attempt).first()
    if existing:
        return existing
    if require_portfolio and not portfolio:
        raise AssignmentError("cohort-aware assignment requires an explicit approved portfolio "
                              "(fail-closed); refusing to select across the whole catalog")
    variant_id, entry = _select(db, candidate, board, portfolio)
    seed = secrets.token_hex(16)                         # CSPRNG, unique per attempt
    contract, ghash = _build_contract(entry, board, variant_id)
    binding = ScenarioBinding(
        candidate_id=candidate.id, github_id=gid, board=board, cohort=cohort, attempt=attempt,
        spec_id=entry.spec_id, spec_version=entry.spec_version, content_hash=entry.content_hash,
        variant_id=variant_id, family=cat.entry_family(entry), seed=seed, status="bound",
        gen_contract=json.dumps(contract), gen_hash=ghash)
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
    """The pinned generation inputs for a binding: (board, variant_id, seed, gen_params).

    Real version pinning (Gap 5): generation inputs come from the IMMUTABLE contract snapshot stored
    on the binding, verified against its integrity hash, so an existing assignment reproduces its
    original world even after the live variant is edited or superseded. A tampered contract, or a
    legacy binding whose live spec no longer matches its pinned content_hash, FAILS CLOSED rather
    than silently generating a different investigation."""
    if binding.gen_contract:
        try:
            contract = json.loads(binding.gen_contract)
        except (ValueError, TypeError) as e:
            raise AssignmentError(f"binding {binding.id} has an unreadable pinned contract: {e}")
        if _gen_hash(contract) != (binding.gen_hash or ""):
            raise AssignmentError(f"binding {binding.id} pinned generation contract failed its "
                                  f"integrity check (tampered or corrupted); refusing to generate")
        if int(contract.get("board", -1)) != int(binding.board):
            raise AssignmentError(f"binding {binding.id} pinned contract board does not match binding")
        gp = contract["gen_params"]
        return binding.board, contract["variant_id"], binding.seed, gp
    # Legacy binding (no pinned contract): use the live variant, but only if the live spec still
    # hashes to the pinned content_hash. Any drift means the variant was edited/superseded, so we
    # fail closed instead of generating a world that differs from the one the candidate was graded on.
    board = binding.board
    gp = bv.gen_params(board, binding.variant_id)
    if gp is None:
        raise AssignmentError(f"bound variant {binding.variant_id} is unknown/unavailable; "
                              f"refusing to generate (fail-closed)")
    try:
        live_hash = cat.content_hash(cat.build_spec(board, binding.variant_id))
    except Exception as e:  # noqa: BLE001
        raise AssignmentError(f"cannot recompute the pinned spec for binding {binding.id}: {e}")
    if binding.content_hash and live_hash != binding.content_hash:
        raise AssignmentError(f"binding {binding.id} pins content_hash {binding.content_hash[:12]} "
                              f"but the live variant now hashes to {live_hash[:12]}; the scenario was "
                              f"edited or superseded. Refusing to generate a different world "
                              f"(fail-closed).")
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
    index; the 'scenario' there is (events, truth) and only events are candidate-visible - and those
    events are passed through a STRICT ALLOWLIST (siem.schema.project_candidate_events) so no
    server-only field (the opaque ref, candidate_id/provenance, any _malicious/_key/seed/truth) can
    reach the candidate, even if the generator's own denylist regresses."""
    board = binding.board
    if board == 2:
        from siem import schema as _schema
        events, _truth = scenario
        return {"board": 2, "events": _schema.project_candidate_events(events)}
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
