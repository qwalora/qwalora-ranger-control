"""Data model for the Qwalora Ranger control plane.

Three tables carry the whole launch surface:

  Candidate      - one row per enrolled ranger (identity + per-candidate token)
  Report         - a written submission (SOC triage write-up, IR reconstruction,
                   detection rationale, red-team narrative) awaiting human review
  RangeRequest   - a queued or provisioned Ludus range for a candidate

The control plane never grades code. Objective grading stays answer-free and
program-side (clone repo, re-measure, sign). This store holds the human-review
surface and the range-provisioning queue the Ludus broker drains.
"""
import datetime as _dt
import secrets

from flask_sqlalchemy import SQLAlchemy

import pathways

db = SQLAlchemy()


def _now():
    return _dt.datetime.now(_dt.timezone.utc)


def _token():
    return secrets.token_urlsafe(24)


def ensure_schema(db):
    """Add columns introduced after the first deploy, idempotently.

    create_all() creates missing tables but never alters existing ones, so a
    production DB that predates the Ludus-linkage columns needs these added.
    Portable across SQLite and Postgres: inspect existing columns, ALTER only
    what is missing. Safe to run on every boot.
    """
    from sqlalchemy import inspect as _inspect
    wanted = {
        "candidates": [
            ("github_id", "VARCHAR(64)"),
            ("org", "VARCHAR(120)"),
            ("ludus_user_id", "VARCHAR(64)"),
            ("ludus_key_enc", "TEXT"),
            ("status", "VARCHAR(20) DEFAULT 'active'"),
            ("current_board", "INTEGER DEFAULT 1"),
            ("board_role", "VARCHAR(40)"),  # maps to Candidate.current_role
            ("exited_at", "TIMESTAMP"),
            ("exit_reason", "VARCHAR(200)"),
        ],
        "cohorts": [
            # M4.3.1 pathway-awareness: existing cohorts default to the STRATA pathway
            # (stable id 'strata'), so backward compatibility holds (no grading/access
            # change). Any row persisted under the interim id 'cyber-ops' is normalized
            # to 'strata' at read time by pathways.normalize_pathway (non-destructive).
            ("pathway", "VARCHAR(20) DEFAULT 'strata'"),
            ("curriculum_version", "VARCHAR(20)"),
        ],
        "evidence_artifacts": [
            # F3 storage/provenance columns added after the F2 table shipped.
            ("object_key", "VARCHAR(128)"),
            ("storage_backend", "VARCHAR(20)"),
            ("scan_state", "VARCHAR(20) DEFAULT 'unscanned'"),
            ("transform", "VARCHAR(60)"),
            ("tool_version", "VARCHAR(60)"),
            ("retention_class", "VARCHAR(30) DEFAULT 'default'"),
        ],
        "custody_events": [
            # F4 correction (C): persist the exact record + timestamp + per-evidence sequence so
            # the chain re-verifies from the DB and truncation is detectable against a checkpoint.
            ("ts", "VARCHAR(40)"),
            ("seq", "INTEGER"),
            ("record_json", "TEXT"),
        ],
        "case_submissions": [
            # F5.1: workbench receipt kept distinct from STRATA's evidence_record/evidence_sig.
            ("wb_receipt", "TEXT"),
            ("wb_receipt_sig", "TEXT"),
            ("wb_receipt_version", "INTEGER"),
        ],
        "cases": [
            ("scenario_ref", "VARCHAR(60)"),   # F5.1: approved candidate-safe scenario metadata ref
            # S5: definitive binding association (additive; release-gated migration in docs/).
            ("binding_id", "INTEGER"),
            ("content_hash", "VARCHAR(64)"),
            ("variant_id", "VARCHAR(60)"),
        ],
        "cohort_scenario_plans": [
            # S3/S4: the cohort's approved portfolio, stored in a DEDICATED column so saving it never
            # clobbers the admin `notes`. Added after the table shipped; a deployed DB needs this
            # ALTER (applied idempotently here; it is also part of the release-gated migration).
            ("portfolio_json", "TEXT"),
        ],
        "scenario_bindings": [
            # S3/S4 real version pinning: immutable generation-contract snapshot + integrity hash.
            # scenario_bindings is itself an additive table (create_all makes it with these columns);
            # these entries keep ensure_schema correct if the table predates the pinning fields.
            ("gen_contract", "TEXT"),
            ("gen_hash", "VARCHAR(64)"),
        ],
        "range_requests": [
            ("template", "VARCHAR(60)"),
            ("wireguard_config", "TEXT"),
            ("last_checked_at", "TIMESTAMP"),
            ("deployed_at", "TIMESTAMP"),
            ("last_active_at", "TIMESTAMP"),
            ("board", "INTEGER"),
            ("host", "VARCHAR(60) DEFAULT 'primary'"),
        ],
        "badges": [
            # Human-typeable public lookup key, minted on the certified badge.
            ("cert_id", "VARCHAR(40)"),
        ],
        "resources": [
            # Richer catalog metadata added after the first resources deploy.
            ("slug", "VARCHAR(90)"),
            ("category", "VARCHAR(40)"),
            ("level", "VARCHAR(20)"),
            ("publisher", "VARCHAR(160)"),
            ("prereqs", "VARCHAR(400)"),
            ("image", "VARCHAR(300)"),
            ("source_attribution", "VARCHAR(300)"),
            ("last_reviewed", "DATE"),
            # Original-research publication fields (QR-RES-* portfolio).
            ("pub_id", "VARCHAR(40)"),
            ("maturity", "VARCHAR(30)"),
            ("pub_type", "VARCHAR(40)"),
            ("collection", "VARCHAR(80)"),
            ("version", "VARCHAR(20)"),
            ("verification", "TEXT"),
            ("artifacts", "TEXT"),
            ("refs", "TEXT"),
            ("related", "VARCHAR(200)"),
            ("track", "VARCHAR(30)"),
        ],
    }
    insp = _inspect(db.engine)
    existing_tables = set(insp.get_table_names())
    for table, cols in wanted.items():
        if table not in existing_tables:
            continue  # create_all will have made it with the full schema
        have = {c["name"] for c in insp.get_columns(table)}
        for name, ddl in cols:
            if name in have:
                continue
            # Two gunicorn workers can race this ALTER on first boot; the loser
            # sees "already exists". Swallow per-column so boot never crash-loops.
            # Quote the identifier so reserved words (e.g. current_role in
            # Postgres) are added correctly rather than silently failing.
            try:
                db.session.execute(db.text(f'ALTER TABLE {table} ADD COLUMN "{name}" {ddl}'))
                db.session.commit()
            except Exception:
                db.session.rollback()
    # Widen resources.summary (was VARCHAR(400)) to hold 70-120 word editorial
    # descriptions. Postgres enforces length; SQLite does not, so this is a
    # Postgres-only concern and is swallowed where unsupported.
    if "resources" in existing_tables:
        try:
            dialect = db.engine.dialect.name
            if dialect == "postgresql":
                db.session.execute(db.text(
                    'ALTER TABLE resources ALTER COLUMN summary TYPE VARCHAR(900)'))
                db.session.commit()
        except Exception:
            db.session.rollback()

    # Pathway normalization at startup is DETECTION-ONLY by default (no writes). An
    # ordinary boot must not silently modify production records; writing on every start
    # is a repeatable, uncontrolled mutation. The actual remap is a versioned, explicitly
    # authorized one-shot migration (RANGER_PATHWAY_MIGRATE=1 or `python migrate_pathways.py`),
    # run under its own transaction with rollback. See normalize_persisted_pathways.
    startup_pathway_check(db, existing_tables)


_PATHWAY_TABLES = ("cohorts", "scenario_catalog_entries")


def detect_legacy_pathways(db, existing_tables=None):
    """Read-only. Return {table: count_of_legacy_rows} for rows still under an interim
    pathway id ('cyber-ops'/'cyber-ai'). Performs NO writes, so it is safe on every boot
    and against production. Portable across SQLite and PostgreSQL."""
    from sqlalchemy import inspect as _inspect
    if existing_tables is None:
        existing_tables = set(_inspect(db.engine).get_table_names())
    legacy_ids = list(pathways.LEGACY_PATHWAY_ALIASES.keys())
    out = {}
    for table in _PATHWAY_TABLES:
        if table not in existing_tables:
            continue
        try:
            rows = db.session.execute(
                db.text(f"SELECT COUNT(*) FROM {table} "
                        f"WHERE pathway IN :legacy").bindparams(
                            db.bindparam("legacy", expanding=True)),
                {"legacy": legacy_ids}).scalar()
            out[table] = int(rows or 0)
        except Exception:
            db.session.rollback()
    return out


def startup_pathway_check(db, existing_tables=None):
    """Called on every boot. Detects legacy pathway values WITHOUT writing. Only when the
    operator explicitly authorizes it (env RANGER_PATHWAY_MIGRATE truthy) does it run the
    one-shot migration; otherwise it leaves records untouched and returns the detection
    result so boot code can log a warning. Never crash-loops the app."""
    import logging
    import os as _os
    try:
        found = detect_legacy_pathways(db, existing_tables)
    except Exception:
        db.session.rollback()
        return {"detected": {}, "migrated": None}
    total = sum(found.values())
    authorized = str(_os.environ.get("RANGER_PATHWAY_MIGRATE", "")).strip().lower() in ("1", "true", "yes")
    if total and not authorized:
        logging.getLogger("ranger").warning(
            "legacy pathway values present (%s); startup is detection-only. Run the "
            "authorized migration (RANGER_PATHWAY_MIGRATE=1 or migrate_pathways.py).", found)
        return {"detected": found, "migrated": None}
    if total and authorized:
        migrated = normalize_persisted_pathways(db, existing_tables)
        logging.getLogger("ranger").warning("authorized pathway migration applied: %s", migrated)
        return {"detected": found, "migrated": migrated}
    return {"detected": found, "migrated": {}}


def normalize_persisted_pathways(db, existing_tables=None):
    """Versioned, non-destructive pathway migration. Remaps legacy interim ids
    ('cyber-ops'->'strata', 'cyber-ai'->'parallax') to canonical ids across EVERY table
    that persists a `pathway` column, in a SINGLE migration-wide transaction: all tables
    migrate or none (a failure on the second table rolls back the first). Idempotent (a
    second run updates 0 rows) and value-only (no DROP/ALTER; genuine rows untouched).
    Returns {table: rows_updated}; on failure returns zeros for all tables.

    Migration-wide atomicity (not per-table) is deliberate: the canonical-id invariant must
    hold across cohorts AND catalog entries together, so a cohort is never left referencing
    a pathway id its catalog no longer uses. This is NOT called on ordinary startup; it runs
    only under explicit authorization (startup_pathway_check with RANGER_PATHWAY_MIGRATE, or
    migrate_pathways.py)."""
    from sqlalchemy import inspect as _inspect
    if existing_tables is None:
        existing_tables = set(_inspect(db.engine).get_table_names())
    tables = [t for t in _PATHWAY_TABLES if t in existing_tables]
    counts = {t: 0 for t in tables}
    try:
        for table in tables:
            for legacy, canonical in pathways.LEGACY_PATHWAY_ALIASES.items():
                res = db.session.execute(
                    db.text(f"UPDATE {table} SET pathway = :canon WHERE pathway = :legacy"),
                    {"canon": canonical, "legacy": legacy})
                counts[table] += (res.rowcount or 0)
        db.session.commit()                # ONE transaction for all tables: all or nothing
    except Exception:
        db.session.rollback()              # rollback leaves EVERY table exactly as it was
        return {t: 0 for t in tables}
    return counts


class Candidate(db.Model):
    __tablename__ = "candidates"
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(120), unique=True, nullable=False, index=True)  # github login
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    cohort = db.Column(db.String(40), nullable=False, index=True)
    # Organization / group: an optional grouping of rangers who belong together
    # (same employer, same sponsored batch). Orthogonal to cohort: an org can
    # span cohorts and a cohort can hold several orgs. Used for batch enrollment,
    # group-level progress and range-capacity planning.
    org = db.Column(db.String(120), nullable=True, index=True)
    repo = db.Column(db.String(200), nullable=True)  # owner/name of their fork, optional at enroll
    token = db.Column(db.String(64), nullable=False, default=_token)  # report-submission secret
    # Person identity: the immutable GitHub numeric user id (a handle can be renamed).
    # Returning-student detection and scenario uniqueness key on this, not the handle.
    # Until GitHub OAuth lands, this is seeded from the handle at enroll.
    github_id = db.Column(db.String(64), nullable=True, index=True)
    # Ludus linkage: one candidate maps to exactly one Ludus user, which owns one range.
    ludus_user_id = db.Column(db.String(64), nullable=True)   # Ludus userID
    ludus_key_enc = db.Column(db.Text, nullable=True)         # Fernet-encrypted Ludus user API key
    # Lifecycle: pending -> active -> graduated | withdrawn | washed_out, plus
    # pending -> rejected. A candidate is "pending" from application until an
    # admin approves (then "active") or declines (then "rejected"). No board and
    # no environment are provisioned until approval. The column default stays
    # "active" so seeded/demo rows and tests are unaffected; the two real
    # application paths (enroll, GitHub sign-in) set "pending" explicitly.
    status = db.Column(db.String(20), nullable=False, default="active", index=True)
    current_board = db.Column(db.Integer, nullable=False, default=1)   # 1..6, the board they're on
    # DB column is "board_role": current_role is a reserved keyword in Postgres.
    current_role = db.Column("board_role", db.String(40), nullable=True)  # role of the current board
    exited_at = db.Column(db.DateTime(timezone=True), nullable=True)
    exit_reason = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)

    reports = db.relationship("Report", backref="candidate", lazy=True,
                              cascade="all, delete-orphan")
    range_requests = db.relationship("RangeRequest", backref="candidate", lazy=True,
                                     cascade="all, delete-orphan")
    board_results = db.relationship("BoardResult", backref="candidate", lazy=True,
                                    cascade="all, delete-orphan")
    badges = db.relationship("Badge", backref="candidate", lazy=True,
                             cascade="all, delete-orphan")

    # Terminal states: no further progression, no environment.
    TERMINAL = ("graduated", "withdrawn", "washed_out", "rejected")
    # In-flight: enrolled and not yet terminal. A cohort completes only when none
    # of its candidates are in-flight (so a cohort of only-pending rangers, or a
    # cohort mid-review, is never auto-completed).
    IN_FLIGHT = ("pending", "active")

    @property
    def is_active(self):
        return self.status == "active"

    @property
    def is_pending(self):
        return self.status == "pending"

    def roster_entry(self):
        return {"handle": self.handle, "name": self.name,
                "repo": self.repo or f"qwalora/{self.handle}",
                "org": self.org, "status": self.status, "board": self.current_board}


class Report(db.Model):
    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    board = db.Column(db.String(40), nullable=False)   # board1..board6
    role = db.Column(db.String(40), nullable=False)    # red-teamer / detection-engineer / soc-analyst / incident-responder
    body = db.Column(db.Text, nullable=False)          # the written analysis (markdown)
    status = db.Column(db.String(20), nullable=False, default="pending", index=True)  # pending/approved/rejected
    reviewer_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)


class RangeRequest(db.Model):
    __tablename__ = "range_requests"
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    # Lifecycle: configured -> deploying -> deployed -> destroyed  (or failed at any step).
    # Legacy "queued" rows are treated as "configured".
    # configured -> queued_slot -> deploying -> deployed -> destroyed (or failed).
    # queued_slot means the concurrency cap is full; a reconcile promotes it when a slot frees.
    status = db.Column(db.String(20), nullable=False, default="configured", index=True)
    template = db.Column(db.String(60), nullable=True, default="goad")  # range config template
    board = db.Column(db.Integer, nullable=True)       # board this range serves
    host = db.Column(db.String(60), nullable=True, default="primary")  # which Ludus host
    ludus_range_id = db.Column(db.String(120), nullable=True)
    wireguard_config = db.Column(db.Text, nullable=True)  # per-candidate WG config to reach the range
    detail = db.Column(db.Text, nullable=True)         # broker message / error
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    last_checked_at = db.Column(db.DateTime(timezone=True), nullable=True)  # last status poll
    deployed_at = db.Column(db.DateTime(timezone=True), nullable=True)      # when it went deployed (TTL base)
    last_active_at = db.Column(db.DateTime(timezone=True), nullable=True)   # last candidate touch (idle base)
    updated_at = db.Column(db.DateTime(timezone=True), default=_now, onupdate=_now)

    ACTIVE = ("configured", "queued_slot", "deploying", "deployed")
    # States that consume a host RAM slot (count against the concurrency cap).
    OCCUPIES_SLOT = ("deploying", "deployed")

    @property
    def is_deployed(self):
        return self.status == "deployed"


class BoardResult(db.Model):
    """One row per (candidate, board): the two grade channels and the signed clearance."""
    __tablename__ = "board_results"
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    board = db.Column(db.Integer, nullable=False, index=True)   # 1..6
    role = db.Column(db.String(40), nullable=True)
    # Objective channel (from GitHub Actions, answer-free, signed CI result).
    objective_score = db.Column(db.Float, nullable=True)        # 0..100
    objective_passed = db.Column(db.Boolean, nullable=False, default=False)
    objective_sig = db.Column(db.Text, nullable=True)           # signed CI attestation
    # Subjective channel (human report review).
    report_id = db.Column(db.Integer, db.ForeignKey("reports.id"), nullable=True)
    report_status = db.Column(db.String(20), nullable=True)
    # Clearance.
    cleared = db.Column(db.Boolean, nullable=False, default=False, index=True)
    cleared_at = db.Column(db.DateTime(timezone=True), nullable=True)
    signature = db.Column(db.Text, nullable=True)               # Ed25519 over the clearance
    updated_at = db.Column(db.DateTime(timezone=True), default=_now, onupdate=_now)

    __table_args__ = (db.UniqueConstraint("candidate_id", "board", name="uq_board_per_candidate"),)


class ScenarioAssignment(db.Model):
    """Lifetime ledger of every scenario seed ever given to a person (github_id),
    spanning cohorts. Guarantees a returning ranger never repeats a scenario:
    assignment excludes seeds already recorded for that (github_id, board).

    The seed is the reproducibility key: a board's scenario generator is a pure
    function of the seed, so the same seed reproduces the same world and answer
    key (for grading), and a never-before-used seed is a never-before-seen world.
    """
    __tablename__ = "scenario_assignments"
    id = db.Column(db.Integer, primary_key=True)
    github_id = db.Column(db.String(64), nullable=False, index=True)  # person key
    board = db.Column(db.Integer, nullable=False, index=True)
    cohort = db.Column(db.String(40), nullable=False)
    seed = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)

    __table_args__ = (db.UniqueConstraint("github_id", "board", "seed",
                                          name="uq_seed_per_person_board"),)


class Cohort(db.Model):
    """A run of the program. Cohorts are first-class so several can exist at
    once and advance in sequence: exactly one is 'active' (new enrollees land
    there), and when it completes the next 'scheduled' one activates on its own.
    The board plan, scenarios and Ludus blueprints are cohort-agnostic, so a new
    cohort is just a row, no rebuild."""
    __tablename__ = "cohorts"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False, index=True)  # e.g. 2026-A
    sequence = db.Column(db.Integer, nullable=False, default=0)   # order for auto-advance
    status = db.Column(db.String(20), nullable=False, default="scheduled", index=True)
    start_at = db.Column(db.DateTime(timezone=True), nullable=True)   # intended start
    activated_at = db.Column(db.DateTime(timezone=True), nullable=True)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    note = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    # M4.3.1 pathway-awareness. Existing cohorts default to STRATA ('strata') -> no
    # change in curriculum, grading, or access. PARALLAX ('parallax') cohorts use a
    # separately approved curriculum and do NOT inherit the six-board sequence. Stable
    # ids only; legacy 'cyber-ops'/'cyber-ai' values normalize via pathways module.
    pathway = db.Column(db.String(20), nullable=False, default=pathways.DEFAULT_PATHWAY)
    curriculum_version = db.Column(db.String(20), nullable=True)

    STATUSES = ("scheduled", "active", "completed")
    PATHWAYS = pathways.PATHWAYS


class AdminUser(db.Model):
    """A non-candidate principal: a reviewer (full admin) or an org sponsor
    (read-only, scoped to one org). GitHub-id based, managed in the UI, and
    merged with the REVIEWER_GITHUB_IDS env allowlist for reviewers."""
    __tablename__ = "admin_users"
    id = db.Column(db.Integer, primary_key=True)
    github_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    login = db.Column(db.String(120), nullable=True)   # GitHub handle, for display
    role = db.Column(db.String(20), nullable=False, default="reviewer")  # reviewer | sponsor
    org = db.Column(db.String(120), nullable=True)     # sponsors: the org they can see
    created_at = db.Column(db.DateTime(timezone=True), default=_now)


class ScenarioBinding(db.Model):
    """S3/S4 - the durable, version-pinned binding of a candidate's qualification attempt to a
    specific APPROVED scenario catalog entry and variant. This is the reproducibility + no-repeat
    anchor for the cohort-aware portfolio system: it records the selected spec_id, spec_version,
    immutable content_hash, structural variant, incident family (for reuse cooldown) and seed. The
    hidden truth is NEVER stored here; it is recomputed from (variant, seed) server-side at grade
    time. One binding per (candidate, board, attempt) makes assignment idempotent; the (github_id,
    board, variant_id) history enforces no-repeat for a returning candidate.

    Additive table: created by create_all offline. A production deployment needs a one-off migration
    to add it; this is reported as a release gate and is not applied here."""
    __tablename__ = "scenario_bindings"
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    github_id = db.Column(db.String(64), nullable=False, index=True)   # person key (no-repeat)
    board = db.Column(db.Integer, nullable=False, index=True)
    cohort = db.Column(db.String(40), nullable=False, index=True)
    attempt = db.Column(db.Integer, nullable=False, default=1)
    spec_id = db.Column(db.String(80), nullable=False)
    spec_version = db.Column(db.Integer, nullable=False, default=1)
    content_hash = db.Column(db.String(64), nullable=False)
    variant_id = db.Column(db.String(60), nullable=False)
    family = db.Column(db.String(60), nullable=True)      # for scenario-family reuse cooldown
    seed = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="bound")   # bound | completed
    # S3/S4 real version pinning: an immutable snapshot of the generation contract (board, variant,
    # spec_version and the exact gen_params) captured at bind time, plus an integrity hash over it.
    # Replay uses THIS, not whatever the live variant code currently returns, so an existing
    # assignment reproduces its original world even after a variant is edited or superseded. A
    # tampered contract fails the gen_hash check; a missing one (legacy binding) falls back to live
    # params only when the live spec still hashes to the pinned content_hash, else fails closed.
    gen_contract = db.Column(db.Text, nullable=True)
    gen_hash = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)

    __table_args__ = (db.UniqueConstraint("candidate_id", "board", "attempt",
                                          name="uq_binding_per_attempt"),)


class QualificationDecision(db.Model):
    """S5 - a governed, signed Board 2 qualification decision. SEPARATE from the shadow score
    (CaseSubmission.shadow_*): a shadow score is advisory and never awards credit, whereas a
    QualificationDecision in mode 'authorized' is the ONLY record that may drive Board 2 objective
    credit, and only when the activation gate is open. It pins the exact scenario identity it was
    computed against and carries an Ed25519 signature over its own content, so the award is auditable
    and idempotent.

    Additive table: created by create_all offline; a production deployment needs the one-off
    migration in docs/ (release gate), not applied here."""
    __tablename__ = "qualification_decisions"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    submission_id = db.Column(db.Integer, nullable=False)
    attempt = db.Column(db.Integer, nullable=False, default=1)
    board = db.Column(db.Integer, nullable=False, default=2)
    rubric_version = db.Column(db.Integer, nullable=False)
    mode = db.Column(db.String(20), nullable=False)          # proposed | authorized
    score = db.Column(db.Float, nullable=False)
    normalized = db.Column(db.Float, nullable=True)
    passed = db.Column(db.Boolean, nullable=False, default=False)
    critical_failures = db.Column(db.Text, nullable=True)    # JSON list
    scenario_fingerprint = db.Column(db.String(64), nullable=False)
    spec_id = db.Column(db.String(80), nullable=True)
    spec_version = db.Column(db.Integer, nullable=True)
    content_hash = db.Column(db.String(64), nullable=True)
    variant_id = db.Column(db.String(60), nullable=True)
    principal = db.Column(db.String(120), nullable=True)
    decision_record = db.Column(db.Text, nullable=False)     # canonical JSON that was signed
    decision_sig = db.Column(db.Text, nullable=False)        # Ed25519 signature over the record
    awarded_objective = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)

    # One decision per (case, attempt, submission, rubric, mode) makes the award idempotent.
    __table_args__ = (db.UniqueConstraint("case_id", "attempt", "submission_id",
                                          "rubric_version", "mode",
                                          name="uq_qual_decision"),)


class Notification(db.Model):
    """A candidate-facing event: promotion, a report decision, a lab becoming
    ready. Shown on the ranger's dashboard and, when SMTP is configured, emailed."""
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    kind = db.Column(db.String(30), nullable=False)   # promotion/graduation/report/range/cohort
    title = db.Column(db.String(160), nullable=False)
    body = db.Column(db.String(400), nullable=True)
    read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_now, index=True)


class Badge(db.Model):
    """A signed, verifiable rank credential, minted on each board clearance."""
    __tablename__ = "badges"
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    level = db.Column(db.String(20), nullable=False)   # "1".."6" or "certified"
    name = db.Column(db.String(60), nullable=False)    # Sentinel, Tracker, ... , Certified
    role = db.Column(db.String(40), nullable=True)
    issued_at = db.Column(db.DateTime(timezone=True), default=_now)
    signature = db.Column(db.Text, nullable=True)      # Ed25519 over the badge claim
    revoked = db.Column(db.Boolean, nullable=False, default=False)
    # Public, human-typeable credential id (e.g. QR-7F3K-9MXB). Set only on the
    # "certified" badge; it is the key the public certificate-lookup resolves.
    # A non-security lookup handle: validity/expiry derive from the signed
    # issued_at, so cert_id itself is never part of the signed claim.
    cert_id = db.Column(db.String(40), nullable=True, index=True)

    __table_args__ = (db.UniqueConstraint("candidate_id", "level", name="uq_badge_per_level"),)


class Resource(db.Model):
    """A single admin-managed reference item. One content model is the source of
    truth for both the public resource library (public + published items) and the
    candidate-scoped resource view (items for the ranger's board/role plus general
    references). Access control is enforced server-side: restricted and draft
    items, and their metadata, are never emitted on the public surface.

    Resources are references and technical documentation, never lectures, guided
    lessons, or step-by-step lab solutions."""
    __tablename__ = "resources"
    id = db.Column(db.Integer, primary_key=True)
    # Stable, unique identifier for idempotent catalog upserts (no duplicates).
    slug = db.Column(db.String(90), unique=True, nullable=True, index=True)
    title = db.Column(db.String(200), nullable=False)
    summary = db.Column(db.String(900), nullable=True)   # 70-120 word editorial description
    # One of Resource.RTYPES (standardized content type).
    rtype = db.Column(db.String(40), nullable=False, default="reference-guide", index=True)
    # Primary category (one of CATEGORIES). Secondary tags live in `topic`.
    category = db.Column(db.String(40), nullable=True, index=True)
    topic = db.Column(db.String(200), nullable=True, index=True)  # comma-separated secondary tags
    level = db.Column(db.String(20), nullable=True, index=True)   # foundational|intermediate|advanced|research
    publisher = db.Column(db.String(160), nullable=True)          # original publisher or author
    prereqs = db.Column(db.String(400), nullable=True)            # relevant prerequisite competencies
    board = db.Column(db.Integer, nullable=True, index=True)   # 1..6, or null = general
    role = db.Column(db.String(40), nullable=True)             # role slug, or null = any
    cohort = db.Column(db.String(40), nullable=True)           # a cohort, or null = all
    # public (anyone) | candidate (signed-in rangers) | restricted (staff only)
    visibility = db.Column(db.String(20), nullable=False, default="public", index=True)
    status = db.Column(db.String(20), nullable=False, default="draft", index=True)  # draft | published
    url = db.Column(db.String(500), nullable=True)       # external or asset link
    body = db.Column(db.Text, nullable=True)             # inline long-form content (markdown)
    image = db.Column(db.String(300), nullable=True)     # optional real source image (path/url)
    source_attribution = db.Column(db.String(300), nullable=True)  # credit line for the source
    last_reviewed = db.Column(db.Date, nullable=True)    # technical review date (never fabricated)
    # Original-research publication fields. Present only on QR-RES-* publications;
    # null on ordinary external-reference rows.
    pub_id = db.Column(db.String(40), nullable=True, index=True)   # e.g. QR-RES-002
    maturity = db.Column(db.String(30), nullable=True)   # one of MATURITIES
    pub_type = db.Column(db.String(40), nullable=True)   # one of PUB_TYPES
    collection = db.Column(db.String(80), nullable=True) # research collection label
    version = db.Column(db.String(20), nullable=True)    # e.g. 1.0.0
    verification = db.Column(db.Text, nullable=True)     # JSON: machine-readable verification record
    artifacts = db.Column(db.Text, nullable=True)        # JSON: [{label,url}] source/tests/manifest/results
    refs = db.Column(db.Text, nullable=True)             # JSON: [{label,url}] authoritative external references
    related = db.Column(db.String(200), nullable=True)   # comma-separated related pub_ids
    track = db.Column(db.String(30), nullable=True, index=True)  # top-level collection (one of TRACKS)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    updated_at = db.Column(db.DateTime(timezone=True), default=_now, onupdate=_now)

    # Standardized content types.
    RTYPES = ("technical-documentation", "research-publication", "technical-standard",
              "reference-guide", "technical-book", "security-advisory",
              "threat-intelligence", "open-source-project", "external-course",
              "practical-exercise")
    # Primary categories (slug -> display is in RTYPE/CATEGORY label maps in app).
    CATEGORIES = ("linux-sysadmin", "networking", "secops-siem", "threat-intel",
                  "ir-forensics", "offensive", "engineering", "frameworks")
    LEVELS = ("foundational", "intermediate", "advanced", "research")
    VISIBILITIES = ("public", "candidate", "restricted")
    STATUSES = ("draft", "published")
    # Research publication maturity (research maturity is distinct from the
    # publish gate: `status` controls public visibility, `maturity` records how
    # far the research itself has progressed). A publication reaches the public
    # surface only when an authorized reviewer sets status="published";
    # tool-generated work is never auto-approved.
    MATURITIES = ("draft", "implemented", "executed", "independently-checked",
                  "technical-review", "approved", "published", "superseded")
    # Evidence maturity of the claim a publication makes.
    PUB_TYPES = ("verified-research", "evaluated-artifact", "technical-methodology",
                 "research-in-progress")
    # Top-level catalog collections (navigation). A publication belongs to one.
    TRACKS = ("research", "cohort-docs", "knowledge-base")

    def article_view(self):
        """Full projection for an internal publication page. Only ever returned
        by the single-article endpoint for a published + public resource, so the
        body and research metadata are safe to expose here."""
        import json as _json
        def _loads(s, default):
            if not s:
                return default
            try:
                return _json.loads(s)
            except Exception:
                return default
        base = self.public_view()
        base.update({
            "body": self.body,
            "pub_id": self.pub_id, "maturity": self.maturity,
            "pub_type": self.pub_type, "collection": self.collection,
            "version": self.version,
            "verification": _loads(self.verification, None),
            "artifacts": _loads(self.artifacts, []),
            "refs": _loads(self.refs, []),
            "related": [x.strip() for x in (self.related or "").split(",") if x.strip()],
            "created_at": (self.created_at.isoformat() if self.created_at else None),
        })
        return base

    def public_view(self):
        """Safe projection for public/candidate surfaces. Never includes the
        visibility/status control fields or anything staff-only."""
        return {"id": self.id, "slug": self.slug, "title": self.title,
                "summary": self.summary, "rtype": self.rtype, "category": self.category,
                "topic": self.topic, "level": self.level, "publisher": self.publisher,
                "prereqs": self.prereqs, "board": self.board, "role": self.role,
                "url": self.url, "image": self.image,
                "source_attribution": self.source_attribution,
                "has_article": bool(self.body),
                "pub_id": self.pub_id, "maturity": self.maturity,
                "pub_type": self.pub_type, "collection": self.collection,
                "track": self.track, "version": self.version,
                "last_reviewed": (self.last_reviewed.isoformat() if self.last_reviewed else None),
                "updated_at": (self.updated_at or self.created_at)}


class CohortScenarioPlan(db.Model):
    """What a cohort covers, per board, declared by an admin. Records coverage,
    difficulty intent, an optional scenario family/variant tag (a forward hook
    for later generator pool-deepening), and notes. Generators stay seed-driven
    today; this is the admin-facing statement of intent and the anchor for
    documentation, not yet a generator switch."""
    __tablename__ = "cohort_scenario_plans"
    id = db.Column(db.Integer, primary_key=True)
    cohort = db.Column(db.String(40), nullable=False, index=True)
    board = db.Column(db.Integer, nullable=False)   # 1..6
    coverage = db.Column(db.String(400), nullable=True)   # what this board covers
    difficulty = db.Column(db.String(20), nullable=True)  # intro | standard | advanced
    variant = db.Column(db.String(40), nullable=True)     # scenario family/variant tag (future)
    notes = db.Column(db.Text, nullable=True)             # admin-maintained free text (never clobbered)
    # S3/S4 cohort portfolio: the admin-approved set of variant ids a cohort draws from, stored in a
    # DEDICATED column so saving a portfolio never overwrites the admin `notes` or other operator
    # metadata. JSON: {"portfolio": [...], "set_by": <approver>, "set_at": <iso>}.
    portfolio_json = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=_now, onupdate=_now)

    __table_args__ = (db.UniqueConstraint("cohort", "board", name="uq_plan_per_cohort_board"),)

    DIFFICULTIES = ("intro", "standard", "advanced")


class ScenarioCatalogEntry(db.Model):
    """M4.3.1 - a validated, versioned, immutable scenario package in the catalog.

    The catalog is pathway-aware WITHOUT being duplicated: one table, a `pathway`
    column (stable ids 'strata' / 'parallax'). An entry holds the full declarative
    ScenarioSpec (siem/scenario_spec.py) plus its content hash (immutability),
    calibration vector, and approval record. Only status `catalog_eligible` is
    selectable for cohort assignment. Hidden truth is never stored here; the spec's
    evaluator_only layer references truth GENERATION, which is recomputed from the
    seed server-side. This does not replace CohortScenarioPlan (admin intent) or the
    Case/CaseSubmission/BoardResult/qualification machinery, which are unchanged.
    """
    __tablename__ = "scenario_catalog_entries"
    id = db.Column(db.Integer, primary_key=True)
    spec_id = db.Column(db.String(80), nullable=False, index=True)
    spec_version = db.Column(db.Integer, nullable=False, default=1)
    pathway = db.Column(db.String(20), nullable=False, default=pathways.DEFAULT_PATHWAY, index=True)
    specialization = db.Column(db.String(40), nullable=True)
    environment_type = db.Column(db.String(40), nullable=False, default="soc-opensearch")
    spec_type = db.Column(db.String(40), nullable=False, default="soc-investigation")
    board_compat = db.Column(db.String(40), nullable=True)   # JSON list of boards
    difficulty = db.Column(db.String(20), nullable=True)
    status = db.Column(db.String(24), nullable=False, default="draft", index=True)
    content_hash = db.Column(db.String(64), nullable=True)   # immutable spec hash
    spec_json = db.Column(db.Text, nullable=True)            # the full declarative ScenarioSpec
    calibration = db.Column(db.Text, nullable=True)          # JSON complexity vector
    diversity = db.Column(db.Text, nullable=True)            # JSON diversity axes
    approved_by = db.Column(db.String(64), nullable=True)
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    updated_at = db.Column(db.DateTime(timezone=True), default=_now, onupdate=_now)

    # one immutable row per (spec_id, spec_version)
    __table_args__ = (db.UniqueConstraint("spec_id", "spec_version",
                                          name="uq_scenario_spec_version"),)

    STATUSES = ("draft", "schema_validated", "capability_validated",
                "executable_tested", "calibrated", "approved", "catalog_eligible",
                "deprecated")


class AssessmentBlueprint(db.Model):
    """F1 - a versioned, immutable assessment blueprint shared by the assessment contract
    (siem/assessment_contract.py). It separates the ten assessment concerns as JSON and is
    pinned by content hash so an in-flight cohort's rules never change. Pathway-aware
    (stable ids strata/parallax); does NOT alter STRATA grading (a STRATA blueprint simply
    records the existing objective-bar policy). Additive table; nothing existing changes."""
    __tablename__ = "assessment_blueprints"
    id = db.Column(db.Integer, primary_key=True)
    pathway = db.Column(db.String(20), nullable=False, default=pathways.DEFAULT_PATHWAY, index=True)
    blueprint_version = db.Column(db.Integer, nullable=False, default=1)
    environment_version = db.Column(db.String(40), nullable=True)
    content_hash = db.Column(db.String(64), nullable=True)      # immutability anchor
    blueprint_json = db.Column(db.Text, nullable=True)          # the full declarative blueprint
    status = db.Column(db.String(24), nullable=False, default="draft", index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)

    __table_args__ = (db.UniqueConstraint("pathway", "blueprint_version",
                                          name="uq_blueprint_pathway_version"),)
    STATUSES = ("draft", "approved", "active", "retired")


class UnitResult(db.Model):
    """F1 - a signed, pathway-scoped qualification decision for one assessment unit. Produced
    by the common contract's sign_decision and verifiable with verify_decision. STRATA keeps
    writing BoardResult unchanged; UnitResult is the additive, pathway-neutral record (used by
    PARALLAX now, and available to represent STRATA later without changing BoardResult today).
    Reviewer adjudications are appended as NEW rows referencing parent_record_hash; a signed
    row is never mutated."""
    __tablename__ = "unit_results"
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    pathway = db.Column(db.String(20), nullable=False, default=pathways.DEFAULT_PATHWAY, index=True)
    curriculum_version = db.Column(db.String(20), nullable=True)
    unit_ref = db.Column(db.String(80), nullable=False, index=True)
    blueprint_version = db.Column(db.Integer, nullable=True)
    blueprint_hash = db.Column(db.String(64), nullable=True)
    qualified = db.Column(db.Boolean, nullable=False, default=False)
    reason = db.Column(db.String(60), nullable=True)
    decision_json = db.Column(db.Text, nullable=True)           # full auditable decision
    record_hash = db.Column(db.String(64), nullable=True)       # hash of the signed record
    parent_record_hash = db.Column(db.String(64), nullable=True)  # for append-only adjudications
    kind = db.Column(db.String(30), nullable=False, default="qualification_decision")
    signature = db.Column(db.Text, nullable=True)               # Ed25519 over the record
    created_at = db.Column(db.DateTime(timezone=True), default=_now)

    KINDS = ("qualification_decision", "reviewer_adjudication")


class EvidenceArtifact(db.Model):
    """F2 - a typed evidence artifact's signed metadata envelope (siem/evidence_types.py).
    Large/binary payloads are NOT stored here: `blob_*` hold a content-addressed BlobRef into
    out-of-DB object storage (not provisioned yet). Bound to its Case + owner + cohort +
    pathway so authorization and lineage travel with the evidence; immutable by version
    (a revision is a new row that `supersedes` the prior). Reuses Ed25519 signing. Additive
    table; nothing existing changes. Reuses Case/CaseSubmission rather than forking evidence."""
    __tablename__ = "evidence_artifacts"
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(64), nullable=False, unique=True, index=True)
    evidence_type = db.Column(db.String(40), nullable=False, index=True)
    evidence_schema_version = db.Column(db.Integer, nullable=False, default=1)
    contract_version = db.Column(db.Integer, nullable=False, default=1)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True, index=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    cohort = db.Column(db.String(40), nullable=False, index=True)
    pathway = db.Column(db.String(20), nullable=False, default=pathways.DEFAULT_PATHWAY, index=True)
    source_identity = db.Column(db.String(120), nullable=True)
    content_hash = db.Column(db.String(64), nullable=False)
    acquisition_ts = db.Column(db.String(40), nullable=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    validation_state = db.Column(db.String(20), nullable=False, default="unvalidated", index=True)
    # BlobRef (reference only; bytes live in out-of-DB object storage via ArtifactStore)
    blob_uri = db.Column(db.String(300), nullable=True)
    blob_sha256 = db.Column(db.String(64), nullable=True)
    blob_media_type = db.Column(db.String(80), nullable=True)
    blob_bytes = db.Column(db.BigInteger, nullable=True)
    # F3 storage/provenance
    object_key = db.Column(db.String(128), nullable=True)   # ArtifactStore content-addressed key
    storage_backend = db.Column(db.String(20), nullable=True)   # filesystem | s3 (dev/prod)
    scan_state = db.Column(db.String(20), nullable=True, default="unscanned")  # unscanned|clean|quarantined
    transform = db.Column(db.String(60), nullable=True)     # transformation type (derived artifacts)
    tool_version = db.Column(db.String(60), nullable=True)  # tool + version that produced it
    retention_class = db.Column(db.String(30), nullable=True, default="default")
    derived_from = db.Column(db.Text, nullable=True)        # JSON list of parent evidence_ids
    supersedes = db.Column(db.String(64), nullable=True)    # prior evidence_id (immutable versioning)
    authenticity_assessment = db.Column(db.Text, nullable=True)  # advisory only, never authoritative
    provenance = db.Column(db.Text, nullable=True)          # JSON
    signature = db.Column(db.Text, nullable=True)           # Ed25519 over the envelope
    revoked = db.Column(db.Boolean, nullable=False, default=False)
    retention_until = db.Column(db.String(40), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)

    RETENTION_CLASSES = ("default", "active_assessment", "signed_qualification")
    SCAN_STATES = ("unscanned", "clean", "quarantined")


class CustodyEvent(db.Model):
    """F3 - an append-only, Ed25519-signed chain-of-custody event for an evidence artifact.
    Events are never mutated; each references the prior event by hash (parent_hash), forming a
    tamper-evident chain. Kinds: acquire, verify, derive, access, revoke, retain, quarantine."""
    __tablename__ = "custody_events"
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(64), nullable=False, index=True)
    kind = db.Column(db.String(20), nullable=False, index=True)
    actor = db.Column(db.String(120), nullable=True)       # server principal / reviewer id
    candidate_id = db.Column(db.Integer, nullable=True, index=True)
    cohort = db.Column(db.String(40), nullable=True)
    pathway = db.Column(db.String(20), nullable=True)
    detail = db.Column(db.Text, nullable=True)             # JSON
    record_hash = db.Column(db.String(64), nullable=False)
    parent_hash = db.Column(db.String(64), nullable=True)
    signature = db.Column(db.Text, nullable=False)         # Ed25519 over the event record
    # F4 correction (C): persist the exact signed record + its timestamp + per-evidence sequence
    # so the chain can be re-verified from the DB (not only from an in-memory list) and so a
    # separately-protected checkpoint can detect truncation of the latest events.
    ts = db.Column(db.String(40), nullable=True)           # the record's own ISO timestamp
    seq = db.Column(db.Integer, nullable=True)             # 0-based position in this evidence's chain
    record_json = db.Column(db.Text, nullable=True)        # canonical signed record for exact re-verify
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    # F4.1: a per-evidence sequence position is unique, so two concurrent jobs appending to the same
    # source chain can never both claim the same seq (the loser's INSERT is rejected). NULL seq
    # (legacy rows) is exempt, as PostgreSQL treats NULLs as distinct.
    __table_args__ = (db.UniqueConstraint("evidence_id", "seq", name="uq_custody_evidence_seq"),)

    KINDS = ("acquire", "verify", "derive", "access", "revoke", "retain", "quarantine")


class CustodyCheckpoint(db.Model):
    """F4 correction (C) - a separately-protected anchor over an evidence artifact's custody chain.

    An internally-valid hash chain cannot by itself detect removal of its most recent events
    (truncation): drop the last N rows and the remaining chain still verifies. This checkpoint
    records, out of band from the events themselves, the chain head hash, the event COUNT, and the
    head sequence, each signed, and itself chained (prev_checkpoint_hash) so checkpoints cannot be
    silently rolled back either. Comparing the live chain against the latest checkpoint detects
    truncation (fewer events than anchored) and head rewrites (same count, different head).

    Honest limitation: checkpoints are signed with the same server Ed25519 key as the events, so an
    attacker who holds that key could forge both. This protects against DB-level tampering/truncation
    by anyone WITHOUT the signing key, and against accidental loss, between checkpoints. External
    anchoring (e.g. a transparency log) is a future extension and needs no paid infra to add later."""
    __tablename__ = "custody_checkpoints"
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(64), nullable=False, index=True)
    event_count = db.Column(db.Integer, nullable=False)       # number of events anchored
    head_hash = db.Column(db.String(64), nullable=False)      # record_hash of the latest event
    head_seq = db.Column(db.Integer, nullable=False)          # seq of the latest event
    prev_checkpoint_hash = db.Column(db.String(64), nullable=True)  # chains checkpoints together
    checkpoint_hash = db.Column(db.String(64), nullable=False)
    ts = db.Column(db.String(40), nullable=False)
    signature = db.Column(db.Text, nullable=False)            # Ed25519 over the checkpoint record
    created_at = db.Column(db.DateTime(timezone=True), default=_now)


class BlobReference(db.Model):
    """F4 correction (B) - a reference from one evidence artifact to one content-addressed object.

    Storage is content-addressed with de-duplication, so several artifacts (possibly across
    candidates/cohorts) may point at the SAME blob/<sha256> object. Physical deletion must therefore
    be reference-counted: revoking, quarantining or deleting one artifact releases only ITS reference,
    and the underlying bytes are removed only when no active reference and no retention hold remains.
    Each reference is scoped to its own candidate/cohort so logical revocation can be scoped without
    touching another tenant's reference, and de-duplication never discloses that another tenant holds
    the same bytes (authorization is always per-artifact; the dedup is invisible to callers)."""
    __tablename__ = "blob_references"
    id = db.Column(db.Integer, primary_key=True)
    object_key = db.Column(db.String(128), nullable=False, index=True)   # blob/<sha256>
    evidence_id = db.Column(db.String(64), nullable=False, index=True)
    candidate_id = db.Column(db.Integer, nullable=True, index=True)
    cohort = db.Column(db.String(40), nullable=True, index=True)
    pathway = db.Column(db.String(20), nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    hold = db.Column(db.Boolean, nullable=False, default=False)   # legal/retention hold: blocks delete
    released_at = db.Column(db.String(40), nullable=True)
    release_reason = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    __table_args__ = (db.UniqueConstraint("object_key", "evidence_id", name="uq_blobref_obj_ev"),)


class TrustedFixture(db.Model):
    """F4.1 - an authenticated, administrator-approved synthetic-fixture registry.

    The ONLY thing that may let media bypass the scan gate for development demonstrations is a
    content hash registered here by an explicit administrative action. Trust is derived server-side
    from this table keyed by the server-computed sha256; it is never taken from a job parameter,
    submitted metadata, or any caller-controlled flag. Real candidate uploads are never registered."""
    __tablename__ = "trusted_fixtures"
    id = db.Column(db.Integer, primary_key=True)
    sha256 = db.Column(db.String(64), nullable=False, unique=True, index=True)
    note = db.Column(db.String(300), nullable=True)
    approved_by = db.Column(db.String(120), nullable=False)   # admin principal that approved it
    created_at = db.Column(db.DateTime(timezone=True), default=_now)


class ForensicJob(db.Model):
    """F4 - a persistent, auditable bounded-forensic-processing job.

    Admin-controlled only (no general candidate execution, no always-on workers). One job runs one
    authorized operation over one source EvidenceArtifact inside the OS-enforced sandbox and persists
    its derived evidence + signed custody. The lifecycle is explicit and restart-recoverable: a crash
    while `running` is reclaimed by the next admin-triggered sweep, not by an unrestricted daemon."""
    __tablename__ = "forensic_jobs"
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(64), nullable=False, unique=True, index=True)
    operation = db.Column(db.String(40), nullable=False)
    source_evidence_id = db.Column(db.String(64), nullable=False, index=True)
    case_id = db.Column(db.Integer, nullable=True, index=True)
    candidate_id = db.Column(db.Integer, nullable=True, index=True)
    cohort = db.Column(db.String(40), nullable=True, index=True)
    pathway = db.Column(db.String(20), nullable=True)
    params = db.Column(db.Text, nullable=True)                # JSON validated params
    idempotency_key = db.Column(db.String(80), nullable=True, unique=True, index=True)
    state = db.Column(db.String(20), nullable=False, default="queued", index=True)
    requested_by = db.Column(db.String(120), nullable=True)   # admin principal
    attempts = db.Column(db.Integer, nullable=False, default=0)
    max_attempts = db.Column(db.Integer, nullable=False, default=1)
    claimed_at = db.Column(db.String(40), nullable=True)
    started_at = db.Column(db.String(40), nullable=True)
    finished_at = db.Column(db.String(40), nullable=True)
    worker_token = db.Column(db.String(64), nullable=True)    # atomic-claim guard
    wall_ms = db.Column(db.Integer, nullable=True)
    error_code = db.Column(db.String(60), nullable=True)
    error_detail = db.Column(db.Text, nullable=True)
    result_manifest = db.Column(db.Text, nullable=True)       # JSON reproducible manifest
    derived_evidence_ids = db.Column(db.Text, nullable=True)  # JSON list
    created_at = db.Column(db.DateTime(timezone=True), default=_now)

    STATES = ("queued", "running", "succeeded", "failed", "canceled", "quarantined")


class Case(db.Model):
    """A SOC investigation assignment for a candidate (Board 2 enterprise SIEM).

    A Case binds a candidate to a specific data plane + index + seed + versioned
    scenario, and carries the investigation lifecycle. The hidden scenario truth is
    NEVER stored here; it is recomputed from `seed` server-side at grade time. Three
    workflows share this model (see siem/case_contract.py): practice (ungraded),
    assigned (formative, reviewer feedback), qualification (the graded exam).
    """
    __tablename__ = "cases"
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    board = db.Column(db.Integer, nullable=False, default=2)
    cohort = db.Column(db.String(40), nullable=False)
    # Which data plane this case investigates: "qualification" (deterministic,
    # graded) or "operational" (continuous, ungraded).
    plane = db.Column(db.String(20), nullable=False, default="qualification", index=True)
    # Workflow: "qualification" | "assigned" | "practice".
    workflow = db.Column(db.String(20), nullable=False, default="qualification", index=True)
    index_name = db.Column(db.String(200), nullable=False)   # the candidate's authorized index
    seed = db.Column(db.String(64), nullable=False)          # reproducibility key (truth recomputed from this)
    scenario_version = db.Column(db.Integer, nullable=False, default=1)
    # F5.1: reference to APPROVED, candidate-safe scenario metadata (scope/objectives/requirements).
    # Resolves, with scenario_version, to a versioned entry in workbench_scenarios; NEVER holds truth.
    # When unset/unknown, the candidate sees an accurate "instructions not available" state.
    scenario_ref = db.Column(db.String(60), nullable=True)
    # S5: definitive association to the S3/S4 authoritative ScenarioBinding, so /soc, /case and
    # grading all share one pinned scenario identity. Nullable for legacy/non-cohort cases.
    binding_id = db.Column(db.Integer, nullable=True, index=True)
    content_hash = db.Column(db.String(64), nullable=True)   # pinned spec content hash
    variant_id = db.Column(db.String(60), nullable=True)     # pinned approved variant
    rubric_version = db.Column(db.Integer, nullable=False, default=2)
    attempt = db.Column(db.Integer, nullable=False, default=1)
    # Lifecycle state (see case_contract.CASE_STATES / CASE_TRANSITIONS).
    status = db.Column(db.String(24), nullable=False, default="assigned", index=True)
    assigned_at = db.Column(db.DateTime(timezone=True), default=_now)
    started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    submitted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    closed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    updated_at = db.Column(db.DateTime(timezone=True), default=_now, onupdate=_now)

    submissions = db.relationship("CaseSubmission", backref="case", lazy=True,
                                  cascade="all, delete-orphan")

    # One live (non-terminal) qualification case per (candidate, board, attempt).
    __table_args__ = (db.UniqueConstraint("candidate_id", "board", "attempt", "plane",
                                          name="uq_case_per_attempt"),)


class CaseSubmission(db.Model):
    """One structured incident submission for a Case.

    `payload` is the candidate-authored CaseSubmission JSON (siem/case_contract.py
    schema). The reviewer-owned fields are never candidate-writable. The enterprise
    grade (`shadow_score`) is SHADOW ONLY and never drives qualification: it is not
    written to BoardResult.objective_* and does not affect clearance.
    """
    __tablename__ = "case_submissions"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"), nullable=False, index=True)
    attempt = db.Column(db.Integer, nullable=False, default=1)
    # draft | submitted | under_review | evaluated | closed
    submission_status = db.Column(db.String(20), nullable=False, default="draft", index=True)
    rubric_version = db.Column(db.Integer, nullable=False, default=2)
    payload = db.Column(db.Text, nullable=True)            # JSON: candidate-authored submission
    validation = db.Column(db.Text, nullable=True)         # JSON: {errors, warnings}
    verification = db.Column(db.Text, nullable=True)       # JSON: per-citation verdicts (server-side)
    evidence_record = db.Column(db.Text, nullable=True)    # JSON: preserved, hashed cited events (STRATA preserved-citation; siem/case_contract.py)
    evidence_sig = db.Column(db.Text, nullable=True)       # Ed25519 over the evidence record (STRATA; integrity/origin, NOT correctness)
    # F5.1: the WORKBENCH submission receipt is a DISTINCT, versioned contract kept in its OWN
    # additive columns so it never collides with or overwrites STRATA's preserved-citation
    # evidence_record/evidence_sig. STRATA verification is unchanged.
    wb_receipt = db.Column(db.Text, nullable=True)         # JSON: workbench_submission_receipt record
    wb_receipt_sig = db.Column(db.Text, nullable=True)     # Ed25519 over the workbench receipt
    wb_receipt_version = db.Column(db.Integer, nullable=True)  # workbench receipt contract version
    # SHADOW enterprise grade: recorded for comparison only; never used for clearance.
    shadow_score = db.Column(db.Float, nullable=True)
    shadow_breakdown = db.Column(db.Text, nullable=True)   # JSON: per-component scores
    review_flags = db.Column(db.Text, nullable=True)       # JSON: human-review triggers raised
    # Reviewer-owned (never candidate-writable).
    reviewer_id = db.Column(db.String(64), nullable=True)
    reviewer_feedback = db.Column(db.Text, nullable=True)
    reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    submitted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    updated_at = db.Column(db.DateTime(timezone=True), default=_now, onupdate=_now)
