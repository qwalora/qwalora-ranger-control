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
            ("ludus_user_id", "VARCHAR(64)"),
            ("ludus_key_enc", "TEXT"),
            ("status", "VARCHAR(20) DEFAULT 'active'"),
            ("current_board", "INTEGER DEFAULT 1"),
            ("board_role", "VARCHAR(40)"),  # maps to Candidate.current_role
            ("exited_at", "TIMESTAMP"),
            ("exit_reason", "VARCHAR(200)"),
        ],
        "range_requests": [
            ("template", "VARCHAR(60)"),
            ("wireguard_config", "TEXT"),
            ("last_checked_at", "TIMESTAMP"),
            ("board", "INTEGER"),
            ("host", "VARCHAR(60) DEFAULT 'primary'"),
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


class Candidate(db.Model):
    __tablename__ = "candidates"
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(120), unique=True, nullable=False, index=True)  # github login
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    cohort = db.Column(db.String(40), nullable=False, index=True)
    repo = db.Column(db.String(200), nullable=True)  # owner/name of their fork, optional at enroll
    token = db.Column(db.String(64), nullable=False, default=_token)  # report-submission secret
    # Ludus linkage: one candidate maps to exactly one Ludus user, which owns one range.
    ludus_user_id = db.Column(db.String(64), nullable=True)   # Ludus userID
    ludus_key_enc = db.Column(db.Text, nullable=True)         # Fernet-encrypted Ludus user API key
    # Lifecycle: active -> graduated | withdrawn | washed_out (the three exit points).
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

    TERMINAL = ("graduated", "withdrawn", "washed_out")

    @property
    def is_active(self):
        return self.status == "active"

    def roster_entry(self):
        return {"handle": self.handle, "name": self.name,
                "repo": self.repo or f"qwalora/{self.handle}",
                "status": self.status, "board": self.current_board}


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

    __table_args__ = (db.UniqueConstraint("candidate_id", "level", name="uq_badge_per_level"),)
