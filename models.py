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


class Candidate(db.Model):
    __tablename__ = "candidates"
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(120), unique=True, nullable=False, index=True)  # github login
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    cohort = db.Column(db.String(40), nullable=False, index=True)
    repo = db.Column(db.String(200), nullable=True)  # owner/name of their fork, optional at enroll
    token = db.Column(db.String(64), nullable=False, default=_token)  # report-submission secret
    created_at = db.Column(db.DateTime(timezone=True), default=_now)

    reports = db.relationship("Report", backref="candidate", lazy=True,
                              cascade="all, delete-orphan")
    range_requests = db.relationship("RangeRequest", backref="candidate", lazy=True,
                                     cascade="all, delete-orphan")

    def roster_entry(self):
        return {"handle": self.handle, "name": self.name,
                "repo": self.repo or f"qwalora/{self.handle}"}


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
    status = db.Column(db.String(20), nullable=False, default="queued", index=True)  # queued/provisioned/failed
    ludus_range_id = db.Column(db.String(120), nullable=True)
    detail = db.Column(db.Text, nullable=True)         # broker message / error
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    updated_at = db.Column(db.DateTime(timezone=True), default=_now, onupdate=_now)
