"""Candidate authorization and credential mapping.

Isolation is index-per-candidate-board plus a per-candidate role that grants read
on only that index pattern, with document-level security on candidate_id as a
second layer. The Ranger backend (the broker) is the only holder of the admin
credential; it provisions the role, user, and mapping, and issues the candidate a
short-lived scoped credential. GitHub OAuth stays the candidate's Ranger identity.
"""
from __future__ import annotations

import secrets

from .client import Role

INDEX_PREFIX = "ranger"


def index_name(cohort: str, candidate_id: str, board: int) -> str:
    """One index per candidate-board. Slugged to OpenSearch-safe lowercase."""
    return f"{INDEX_PREFIX}-{_slug(cohort)}-{_slug(candidate_id)}-b{int(board)}".lower()


def candidate_index_pattern(cohort: str, candidate_id: str) -> str:
    """All of one candidate's boards, for their role. Never spans candidates."""
    return f"{INDEX_PREFIX}-{_slug(cohort)}-{_slug(candidate_id)}-b*".lower()


def qualification_index_name(cohort: str, candidate_id: str, board: int, attempt: int) -> str:
    """S5: the GRADED qualification index for one candidate-board-attempt, kept distinct from the
    operational SOC index (…-b{board}) so qualification assessment data and operational SOC
    collaboration never share an index. Still inside the candidate's own `…-b*` role pattern, so
    per-candidate role + DLS authorization is unchanged. One index per (candidate, board, attempt)
    makes provisioning idempotent and prevents two modules minting equivalent indices."""
    return (f"{INDEX_PREFIX}-{_slug(cohort)}-{_slug(candidate_id)}"
            f"-b{int(board)}-q{int(attempt)}").lower()


def role_name(candidate_id: str) -> str:
    return f"cand_{_slug(candidate_id)}".lower()


def user_name(candidate_id: str) -> str:
    return f"cand_{_slug(candidate_id)}".lower()


def candidate_role(cohort: str, candidate_id: str) -> Role:
    """Read-only on only this candidate's indices, with DLS on candidate_id as a
    second isolation layer. No write, no cluster privileges."""
    return Role(
        name=role_name(candidate_id),
        index_patterns=[candidate_index_pattern(cohort, candidate_id)],
        allow_write=False,
        dls={"ranger.candidate_id": candidate_id},
    )


# Candidate statuses that may hold SOC access. Anything else is revoked.
ACTIVE_STATUSES = ("active",)
# Boards served by this SIEM (1 to 4). Boards 5 to 6 are Ludus/GOAD (Phase 3).
SIEM_BOARDS = (1, 2, 3, 4)


class AccessDecision:
    def __init__(self, allowed: bool, reason: str, board: int | None = None):
        self.allowed = allowed
        self.reason = reason
        self.board = board


def decide_access(status: str, current_board: int) -> AccessDecision:
    """Server-side gate: only an active candidate on a SIEM board gets access.
    This runs in the Ranger backend before any credential is minted."""
    if status not in ACTIVE_STATUSES:
        return AccessDecision(False, f"status:{status}-not-active")
    if current_board not in SIEM_BOARDS:
        return AccessDecision(False, f"board:{current_board}-not-a-siem-board")
    return AccessDecision(True, "authorized", board=current_board)


class CredentialBroker:
    """Mints, rotates, and revokes candidate OpenSearch credentials against the
    Security API, using the admin identity. The admin credential never leaves this
    broker and is never sent to a candidate or the frontend."""

    def __init__(self, client, admin_user=None):
        self.client = client
        self.admin = admin_user or getattr(client, "ADMIN", "_broker_admin")

    def provision(self, cohort: str, candidate_id: str, status: str,
                  current_board: int) -> dict:
        """Ensure the candidate's role, user, and index exist for their current
        board, and return a short-lived scoped credential. Enforces the access
        decision first; returns {'allowed': False, ...} if not permitted."""
        decision = decide_access(status, current_board)
        if not decision.allowed:
            return {"allowed": False, "reason": decision.reason}

        role = candidate_role(cohort, candidate_id)
        self.client.put_role(self.admin, role)
        uname = user_name(candidate_id)
        # A fresh short-lived secret each provision (rotation on every board access).
        password = secrets.token_urlsafe(24)
        self.client.put_user(self.admin, uname, [role.name])

        idx = index_name(cohort, candidate_id, current_board)
        if not self.client.index_exists(idx):
            self.client.create_index(self.admin, idx)

        return {"allowed": True, "username": uname, "password": password,
                "index": idx, "role": role.name, "board": current_board}

    def revoke(self, candidate_id: str):
        """Remove the candidate's OpenSearch user (and role). Called on any status
        change away from active (withdrawn, washed out, graduated, rejected)."""
        self.client.delete_user(self.admin, user_name(candidate_id))
        self.client.delete_role(self.admin, role_name(candidate_id))


def _slug(s: str) -> str:
    out = []
    for ch in str(s).lower():
        out.append(ch if (ch.isalnum() or ch in "-_") else "-")
    return "".join(out).strip("-") or "x"
