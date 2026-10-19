"""One-shot, idempotent, reversible migration: establish per-candidate program
entitlements (STRATA / PARALLAX) from reliable existing evidence.

Design (see docs/PARALLAX_PROGRAM_ENTITLEMENTS_DESIGN.md section 6). For every candidate
that has NO program membership yet, derive membership(s) from the strongest available
evidence, never blanket-granting both and never locking out a currently-active candidate:

  1. exactly one program has STRONG evidence  -> grant that program (mirror candidate status)
  2. BOTH have strong evidence                -> grant both (genuine dual use)
  3. NEITHER has strong evidence              -> grant the single cohort-pathway program

STRONG STRATA  = any STRATA-owned record (BoardResult, Report, ScenarioBinding, RangeRequest,
                 Badge, Case, CaseSubmission, QualificationDecision) OR current_board > 1 OR
                 status == 'graduated'.
STRONG PARALLAX = any PARALLAX-owned record (ParallaxResearchRun by researcher_id,
                 UnitResult pathway=='parallax', ParallaxReviewerAssignment by candidate_key).

Run (gated so it never fires implicitly):   RANGER_PROGRAM_MIGRATE=1 python migrate_program_memberships.py
Rollback (removes only untouched system rows): python migrate_program_memberships.py --rollback

Idempotent: a candidate that already has any membership row is skipped. Every created row writes
a 'migrate' audit event with granted_by='system:migration' and the evidence basis.
"""
from __future__ import annotations

import datetime as _dt
import os
import sys

ACTOR = "system:migration"


def _mirror_status(cand_status):
    return {"active": "active", "graduated": "active", "pending": "pending",
            "rejected": "rejected", "withdrawn": "revoked",
            "washed_out": "revoked"}.get(cand_status, "pending")


def _strong_strata(db, models, c):
    from sqlalchemy import or_  # noqa: F401
    M = models
    if c.current_board and c.current_board > 1:
        return True
    if c.status == "graduated":
        return True
    for Model in (M.BoardResult, M.Report, M.RangeRequest, M.Badge):
        if db.session.query(Model.id).filter_by(candidate_id=c.id).first():
            return True
    for name in ("ScenarioBinding", "QualificationDecision", "Case", "CaseSubmission"):
        Model = getattr(M, name, None)
        if Model is not None and db.session.query(Model.id).filter_by(candidate_id=c.id).first():
            return True
    return False


def _strong_parallax(db, models, c):
    M = models
    keys = {str(c.id)}
    if c.github_id:
        keys.add(c.github_id)
    if c.handle:
        keys.add(c.handle)
    PR = getattr(M, "ParallaxResearchRun", None)
    if PR is not None and db.session.query(PR.id).filter(PR.researcher_id.in_(keys)).first():
        return True
    UR = getattr(M, "UnitResult", None)
    if UR is not None and db.session.query(UR.id).filter_by(candidate_id=c.id, pathway="parallax").first():
        return True
    RA = getattr(M, "ParallaxReviewerAssignment", None)
    if RA is not None and db.session.query(RA.id).filter(RA.candidate_key.in_(keys)).first():
        return True
    return False


def migrate():
    import pathways
    import app as appmod
    import models as M
    from models import db, Candidate, Cohort, ProgramMembership, ProgramMembershipEvent

    application = appmod.create_app()
    created = {"strata": 0, "parallax": 0}
    skipped = 0
    with application.app_context():
        for c in Candidate.query.order_by(Candidate.id.asc()).all():
            if ProgramMembership.query.filter_by(candidate_id=c.id).first() is not None:
                skipped += 1
                continue
            ss = _strong_strata(db, M, c)
            sp = _strong_parallax(db, M, c)
            co = Cohort.query.filter_by(name=c.cohort).first()
            cohort_pw = pathways.normalize_pathway(co.pathway if co else None)
            if ss and not sp:
                progs, basis = [pathways.PATHWAY_STRATA], "strong strata evidence"
            elif sp and not ss:
                progs, basis = [pathways.PATHWAY_PARALLAX], "strong parallax evidence"
            elif ss and sp:
                progs, basis = [pathways.PATHWAY_STRATA, pathways.PATHWAY_PARALLAX], "strong evidence both"
            else:
                progs, basis = [cohort_pw], "cohort pathway (no record evidence)"
            status = _mirror_status(c.status)
            for p in progs:
                db.session.add(ProgramMembership(candidate_id=c.id, program=p, status=status,
                                                 cohort=c.cohort, granted_by=ACTOR,
                                                 decided_at=_dt.datetime.now(_dt.timezone.utc)))
                db.session.add(ProgramMembershipEvent(
                    candidate_id=c.id, program=p, action="migrate", from_status=None,
                    to_status=status, actor=ACTOR,
                    reason=("%s; candidate=%s" % (basis, c.status))[:400]))
                created[p] = created.get(p, 0) + 1
        db.session.commit()
    print("migrate: created strata=%d parallax=%d, skipped(existing)=%d"
          % (created.get("strata", 0), created.get("parallax", 0), skipped))
    return 0


def rollback():
    import app as appmod
    from models import db, ProgramMembership, ProgramMembershipEvent
    application = appmod.create_app()
    removed = 0
    with application.app_context():
        # Only remove memberships still owned by the migration (untouched by an admin), and
        # their migrate events. Admin-modified rows (granted_by != system:migration) are kept.
        for m in ProgramMembership.query.filter_by(granted_by=ACTOR).all():
            ProgramMembershipEvent.query.filter_by(
                candidate_id=m.candidate_id, program=m.program, actor=ACTOR).delete()
            db.session.delete(m)
            removed += 1
        db.session.commit()
    print("rollback: removed %d system-migration memberships" % removed)
    return 0


def main(argv):
    if "--rollback" in argv:
        return rollback()
    if os.environ.get("RANGER_PROGRAM_MIGRATE") != "1":
        print("refusing to run: set RANGER_PROGRAM_MIGRATE=1 to apply the migration "
              "(or pass --rollback). No changes made.")
        return 0
    return migrate()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
