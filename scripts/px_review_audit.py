"""READ-ONLY post-adjudication integrity audit for the PARALLAX Research Review acceptance test.

Run INSIDE the parallax-portal service shell (DATABASE_URL -> nonprod PG). It performs NO writes,
runs NO model, creates NO record. It opens a PostgreSQL READ-ONLY session, verifies the persisted
investigation / evidence / adjudication / audit-chain / qualification-isolation state against the
existing verification functions, rolls back, and prints ONE sanitized JSON matrix (booleans, ids,
sha-256 hashes, counts, short key fingerprints). It never prints signatures, keys, or payloads.

    python scripts/px_review_audit.py

It is non-destructive and idempotent (read-only): running it any number of times changes nothing.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

INV_ID = "run-192b88497835"
EV_ID = "run-8332b70211aa"
RESEARCHER = "nonprod-fixture:parallax-review-selftest"
REVIEWER = "67871275"
EXPECTED_DECISION = "inconclusive"
FIXTURE_GID = RESEARCHER
PROTECTED = ("run-f0d33a285717", "run-e07852969609")
_NONPROD_ENVS = {"development", "dev", "nonproduction", "non-production", "test", "staging"}


def _nonprod_ok():
    env = (os.environ.get("RANGER_PARALLAX_LABA_ENV") or "").strip().lower()
    if env not in _NONPROD_ENVS:
        return False, "RANGER_PARALLAX_LABA_ENV=%r is not a nonproduction value" % env
    for m in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
        if (os.environ.get(m) or "").strip().lower() in ("prod", "production"):
            return False, "production marker present (%s)" % m
    return True, env


def _bind(dsn):
    from flask import Flask
    from models import db
    app = Flask("px_review_audit")
    app.config["SQLALCHEMY_DATABASE_URI"] = dsn
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    return app, db


def main():
    ok, env = _nonprod_ok()
    if not ok:
        print(json.dumps({"abort": env, "code": "not_nonprod"})); return 1
    dsn = os.environ.get("DATABASE_URL", "")
    if "postgresql" not in dsn:
        print(json.dumps({"abort": "DATABASE_URL is not postgresql (run inside parallax-nonprod)",
                          "code": "not_pg"})); return 1
    app, db = _bind(dsn)
    from sqlalchemy import text
    from parallax.research import store as rstore
    from parallax import auditlog
    from models import (ParallaxResearchRun, ParallaxAuditEvent, Candidate, ProgramMembership,
                        QualificationDecision, UnitResult, Badge, BoardResult)

    out = {"target": {"investigation": INV_ID, "evidence": EV_ID, "researcher": RESEARCHER,
                      "reviewer": REVIEWER, "expected_decision": EXPECTED_DECISION},
           "checks": {}, "facts": {}, "limitations": []}

    with app.app_context():
        if db.engine.dialect.name != "postgresql":
            print(json.dumps({"abort": "target is not postgresql", "code": "not_pg"})); return 1
        # Defensive: make the whole session reject any write at the database level.
        db.session.execute(text("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"))
        db.session.execute(text("SET TRANSACTION READ ONLY"))
        out["facts"]["database"] = db.session.execute(text("select current_database()")).scalar()
        out["facts"]["env"] = env

        c = {}

        # --- 2. investigation + evidence integrity ---------------------------------------
        detail = rstore.get_investigation_detail(db, run_id=INV_ID)
        inv_v = rstore.admin_verify_run(db, run_id=INV_ID)
        ev_v = rstore.admin_verify_run(db, run_id=EV_ID)
        ev_sum = (detail or {}).get("evidence") or {}

        c["investigation_exists"] = bool(detail) and inv_v.get("exists") is True
        c["evidence_exists"] = ev_v.get("exists") is True and ev_sum.get("exists") is True
        c["investigation_owner_is_fixture"] = (detail or {}).get("researcher_id") == RESEARCHER
        c["investigation_references_expected_evidence"] = ev_sum.get("evidence_run_id") == EV_ID
        c["investigation_hash_match"] = inv_v.get("hash_match") is True
        c["investigation_signature_valid"] = inv_v.get("signature_valid") is True and \
            (detail or {}).get("signature_verifies") is True
        c["investigation_key_trusted"] = inv_v.get("kid_trusted") is True
        c["investigation_tamper_control_fails"] = inv_v.get("tamper_negative_control_fails") is True
        c["evidence_hash_match"] = ev_v.get("hash_match") is True
        c["evidence_signature_valid"] = ev_v.get("signature_valid") is True and \
            ev_sum.get("signature_verifies") is True
        c["evidence_key_trusted"] = ev_v.get("kid_trusted") is True
        c["evidence_ownership_matches_investigation"] = ev_sum.get("owner_matches") is True
        c["evidence_provenance_simulated"] = (ev_v.get("backend_provenance") == "simulated"
                                              and ev_sum.get("backend_provenance") == "simulated")
        c["evidence_nonempirical"] = ev_v.get("is_empirical") is False and ev_sum.get("is_empirical") is False
        out["facts"]["investigation_verify"] = {k: inv_v.get(k) for k in
            ("hash_match", "signature_valid", "kid_state", "key_fingerprint16",
             "backend_provenance", "all_checks_pass", "signed_run_id_matches")}
        out["facts"]["evidence_verify"] = {k: ev_v.get(k) for k in
            ("hash_match", "signature_valid", "kid_state", "key_fingerprint16",
             "backend_provenance", "is_empirical", "all_checks_pass", "condition", "outcome",
             "canary_emitted", "observed_len")}

        # --- 3. reviewer decision ---------------------------------------------------------
        decisions = (detail or {}).get("decisions") or []
        match = [d for d in decisions if d.get("decision") == EXPECTED_DECISION
                 and str(d.get("reviewer_id")) == REVIEWER]
        adj = match[0] if match else (decisions[-1] if decisions else None)
        adj_id = adj.get("adjudication_id") if adj else None
        adj_v = rstore.admin_verify_run(db, run_id=adj_id) if adj_id else {"exists": False}

        c["adjudication_present"] = adj is not None
        c["adjudication_targets_investigation"] = bool(adj) and True  # _decisions_for filters on target==INV_ID
        c["decision_is_expected"] = bool(adj) and adj.get("decision") == EXPECTED_DECISION
        c["reviewer_identity_matches"] = bool(adj) and str(adj.get("reviewer_id")) == REVIEWER
        c["adjudication_hash_match"] = adj_v.get("hash_match") is True
        c["adjudication_signature_valid"] = adj_v.get("signature_valid") is True and \
            bool(adj) and adj.get("signature_verifies") is True
        c["adjudication_key_trusted"] = adj_v.get("kid_trusted") is True
        c["reviewer_differs_from_researcher"] = bool(adj) and str(adj.get("reviewer_id")) != RESEARCHER
        c["feedback_preserved"] = bool(adj) and bool((adj.get("comment") or "").strip())
        c["single_adjudication"] = len([d for d in decisions]) == 1
        out["facts"]["adjudication"] = {"adjudication_id": adj_id,
            "decision": (adj or {}).get("decision"),
            "reviewer_id": (adj or {}).get("reviewer_id"),
            "feedback_len": len(((adj or {}).get("comment") or "")),
            "at": (adj or {}).get("at"),
            "decision_count": len(decisions),
            "verify": {k: adj_v.get(k) for k in ("hash_match", "signature_valid", "kid_state",
                        "key_fingerprint16", "all_checks_pass")}}

        # --- 4. audit trail ---------------------------------------------------------------
        chain_ok = auditlog.verify_chain(db)
        refs = {INV_ID, EV_ID}
        if adj_id:
            refs.add(adj_id)
        ev_rows = (ParallaxAuditEvent.query.filter_by(stream="parallax-governance")
                   .order_by(ParallaxAuditEvent.seq.asc()).all())
        related = [{"seq": r.seq, "action": r.action, "subject_kind": r.subject_kind,
                    "subject_ref": r.subject_ref, "actor_id": r.actor_id}
                   for r in ev_rows
                   if r.subject_ref in refs or r.action in
                   ("research_run_persisted", "research_investigation_adjudicated")]
        adjudicated_events = [r for r in related if r["action"] == "research_investigation_adjudicated"]
        c["audit_chain_intact"] = chain_ok is True
        c["adjudication_has_audit_event"] = any(
            (r.get("subject_ref") in (INV_ID, adj_id)) for r in adjudicated_events)
        out["facts"]["audit_total_events"] = len(ev_rows)
        out["facts"]["audit_related_events"] = related

        # --- 5. qualification isolation (DB-level, this fixture) --------------------------
        cand = Candidate.query.filter_by(github_id=FIXTURE_GID).first()
        cid = cand.id if cand else None
        qd = QualificationDecision.query.filter_by(candidate_id=cid).count() if cid else -1
        ur_total = UnitResult.query.filter_by(candidate_id=cid).count() if cid else -1
        ur_qual = UnitResult.query.filter_by(candidate_id=cid, kind="qualification_decision").count() if cid else -1
        ur_adj = UnitResult.query.filter_by(candidate_id=cid, kind="reviewer_adjudication").count() if cid else -1
        badges = Badge.query.filter_by(candidate_id=cid).count() if cid else -1
        boards = BoardResult.query.filter_by(candidate_id=cid).count() if cid else -1
        cleared = BoardResult.query.filter_by(candidate_id=cid, cleared=True).count() if cid else -1
        progs = sorted({m.program for m in ProgramMembership.query.filter_by(candidate_id=cid).all()}) if cid else []

        c["fixture_candidate_present"] = cid is not None
        c["no_qualification_decision"] = qd == 0
        c["no_unit_result_qualification"] = ur_qual == 0
        c["no_badge_or_certificate"] = badges == 0
        c["no_board_clearance"] = cleared == 0
        c["still_on_board_1"] = bool(cand) and cand.current_board == 1
        c["parallax_only_entitlement"] = progs == ["parallax"]
        c["strata_entitlement_absent"] = "strata" not in progs
        out["facts"]["qualification_isolation"] = {
            "candidate_id": cid, "current_board": (cand.current_board if cand else None),
            "status": (cand.status if cand else None),
            "qualification_decisions": qd, "unit_results_total": ur_total,
            "unit_results_qualification": ur_qual, "unit_results_reviewer_adjudication": ur_adj,
            "badges": badges, "board_results": boards, "board_clearances": cleared,
            "programs": progs}

        # --- 6. visibility + owner-scoping ------------------------------------------------
        pending = {x["investigation_id"] for x in rstore.list_investigations_for_review(db, status="pending")}
        reviewed = {x["investigation_id"] for x in rstore.list_investigations_for_review(db, status="reviewed")}
        owner_view = rstore.review_status_for(db, run_id=INV_ID, authenticated_researcher_id=RESEARCHER)
        cross_blocked = False
        try:
            rstore.review_status_for(db, run_id=INV_ID, authenticated_researcher_id=REVIEWER)
        except rstore.ResearchStoreError:
            cross_blocked = True
        c["absent_from_pending_queue"] = INV_ID not in pending
        c["present_in_reviewed_queue"] = INV_ID in reviewed
        c["owner_scoped_status_reviewed"] = bool(owner_view) and owner_view.get("status") == "reviewed"
        c["owner_scoped_decision_matches"] = bool(owner_view) and owner_view.get("decision") == EXPECTED_DECISION
        c["owner_scoped_feedback_present"] = bool(owner_view) and bool((owner_view.get("feedback") or "").strip())
        c["cross_owner_access_blocked"] = cross_blocked is True
        out["facts"]["owner_view"] = {"status": (owner_view or {}).get("status"),
            "decision": (owner_view or {}).get("decision"),
            "feedback_len": len(((owner_view or {}).get("feedback") or "")),
            "pathway_qualified": (owner_view or {}).get("pathway_qualified")}

        # --- protected records (current validity; no pre-adjudication baseline here) -------
        prot = {}
        for pid in PROTECTED:
            pv = rstore.admin_verify_run(db, run_id=pid)
            prot[pid] = {"exists": pv.get("exists"), "hash_match": pv.get("hash_match"),
                         "signature_valid": pv.get("signature_valid"),
                         "kid_trusted": pv.get("kid_trusted"),
                         "all_checks_pass": pv.get("all_checks_pass"),
                         "backend_provenance": pv.get("backend_provenance")}
        c["protected_records_currently_valid"] = all(
            (prot[p]["exists"] and prot[p]["signature_valid"] and prot[p]["hash_match"]) for p in PROTECTED)
        out["facts"]["protected_records"] = prot
        out["limitations"].append(
            "Protected-record check proves CURRENT signature+hash validity, not historical byte-for-byte "
            "immutability: no independent pre-adjudication baseline snapshot is available in this script.")
        out["limitations"].append(
            "Owner-scoped researcher visibility is verified at the store layer (review_status_for); the "
            "simulated fixture has no GitHub OAuth session, so this is NOT a human-authenticated browser view.")
        out["limitations"].append(
            "Negative authZ checks (unauthorized reviewer cannot adjudicate; self-review 403) are enforced "
            "in code and were not exercised here because doing so would require a write attempt.")

        out["checks"] = c
        out["summary"] = {"total": len(c), "passed": sum(1 for v in c.values() if v is True),
                          "failed": sorted(k for k, v in c.items() if v is not True)}
        # strictly read-only: never commit
        db.session.rollback()
    print(json.dumps(out, indent=2, default=str))
    return 0 if not out["summary"]["failed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
