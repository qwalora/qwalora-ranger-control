"""F2 tests - the typed evidence contract + media artifact interfaces, and its integration
with the assessment contract.

Covers: malformed references; cross-candidate access; cross-cohort isolation; forged hashes;
unauthorized artifacts; immutable evidence (versioned revisions + signature tamper); unsupported
artifact/contract versions; expired/revoked access; media safety (content-type, size, path
traversal, unsafe formats); C2PA-missing != manipulated; model scores advisory-only; unsupported
evaluator types fail closed; PARALLAX qualification inactive; STRATA unchanged; persistence.
Offline (no object storage, no media processing, no cluster).
"""
import copy
import datetime as dt
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "f2-test-secret")
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import program                                   # noqa: E402
from siem import evidence_types as et            # noqa: E402
from siem import assessment_contract as ac       # noqa: E402
from siem import evaluator as ev                 # noqa: E402

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


H = hashlib.sha256(b"payload-bytes").hexdigest()


def _image(**over):
    ref = et.blob_ref("blob/" + H, H, "image/jpeg", 2048)
    a = et.new_artifact(evidence_type=et.EV_MEDIA_IMAGE, case_id=10, candidate_id=1,
                        cohort="2026-A", pathway="parallax", source_identity="evidence-intake",
                        content_hash=H, blob=ref)
    a.update(over)
    return a


def run():
    # ---- valid artifact + signing/immutability -------------------------------------
    img = _image()
    check("valid media-image artifact validates", et.validate_artifact(img)["ok"])
    signed = et.sign_artifact(img)
    check("artifact signs + verifies", et.verify_artifact(signed))
    mut = copy.deepcopy(signed); mut["artifact"]["candidate_id"] = 999
    check("mutating a signed artifact breaks verification (immutable)", not et.verify_artifact(mut))
    rev = et.revise(img, {"validation_state": "validated"})
    check("revision is a new version superseding the prior (prior untouched)",
          rev["version"] == 2 and rev["supersedes"] == img["evidence_id"]
          and img["version"] == 1 and img["validation_state"] == "unvalidated")

    # ---- malformed references ------------------------------------------------------
    bad = _image(); bad["content_hash"] = "not-a-hash"
    check("malformed content_hash rejected",
          any(e["code"] == "BAD_CONTENT_HASH" for e in et.validate_artifact(bad)["errors"]))
    nofield = _image(); del nofield["cohort"]
    check("missing required field rejected",
          any(e["code"] == "MISSING_FIELD" for e in et.validate_artifact(nofield)["errors"]))

    # ---- forged hash (BlobRef sha256 != envelope content_hash) ---------------------
    forged = _image(); forged["blob_ref"] = et.blob_ref("blob/" + H, hashlib.sha256(b"other").hexdigest(),
                                                        "image/jpeg", 2048)
    check("forged blob hash (mismatch with envelope) rejected",
          any(e["code"] == "HASH_MISMATCH" for e in et.validate_artifact(forged)["errors"]))

    # ---- media safety: content-type, size, path traversal, unsafe format -----------
    badtype = _image(); badtype["blob_ref"] = et.blob_ref("blob/" + H, H, "image/svg+xml", 2048)
    check("unsafe/disallowed media type rejected",
          any(e["code"] == "UNSUPPORTED_MEDIA_TYPE" for e in et.validate_artifact(badtype)["errors"]))
    oversize = _image(); oversize["blob_ref"] = et.blob_ref("blob/" + H, H, "image/jpeg", 500 * et.MB)
    check("oversize media rejected",
          any(e["code"] == "BLOB_TOO_LARGE" for e in et.validate_artifact(oversize)["errors"]))
    for evil in ("../../etc/passwd", "/abs/path", "file:///etc/passwd", "blob/../x"):
        trav = _image(); trav["blob_ref"] = et.blob_ref(evil, H, "image/jpeg", 2048)
        if not any(e["code"] == "UNSAFE_BLOB_URI" for e in et.validate_artifact(trav)["errors"]):
            check(f"path-traversal uri rejected ({evil})", False); break
    else:
        check("path-traversal / unsafe BlobRef uris all rejected", True)

    # ---- C2PA-missing != manipulated; model score advisory-only --------------------
    interp = et.interpret_provenance(_image())   # no c2pa manifest present
    check("missing C2PA manifest => 'indeterminate', never 'manipulated'",
          interp["provenance_verdict"] == "indeterminate" and interp["authoritative"] is False)
    scored = _image()
    scored["blob_ref"] = et.blob_ref("blob/" + H, H, "image/jpeg", 2048, authenticity_assessment=0.97)
    check("model authenticity score is stored advisory-only (never authoritative)",
          et.validate_artifact(scored)["ok"]
          and et.interpret_provenance(scored)["model_authenticity_advisory"] == 0.97
          and et.interpret_provenance(scored)["authoritative"] is False)
    nonadv = _image()
    nonadv["authenticity_assessment"] = {"advisory": False, "verdict": "authentic"}
    check("a non-advisory authenticity claim is rejected",
          any(e["code"] == "NON_ADVISORY_AUTHENTICITY" for e in et.validate_artifact(nonadv)["errors"]))

    # ---- unsupported artifact / contract versions ----------------------------------
    oldc = _image(); oldc["contract_version"] = 2
    check("unsupported contract version rejected",
          any(e["code"] == "UNSUPPORTED_CONTRACT_VERSION" for e in et.validate_artifact(oldc)["errors"]))
    olds = _image(); olds["evidence_schema_version"] = 99
    check("unsupported schema version rejected",
          any(e["code"] == "UNSUPPORTED_SCHEMA_VERSION" for e in et.validate_artifact(olds)["errors"]))
    badtype2 = _image(); badtype2["evidence_type"] = "hologram"
    check("unsupported evidence type rejected",
          any(e["code"] == "UNSUPPORTED_EVIDENCE_TYPE" for e in et.validate_artifact(badtype2)["errors"]))

    # ---- derived-artifact lineage --------------------------------------------------
    nolineage = et.new_artifact(evidence_type=et.EV_DERIVED_ARTIFACT, case_id=10, candidate_id=1,
                                cohort="2026-A", pathway="parallax", source_identity="tool",
                                content_hash=H, blob=et.blob_ref("blob/" + H, H, "image/png", 10))
    check("derived artifact without lineage rejected",
          any(e["code"] == "MISSING_LINEAGE" for e in et.validate_artifact(nolineage)["errors"]))
    derived = et.derive(rev, evidence_type=et.EV_DERIVED_ARTIFACT,
                        blob=et.blob_ref("blob/" + H, H, "image/png", 10))
    check("derive() records parent lineage + inherits case/owner/cohort/pathway",
          derived["derived_from"] == [rev["evidence_id"]] and derived["case_id"] == rev["case_id"]
          and derived["pathway"] == rev["pathway"])

    # ---- authorization: ownership, cross-candidate, cross-cohort, cross-pathway -----
    owner = {"candidate_id": 1, "cohort": "2026-A", "pathway": "parallax", "role": "candidate"}
    check("owner may access own artifact", et.authorize_access(img, requester=owner)[0])
    check("cross-candidate access denied (no existence disclosure path)",
          et.authorize_access(img, requester={**owner, "candidate_id": 2})[0] is False)
    check("cross-cohort isolation enforced",
          et.authorize_access(img, requester={**owner, "cohort": "2026-B"})[0] is False)
    check("cross-pathway isolation enforced",
          et.authorize_access(img, requester={**owner, "pathway": "strata"})[0] is False)
    check("reviewer may read within same cohort+pathway",
          et.authorize_access(img, requester={**owner, "candidate_id": 77, "role": "reviewer"})[0])

    # ---- revoked / expired access --------------------------------------------------
    revoked = _image(validation_state="revoked")
    check("revoked artifact access denied", et.authorize_access(revoked, requester=owner)[0] is False)
    expired = _image()
    expired["retention_until"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat()
    check("expired (past retention) access denied", et.authorize_access(expired, requester=owner)[0] is False)

    # ---- unsupported evaluator type fails closed -----------------------------------
    try:
        ev.get_evaluator("nonexistent_evaluator"); failed_closed = False
    except KeyError:
        failed_closed = True
    check("unsupported evaluator type fails closed (KeyError)", failed_closed)
    bp_badeval = {"pathway": "parallax", "blueprint_version": 1,
                  "objective_checks": [{"check_id": "x", "evaluator": "nonexistent_evaluator"}],
                  "decision_policy": {"type": ac.POLICY_PARALLAX_PORTFOLIO}}
    check("blueprint referencing unknown evaluator fails validation",
          any(e["code"] == "UNKNOWN_EVALUATOR" for e in ac.validate_blueprint(bp_badeval)["errors"]))

    # ---- integration with the assessment contract ----------------------------------
    validated = et.revise(img, {"validation_state": "validated"})
    req = {"kind": "media", "evidence_type": et.EV_MEDIA_IMAGE, "satisfied_by": "media_check"}
    ok_sat, why = et.satisfies_requirement(validated, req, requester=owner)
    check("validated+authorized artifact satisfies an evidence requirement", ok_sat and why == "ok")
    unval_ok, _ = et.satisfies_requirement(img, req, requester=owner)   # still 'unvalidated'
    check("an unvalidated artifact does NOT satisfy the requirement", not unval_ok)
    # feed into a decision: evidence requirement met -> gate check passes -> assessment met,
    # but PARALLAX final qualification stays inactive
    gate = ev.signed_check("media_check", True, {"evidence_id": validated["evidence_id"]})
    bp = {"pathway": "parallax", "blueprint_version": 1, "environment_version": "valyria-ai-1",
          "evidence_requirements": [{"kind": "media", "satisfied_by": "media_check", "required": True}],
          "objective_checks": [{"check_id": "media_check", "evaluator": "event_reference", "required": True}],
          "critical_failures": [], "rubric_dimensions": [{"dimension": "reasoning", "weight": 1}],
          "human_review": {"min_reviewers": 1},
          "decision_policy": {"type": ac.POLICY_PARALLAX_PORTFOLIO, "activated": True, "rubric_threshold": 50.0}}
    d = ac.decide(bp, authorization={"candidate_id": 1, "pathway": "parallax"},
                  objective_results=[gate], rubric_scores={"reasoning": 90},
                  reviewer_decision={"decision": "pass", "reviewer_id": "r1"})
    check("evidence->assessment integration: assessment MET, assessment-only (never a qualification)",
          d["assessment_passed"] and not d["qualified"] and d["reason"] == "assessment_met")

    # ---- PARALLAX inactive + STRATA unchanged --------------------------------------
    check("STRATA PASS_BAR unchanged (95.0)", program.PASS_BAR == 95.0)
    check("PARALLAX qualification remains inactive by default",
          ac.parallax_qualification_active() is False)

    # ---- persistence (sqlite via create_app) ---------------------------------------
    import app as appmod
    from models import db, Candidate, Case, EvidenceArtifact
    application = appmod.create_app(); ctx = application.app_context(); ctx.push()
    cand = Candidate(handle="f2", name="F2", email="f2@e", cohort="2026-A",
                     github_id="f2-gid", status="active", current_board=2)
    db.session.add(cand); db.session.commit()
    row = EvidenceArtifact(evidence_id=validated["evidence_id"], evidence_type=et.EV_MEDIA_IMAGE,
                           candidate_id=cand.id, cohort="2026-A", pathway="parallax",
                           content_hash=H, validation_state="validated",
                           blob_uri="blob/" + H, blob_sha256=H, blob_media_type="image/jpeg",
                           blob_bytes=2048, signature=signed["signature"])
    db.session.add(row); db.session.commit()
    check("EvidenceArtifact persists; BlobRef stored as reference (no bytes in DB)",
          EvidenceArtifact.query.count() == 1 and EvidenceArtifact.query.first().blob_uri.startswith("blob/"))
    ctx.pop()

    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_evidence_types():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
