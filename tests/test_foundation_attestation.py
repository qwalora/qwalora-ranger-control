"""Foundation self-attestation is a tamper-evident, signed record (not a bare boolean)."""
import app as A
from models import db, Candidate, ProgramMembership, FoundationAttestation
import netacad_foundation as NF
import signing


def _strata_candidate(gid):
    c = Candidate(handle=gid, name=gid, email=gid + "@nonprod.invalid", cohort="2026-A",
                  github_id=gid, status="active", current_board=1)
    db.session.add(c); db.session.commit()
    db.session.add(ProgramMembership(candidate_id=c.id, program="strata", status="active",
                                     cohort="2026-A")); db.session.commit()
    return c.id


def test_attestation_is_signed_and_carries_reference(client):
    with A.app.app_context():
        cid = _strata_candidate("found-sign")
        course = NF.required_course_keys("strata")[0]
    with client.session_transaction() as sess:
        sess["cand"] = cid
        sess["csrf"] = "t"
    r = client.post("/me/foundation/attest",
                    data={"program": "strata", "course": course, "done": "1",
                          "reference": "NETACAD-CERT-99town", "csrf": "t"})
    assert r.status_code == 200, r.data
    with A.app.app_context():
        row = FoundationAttestation.query.filter_by(candidate_id=cid, course_key=course).first()
        assert row is not None
        assert row.claimed_ref == "NETACAD-CERT-99town"
        assert row.attestation_sig, "attestation is unsigned"
        c = db.session.get(Candidate, cid)
        claim = {"kind": "foundation-attestation", "handle": c.handle, "program": "strata",
                 "course": course, "reference": "NETACAD-CERT-99town",
                 "at": A._iso(row.attested_at)}
        assert signing.verify(claim, row.attestation_sig)
