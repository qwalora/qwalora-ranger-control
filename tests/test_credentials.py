"""Verifiable-credential export: reproduce the signed badge claim, export it as an
offline-verifiable Open Badge 3.0, and prove a third party can verify it with nothing but a
standard Ed25519 library and the published public key. Also covers the public routes.
"""
import base64
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("SECRET_KEY", "cred-test-key")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

import credentials  # noqa: E402
import signing  # noqa: E402


BADGE = dict(handle="ranger-ada", cohort="2026-A", level="certified",
             name="Certified", role="Ranger")


def _issued():
    import datetime as dt
    return dt.datetime(2026, 11, 20, 15, 30, tzinfo=dt.timezone.utc)


def _sign_badge(**over):
    d = {**BADGE, "issued_at": _issued(), **over}
    claim = credentials.badge_claim(d["handle"], d["cohort"], d["level"], d["name"],
                                    d["role"], d["issued_at"])
    return d, signing.sign(claim)


def _third_party_verify(vc):
    """Verify exactly as an external party would: recompute canonical bytes and check the
    Ed25519 signature against the embedded public key. No Ranger code in the trust path."""
    proof = vc["proof"]
    canon = json.dumps(proof["signedClaim"], sort_keys=True, separators=(",", ":")).encode()
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(proof["publicKeyBase64"]))
    pub.verify(base64.b64decode(proof["proofValue"]), canon)   # raises on failure


def test_reproduced_claim_verifies_and_tamper_fails():
    d, sig = _sign_badge()
    assert credentials.verify_badge(d["handle"], d["cohort"], d["level"], d["name"],
                                    d["role"], d["issued_at"], sig) is True
    # any changed field breaks verification (the signature is over the exact claim)
    assert credentials.verify_badge(d["handle"], d["cohort"], d["level"], "Tracker",
                                    d["role"], d["issued_at"], sig) is False


def test_exported_open_badge_verifies_offline_by_a_third_party():
    d, sig = _sign_badge()
    vc = credentials.to_open_badge(handle=d["handle"], person_name="Ada R.", cohort=d["cohort"],
                                   level=d["level"], badge_name=d["name"], role=d["role"],
                                   issued_at=d["issued_at"], signature=sig, cert_id="QR-2345-6789",
                                   base_url="https://ranger.qwalora.com")
    # shape
    assert "OpenBadgeCredential" in vc["type"]
    assert vc["credentialSubject"]["identifier"] == "ranger-ada"
    assert vc["proof"]["proofValue"] == sig and vc["proof"]["publicKeyBase64"]
    # platform-side and third-party verification both pass
    assert credentials.verify_open_badge(vc) is True
    _third_party_verify(vc)   # raises if not verifiable with just the published key


def test_tampered_export_is_rejected():
    d, sig = _sign_badge()
    vc = credentials.to_open_badge(handle=d["handle"], person_name="Ada R.", cohort=d["cohort"],
                                   level=d["level"], badge_name=d["name"], role=d["role"],
                                   issued_at=d["issued_at"], signature=sig, cert_id="QR-2345-6789")
    vc["proof"]["signedClaim"]["level"] = "1"   # forge an upgrade
    assert credentials.verify_open_badge(vc) is False
    with pytest.raises(Exception):
        _third_party_verify(vc)


def test_public_key_set_has_no_private_material():
    ks = credentials.public_key_set()
    assert ks["alg"] == "Ed25519" and ks["keys"]
    blob = json.dumps(ks)
    for e in ks["keys"]:
        assert e["public_b64"]
        assert "seed" not in e and "private" not in e
    assert "seed" not in blob


@pytest.fixture()
def appctx():
    import importlib
    import app as appmod
    importlib.reload(appmod)
    from models import db
    application = appmod.create_app()
    ctx = application.app_context()
    ctx.push()
    db.drop_all()
    db.create_all()
    yield application, db
    ctx.pop()


def _seed_cert(db, cert_id="QR-2345-6789", revoked=False):
    from models import Candidate, Badge
    c = Candidate(handle="ranger-ada", name="Ada R.", email="ada@e", cohort="2026-A",
                  github_id="ranger-ada", status="graduated", current_board=6, token="tok-ada")
    db.session.add(c)
    db.session.commit()
    issued = _issued()
    claim = credentials.badge_claim(c.handle, c.cohort, "certified", "Certified", "Ranger", issued)
    b = Badge(candidate_id=c.id, level="certified", name="Certified", role="Ranger",
              issued_at=issued, signature=signing.sign(claim), cert_id=cert_id, revoked=revoked)
    db.session.add(b)
    db.session.commit()
    return c, b


def test_route_serves_offline_verifiable_credential(appctx):
    application, db = appctx
    _seed_cert(db)
    cl = application.test_client()
    r = cl.get("/credentials/QR-2345-6789")
    assert r.status_code == 200
    vc = json.loads(r.data)
    assert credentials.verify_open_badge(vc) is True
    _third_party_verify(vc)


def test_route_keyset_endpoint_publishes_active_key(appctx):
    application, db = appctx
    cl = application.test_client()
    r = cl.get("/.well-known/ranger-credentials.json")
    assert r.status_code == 200
    ks = json.loads(r.data)
    assert any(e["state"] == "active" and e["public_b64"] for e in ks["keys"])
    assert "seed" not in r.data.decode()


def test_route_404_on_unknown_and_revoked(appctx):
    application, db = appctx
    _seed_cert(db, cert_id="QR-2345-6789", revoked=True)
    cl = application.test_client()
    assert cl.get("/credentials/QR-2345-6789").status_code == 404   # revoked hidden
    assert cl.get("/credentials/QR-9999-9999").status_code == 404   # unknown
    assert cl.get("/credentials/not-a-cert").status_code == 404     # unparseable
