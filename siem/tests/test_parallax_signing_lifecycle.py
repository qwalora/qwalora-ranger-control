"""PARALLAX Phase 1C Workstream A - signing-key lifecycle, rotation, and historical verification.

Uses only TEMPORARY, in-test Ed25519 keys (never production material) and an in-memory registry
override; the registry is reset after every test so no key state leaks. Exercises both the signing
layer directly and the persisted PARALLAX records (approvals, audit chain) across rotation and
compromise revocation.
"""
import base64
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("SECRET_KEY", "px1c-signing")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("DEFAULT_COHORT", "2026-A")

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402

import signing  # noqa: E402
from parallax import registry, auditlog, keyadmin  # noqa: E402
from parallax import laba_blueprint as BP  # noqa: E402

COHORT = "2026-A"


def _seed_b64():
    k = Ed25519PrivateKey.generate()
    return base64.b64encode(
        k.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())).decode()


def _pub_b64(seed_b64):
    seed = base64.b64decode(seed_b64)
    k = Ed25519PrivateKey.from_private_bytes(seed[:32])
    return base64.b64encode(
        k.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)).decode()


@pytest.fixture(autouse=True)
def _reset_keys():
    yield
    signing._reset_registry()   # never let an in-test registry leak to other suites


@pytest.fixture()
def appctx():
    saved = {k: os.environ.get(k)
             for k in ("RANGER_PARALLAX_QUALIFICATION_ACTIVE",
                       "RANGER_PARALLAX_PATHWAY_QUALIFICATION_ACTIVE", "REVIEWER_GITHUB_IDS")}
    for k in saved:
        os.environ.pop(k, None)
    import app as appmod
    from models import db
    application = appmod.create_app()
    ctx = application.app_context(); ctx.push()
    db.drop_all(); db.create_all()
    yield appmod, db
    try:
        ctx.pop()
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _seed(db):
    from models import AdminUser, Candidate
    db.session.add_all([
        AdminUser(github_id="admin-1", login="admin-1", role="reviewer"),
        Candidate(handle="gh-alice", name="A", email="a@e", cohort=COHORT, github_id="gh-alice",
                  status="active", current_board=1),
    ])
    db.session.commit()


def _admin(db, gid="admin-1"):
    from models import AdminUser
    return AdminUser.query.filter_by(github_id=gid).first()


# --- signing-layer lifecycle ---------------------------------------------------------------------
def test_sign_A_verify_A_then_rotate_to_B():
    A, B = _seed_b64(), _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A}], "A")
    rec = {"claim": "x", "n": 1}
    sigA = signing.sign(rec)
    assert signing.active_kid() == "A"
    assert signing.verify(rec, sigA, kid="A") is True            # sign A, verify A

    # rotate: B active, A verify-only
    signing._install_registry([{"kid": "A", "state": "verify_only", "seed_b64": A},
                               {"kid": "B", "state": "active", "seed_b64": B}], "B")
    assert signing.active_kid() == "B"
    recB = {"claim": "y", "n": 2}
    sigB = signing.sign(recB)
    assert signing.verify(recB, sigB, kid="B") is True           # new B records verify
    assert signing.verify(rec, sigA, kid="A") is True            # historical A under authorized policy
    assert signing.verify(rec, sigA) is True                     # legacy (no kid) under trusted policy


def test_reject_unknown_altered_kid_and_signature_substitution():
    A, B = _seed_b64(), _seed_b64()
    signing._install_registry([{"kid": "A", "state": "verify_only", "seed_b64": A},
                               {"kid": "B", "state": "active", "seed_b64": B}], "B")
    rec = {"claim": "x"}
    sigA = signing.sign({"claim": "x", "by": "A-not-active"})     # a stray signature
    sigA = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(base64.b64decode(A)[:32]).sign(signing.canonical(rec))
    ).decode()
    assert signing.verify(rec, sigA, kid="A") is True
    assert signing.verify(rec, sigA, kid="Z") is False           # unknown kid -> fail closed
    assert signing.verify(rec, sigA, kid="B") is False           # altered kid (A sig, claims B)
    # signature substitution: a valid signature over DIFFERENT content must not verify for rec
    sig_other = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(base64.b64decode(A)[:32]).sign(signing.canonical({"z": 9}))
    ).decode()
    assert signing.verify(rec, sig_other, kid="A") is False


def test_revoked_key_is_never_trusted_even_historically():
    A, B = _seed_b64(), _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A}], "A")
    rec = {"claim": "pre-compromise"}
    sigA = signing.sign(rec)
    # emergency revocation of A (compromise), B becomes active
    signing._install_registry([{"kid": "A", "state": "revoked", "seed_b64": A},
                               {"kid": "B", "state": "active", "seed_b64": B}], "B")
    assert signing.verify(rec, sigA, kid="A") is False           # revoked -> fail closed
    assert signing.verify(rec, sigA) is False                    # not implicitly trusted via legacy path
    assert signing.key_state("A") == "revoked"


def test_retired_key_still_verifies_history():
    A, B = _seed_b64(), _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A}], "A")
    rec = {"claim": "old"}
    sigA = signing.sign(rec)
    signing._install_registry([{"kid": "A", "state": "retired", "seed_b64": A},
                               {"kid": "B", "state": "active", "seed_b64": B}], "B")
    assert signing.verify(rec, sigA, kid="A") is True            # planned retirement still verifies
    assert signing.verify(rec, sigA) is True


def test_unavailable_private_material_fails_closed_but_still_verifies():
    A = _seed_b64()
    # active key present by PUBLIC only (no seed): signing must fail, verification must still work
    signing._install_registry([{"kid": "A", "state": "active", "public_b64": _pub_b64(A)}], "A")
    # a signature made out-of-band by the real private key still verifies
    sig = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(base64.b64decode(A)[:32]).sign(
            signing.canonical({"c": 1}))).decode()
    assert signing.verify({"c": 1}, sig, kid="A") is True
    with pytest.raises(LookupError):
        signing.sign({"c": 1})                                   # no private material -> fail closed


def test_public_registry_never_exposes_private_material():
    A = _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A}], "A")
    pub = signing.public_registry()
    blob = repr(pub) + "".join(repr(e) for e in signing._registry().values())
    assert A not in blob and "seed" not in blob.lower()
    assert all(set(k) == {"kid", "alg", "state", "public_b64"} for k in pub)


# --- persisted records across rotation (DB-backed) -----------------------------------------------
def test_persisted_approval_and_audit_survive_rotation_fail_on_revocation(appctx):
    _appmod, db = appctx
    _seed(db)
    A, B = _seed_b64(), _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A}], "A")

    approval, row = registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
    from models import ParallaxApproval
    assert ParallaxApproval.query.first().signing_kid == "A"     # kid recorded alongside
    assert auditlog.verify_chain(db) is True

    # rotate A -> verify_only, B active (simulated restart: drop the session, keep the DB + registry)
    signing._install_registry([{"kid": "A", "state": "verify_only", "seed_b64": A},
                               {"kid": "B", "state": "active", "seed_b64": B}], "B")
    db.session.remove()
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is not None   # history OK
    assert auditlog.verify_chain(db) is True

    # a NEW audit event is signed by B; the mixed A+B chain still verifies
    keyadmin.snapshot_public_registry(db, principal=_admin(db))
    from models import ParallaxAuditEvent
    kids = {e.signing_kid for e in ParallaxAuditEvent.query.all()}
    assert "A" in kids and "B" in kids
    assert auditlog.verify_chain(db) is True

    # compromise: revoke A -> historical A-signed approval and chain fail closed
    signing._install_registry([{"kid": "A", "state": "revoked", "seed_b64": A},
                               {"kid": "B", "state": "active", "seed_b64": B}], "B")
    db.session.remove()
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is None
    assert auditlog.verify_chain(db) is False


def test_altered_stored_kid_rejected(appctx):
    _appmod, db = appctx
    _seed(db)
    A, B = _seed_b64(), _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A},
                               {"kid": "B", "state": "verify_only", "seed_b64": B}], "A")
    registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
    from models import ParallaxApproval
    row = ParallaxApproval.query.first()
    row.signing_kid = "B"              # tamper: claim a different (trusted) key
    db.session.commit(); db.session.remove()
    # signature was made by A, so verifying under B fails -> approval is not returned
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is None


def test_unauthorized_key_registry_change_rejected(appctx):
    _appmod, db = appctx
    _seed(db)
    A = _seed_b64()
    signing._install_registry([{"kid": "A", "state": "active", "seed_b64": A}], "A")
    # a non-admin principal cannot record a key-lifecycle event
    with pytest.raises(registry.RegistryAuthError):
        keyadmin.record_key_event(db, principal={"login": "nobody"}, action="key_revoke", kid="A")
    # an unknown action is refused
    with pytest.raises(keyadmin.KeyAdminError):
        keyadmin.record_key_event(db, principal=_admin(db), action="key_teleport", kid="A")
    # an authorized admin CAN record one, and it lands in the signed chain
    row = keyadmin.record_key_event(db, principal=_admin(db), action="key_revoke", kid="A",
                                    detail={"reason": "compromise drill"})
    assert row is not None
    from models import ParallaxAuditEvent
    ev = ParallaxAuditEvent.query.filter_by(action="key_revoke").first()
    assert ev is not None and ev.subject_ref == "A"
    assert auditlog.verify_chain(db) is True


def test_legacy_record_compat_and_failure(appctx):
    _appmod, db = appctx
    _seed(db)
    # default registry (reset): a legacy-style record with NULL kid verifies under the trusted policy
    signing._reset_registry()
    approval, row = registry.store_spec_approval(db, BP.LABA_SPEC, BP.blueprint(), principal=_admin(db))
    from models import ParallaxApproval
    r = ParallaxApproval.query.first()
    r.signing_kid = None               # force legacy shape
    db.session.commit(); db.session.remove()
    assert registry.active_spec_approval(db, BP.LABA_SPEC, BP.blueprint()) is not None  # legacy verifies
    assert auditlog.verify_chain(db) is True
