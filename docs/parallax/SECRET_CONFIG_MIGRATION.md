# Fail-closed production secret configuration — requirements, migration, rollback

Implements Sprint 1A (risk register R1, R2). Enforces explicit, stable, securely configured secrets
in production and rejects development defaults, without changing the canonical signing format,
regenerating keys, or invalidating existing signatures.

## What changed (code)
- `prodconfig.py` (new): `is_production()` (true only when an explicit marker `RANGER_ENV`/`APP_ENV`/`ENVIRONMENT`/`FLASK_ENV` is `prod`/`production`); `require_secret_key()` (fail-closed `SECRET_KEY` contract in production); `InsecureConfigError`. Reads env var names only; never logs or embeds a secret value.
- `signing.py`: `_legacy_seed()` now rejects a malformed `RANGER_SIGNING_KEY` and, in production, refuses to derive a key from `SECRET_KEY` or the `"qwalora-ranger-dev"` literal (fail closed). New `assert_signing_ready()` force-builds and validates the key registry so bad material fails at startup, not at first sign.
- `app.py` `create_app()`: calls `prodconfig.require_secret_key()` and `signing.assert_signing_ready()` first, before serving. Outside production, the historical ephemeral-`SECRET_KEY` fallback and dev key derivation are unchanged.

## Production configuration contract
Set all of the following in the production environment:
- `RANGER_ENV=production` (the authoritative production marker).
- `SECRET_KEY`: a stable, securely random value of at least 32 characters (e.g. `python -c "import os;print(os.urandom(32).hex())"`). Must not be a known placeholder. It is independent of the signing key and must not be reused as one.
- Signing material, exactly one of:
  - `RANGER_SIGNING_KEYS`: a JSON array of `{kid, alg, state, seed_b64?, public_b64?}` with exactly one `active` key carrying a private seed (the versioned registry; preferred, supports rotation and historical verification); or
  - `RANGER_SIGNING_KEY`: base64 of a 32-byte Ed25519 seed (single-key form).

If any required item is missing, too short, a placeholder, or malformed, the app refuses to boot with
`InsecureConfigError` naming the offending variable (never its value).

Nonproduction (`parallax-nonprod`) is not affected: it already sets `SECRET_KEY` and
`RANGER_SIGNING_KEY` explicitly, and without a production marker the lenient dev behavior remains.

## Safe migration sequence (operator)
1. Generate (out of band) a production `SECRET_KEY` and, if using the registry form, a production signing key; store them in the secret manager. Do not commit them. This change set does not generate, replace, or rotate any key automatically.
2. Preserve historical verification: if production will verify evidence signed under an existing key, include that key in `RANGER_SIGNING_KEYS` as `active` (if still signing with it) or `verify_only`/`retired` (if rotating to a new active key). Never drop a key that signed records you still need to verify. Revoked keys fail closed by design.
3. Set `SECRET_KEY`, the signing variable(s), and `RANGER_ENV=production` in the production environment only. Do not touch `parallax-nonprod` or production Railway variables as part of this task (deployment is separately authorized).
4. Deploy this branch to production only under separate authorization. On boot, a misconfiguration fails closed (health check never turns green) rather than starting with a weak secret.
5. Verify after boot: `/healthz` is ok; a known historical signed record still verifies (via the admin evidence verifier); `signing.active_kid()` is the intended key.

## Rollback plan
- Code rollback: this is an additive, environment-gated guard. Reverting is safe: redeploy the previous image, or revert the three files (`prodconfig.py`, `signing.py`, `app.py`). No data migration, no schema change, no key change, so there is nothing to undo in the database and no signatures are affected.
- Fast mitigation without code rollback: because the guard only triggers under a production marker, unsetting `RANGER_ENV` (and the other markers) reverts to lenient behavior. This is a last resort and reintroduces R1/R2, so prefer fixing the missing/invalid secret over disabling the guard.
- A boot that fails closed has not served traffic or mutated data; correct the environment variable named in the error and redeploy.

## Guarantees preserved
- Canonical signing format unchanged (locked by `test_canonical_format_is_unchanged`).
- Existing signatures remain valid as long as their signing key is present in the configured registry (active/verify_only/retired); verified by `test_historical_signatures_verify_after_rotation`.
- No key is regenerated, replaced, or rotated by this change; rotation remains an explicit operator action via `RANGER_SIGNING_KEYS` + `parallax/keyadmin.py`.
- No signed research evidence, audit records, reviewer decisions, or qualification data are modified.

## Administrator decisions required before deployment
- D1: Confirm `RANGER_ENV=production` as the production marker (or name the marker your platform sets).
- D2: Provision the production `SECRET_KEY` and signing key in the secret manager, and decide single-key (`RANGER_SIGNING_KEY`) vs registry (`RANGER_SIGNING_KEYS`). Registry is recommended for rotation.
- D3: Confirm which historical key id(s) must remain verifiable in production and their states.
