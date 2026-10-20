# Recovery-key generation and custody (Stage 2, item B)

Scope: a secure, practical procedure for the age recovery keypair such that the private identity is
NEVER uploaded into Railway and NEVER pasted into chat, the backup runner receives only the public
recipient, and an authorized operator can still restore later. No real keypair is generated here.
Companion: `BACKUP_DR_STAGE2_READINESS.md`.

## Key model
Backups are encrypted with age (X25519). Encryption needs only the PUBLIC recipient (`age1...`);
decryption needs the PRIVATE identity. The runner is given only the recipient, so it can create
backups it cannot read. `scripts/pg_backup.py` accepts one recipient (`RANGER_BACKUP_AGE_RECIPIENT`)
or several via `RANGER_BACKUP_AGE_RECIPIENTS_FILE` (one `age1...` per line), which enables multi-
custodian encryption.

## Trust boundary (what holds the private identity, what never does)
- NEVER holds the private identity: the backup runner, any Railway variable or secret, this chat,
  the git repository, CI logs, the S3 bucket.
- HOLDS the private identity: an operator-controlled custody location only (hardware token, or an
  offline/encrypted secret store), used only on a dedicated restore host at restore time.

## Option 1 (recommended): hardware-backed identity, non-exportable
Use `age-plugin-yubikey` so the private key is generated on and never leaves a hardware token.

Generation (operator, on a trusted workstation; illustrative, do not run here):
```
age-plugin-yubikey            # generates a slot key ON the YubiKey; prints the public recipient age1yubikey1...
```
- Give the runner only the printed `age1yubikey1...` recipient.
- Enroll TWO tokens as TWO recipients (encrypt to both) so either can decrypt; store them in separate
  safes held by two custodians. This is continuity without any exportable secret.
- Restore requires physical possession of a token plus its PIN; the private key is non-exportable, so
  it cannot be uploaded to Railway or pasted anywhere even by mistake.

## Option 2 (practical): software identity, passphrase-wrapped, offline escrow
Generation (operator, on a trusted/offline workstation; illustrative, do not run here):
```
age-keygen -o ranger-nonprod-backup.identity         # writes the identity; prints Public key: age1...
age -p -o ranger-nonprod-backup.identity.age ranger-nonprod-backup.identity   # passphrase-wrap the identity
shred -u ranger-nonprod-backup.identity              # remove the plaintext identity
```
- Give the runner only the `age1...` recipient from the keygen output.
- Store `ranger-nonprod-backup.identity.age` (passphrase-wrapped) in the org password manager as a
  secret item, AND keep one offline copy (encrypted USB or printed in a sealed envelope) in a safe.
  Store the passphrase separately from the wrapped file (different custodian or vault).
- Optional higher assurance: split the passphrase or the identity with an M-of-N secret-sharing tool
  so no single person can decrypt alone.

## Restore without exposing the private identity to the backup service
Restores run on a SEPARATE authorized operator host, never on the runner and never inside Railway:
1. Download the chosen `*.dump.age` (+ `.sha256`, `.manifest.json`) from `ranger-nonprod-backups`
   using read-scoped bucket credentials.
2. Verify the sidecar SHA-256 against the artifact.
3. Decrypt locally with the offline identity: `age -d -i <identity>` (Option 2) or the YubiKey plugin
   (Option 1). The identity stays on the operator host / token; it is never set as a Railway variable.
4. Restore-verify into a disposable or new target and require exit 0:
   `python scripts/pg_restore_verify.py <dump.age> --identity <identity>`.
5. Promote only by a deliberate cutover; the live DB is never overwritten by the drill.

Because decryption happens only on the operator host, the backup service remains incapable of reading
any backup it produced, and the private identity is never transmitted to Railway or chat.

## Key rotation and continuity
- Rotation: generate a new recipient, add it to `RANGER_BACKUP_AGE_RECIPIENTS_FILE` ALONGSIDE the old
  one so new backups are decryptable by both during an overlap window; retire the old recipient after
  the retention window passes. age supports multiple `-r` recipients, so historical backups stay
  decryptable by their original identity.
- Continuity: at least two custodians or two enrolled recipients (two YubiKeys, or password-manager +
  offline escrow) so loss of one does not lose recoverability.
- Compromise response: if an identity may be exposed, rotate the recipient immediately, re-encrypt or
  let old artifacts age out within the window, and revoke the exposed custody copy. A recipient
  leaking is harmless (public); only identity exposure matters.

## What the runner receives (and only this)
- `RANGER_BACKUP_AGE_RECIPIENT` = `age1...` (public), or `RANGER_BACKUP_AGE_RECIPIENTS_FILE` listing
  public recipients. Nothing else key-related. No identity, no passphrase.

## Remaining operator actions for item B
- Choose Option 1 (hardware, recommended) or Option 2 (software + escrow).
- Generate the keypair offline on a trusted host (Claude will not generate it). Record only the
  `age1...` recipient for the runner.
- Place the private identity in the chosen custody location with a second custodian or second
  recipient for continuity; confirm the passphrase/token is stored separately.
- Keep the restore procedure above with the custody records so a future operator can recover without
  exposing the identity to Railway or chat.
