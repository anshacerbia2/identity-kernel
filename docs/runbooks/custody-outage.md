# Custody outage at startup

Version 1.0.0. Last reviewed 2026-10-20.

The kernel cannot load its signing key. It refuses to start, or `realm-apply` refuses the realm. Both
are the design: STD-IAM-001 §3.5 prohibits per-process key generation "including as a fallback when
protected custody is unreachable", and Keycloak would otherwise generate a `fallback-PS256` key
(TDD-identity-kernel-002 1.2.0 §Startup as Built).

## Signal

One of these, on the development server, in `deploy/dev`:

| Where | Line | Meaning |
| :-- | :-- | :-- |
| `docker compose logs keycloak` | `identity-kernel: refusing to start: no realm signing keystore is mounted ...` | `keys/signing/` holds no `realm-signing-<kid>.p12`: the ceremony has not run, or the files are gone |
| same | `... the realm signing keystore ... is not readable` | a `keys/signing/realm-signing-<kid>.p12` is not readable by the kernel's user (1000) |
| same | `... the password of ..., ..., is not mounted or not readable` | its `keys/vault/scnehaux_realm-signing-<kid>` (underscores doubled) is missing or unreadable |
| same | `... does not open with the password ...`, `... holds more or fewer than one entry ...` or `... holds no entry realm-signing` | the two files do not belong together, the keystore is damaged, or it holds a second key |
| same | `... KC_VAULT_DIR is empty` | the image's default was overridden |
| `docker compose logs realm-apply` | `the signing key provider realm-signing-<kid> serves 0 keys, want 1: its keystore did not load` | the kernel started, and the provider failed to load the keystore |
| same | `the realm holds PS256 keys other than the custody keys: ... fallback-PS256` | Keycloak generated a key in-process |
| same | `the realm publishes the key ..., which is not in custody` | the realm publishes a key whose certificate is not in `keys/` |

The kernel's container restarts on each refusal (`restart: unless-stopped`), so `docker compose ps`
shows it restarting and never healthy. Nothing signs while it does.

## Steps

1. **Read the line.** `docker compose logs --tail 50 keycloak realm-apply`. It names the file or the
   check that failed.

2. **Look at the files, without reading them.** They belong to the kernel's user, so:

   ```sh
   sudo ls -la keys/ keys/signing keys/vault
   ```

   Expected, for each key: `keys/signing/realm-signing-<kid>.p12` and
   `keys/vault/scnehaux_realm-signing-<kid>`, each owned by 1000, mode `0400`, in directories of mode
   `0500`, and `keys/realm-signing-<kid>.crt`, mode `0644`. Never print the password file or copy either file anywhere.

3. **A file missing, or both missing.** On a server built from zero this means the ceremony has not
   run: run it ([Signing-key ceremony](signing-key-ceremony.md)). If the ceremony ran and the files
   are gone, the key is lost. It is not restored from anywhere, because no copy exists (STD-GLB-009
   rule 9). Rebuild the server from zero with a new ceremony and a new `kid`
   (`deploy/dev/README.md` §Never do explains what `docker compose down -v` takes with it). Every
   token signed by the old key then fails, and every application signs in again.

4. **Wrong owner or mode.** Restore them, then start again:

   ```sh
   sudo chown 1000:0 keys/signing keys/vault keys/signing/realm-signing-*.p12 keys/vault/scnehaux_realm-signing-*
   sudo chmod 0400 keys/signing/realm-signing-*.p12 keys/vault/scnehaux_realm-signing-*
   sudo chmod 0500 keys/signing keys/vault
   docker compose up -d --wait
   ```

5. **The keystore does not open with its password.** The two files are from different ceremonies, or
   one was edited. There is no way to recover a keystore without its password: treat it as step 3, a
   lost key.

6. **A `fallback-PS256` in the realm.** The kernel signed with a key it generated, so every token it
   issued since is one no consumer accepts (it is 2048 bits). Fix the cause above first, then delete
   the provider in the Admin Console (**Realm settings**, **Keys**, **Providers**) or with the Admin
   API, and run `docker compose up -d` so `realm-apply` checks the realm again. Record it as an
   incident: an unexplained fallback key is a custody failure.

7. **Confirm.** `docker compose logs realm-apply` ends in "... and signs with the keystore's key", and
   the key set publishes one `PS256` key, the ceremony record's `kid`.

## Gaps

- **Production.** The kernel's pods mount the two files through the AWS Secrets and Configuration
  Provider. A pod whose secrets cannot be mounted does not start, and `kubectl describe pod` shows a
  `FailedMount` event; CloudTrail shows whether the role's `GetSecretValue` was denied. This section
  is written when the environment exists.
- **No alert.** Nothing pages on a refusing kernel. The health check, which never turns healthy, and
  the consumers' failures are the signals today.
