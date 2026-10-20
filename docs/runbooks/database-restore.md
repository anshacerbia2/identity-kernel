# Database restore

Version 1.0.0. Last reviewed 2026-10-20.

The kernel's database, the volume `postgres`, is lost or must go back to a backup. The backup is the
set `deploy/dev/backup.sh` writes daily (`deploy/dev/README.md` §Backups, STD-GLB-009 1.10.0 rule 9).
`deploy-dev` drills this procedure on every change and weekly (`scripts/dev-restore-drill.sh`,
STD-GLB-002 §Restore Evidence), and keeps its `restore-evidence` artifact.

## What a restore brings back, and what it does not

- **Back:** the realms, users and their credentials, clients and their keys, and the signing key
  provider's configuration, as they were at the backup.
- **Not in the backup:** the signing keystore and its password. They are files in `keys/signing` and
  `keys/vault`, never copied (ADR-IAM-002 §5.3). The restored realm loads the same file under the same
  `kid`, so the key set is the one published before. The drill asserts it.
- **Lost:** everything written after the backup: users created, credentials enrolled, sessions,
  clients registered and keys installed. identity-control reconciles what it registered
  (its restore runbook); tell its owner before you start.

## Steps

1. **Pick the set.** The newest complete one, unless the fault is older:

   ```sh
   ls -l /mnt/imam-storage/scnehaux-backups/identity-kernel/
   ```

   A set is `globals-<date>.sql` and `keycloak-<date>.dump`, both present. `backup.sh` keeps the newest
   14.

2. **Put `.env` and `keys/` back first,** if the host lost them, from the operator's copy. The roles
   file sets the role `keycloak`'s password hash to the one backed up, so `.env` must be the one from
   the same time. The keystore and its vault file are not in that copy. If they are gone too, the key
   is lost: the restore is a new server from zero, with a new ceremony and a new `kid`
   ([Signing-key ceremony](signing-key-ceremony.md)).

3. **Stop everything that joins the kernel's network,** identity-control and organization-control,
   then remove the old volume if it still exists. This deletes the database, which is why the set from
   step 1 must exist:

   ```sh
   cd deploy/dev
   docker compose down --volumes
   ```

4. **Restore** into the new, empty volume. The script starts `postgres` alone, refuses a database that
   holds anything, applies the roles, then the database, and stops on the first error:

   ```sh
   ./restore.sh /mnt/imam-storage/scnehaux-backups/identity-kernel/globals-<date>.sql \
                /mnt/imam-storage/scnehaux-backups/identity-kernel/keycloak-<date>.dump
   ```

5. **Start the stack** and let `realm-apply` check it:

   ```sh
   docker compose up -d --build --wait
   docker compose logs realm-apply   # ends in "... and signs with the keystore's key"
   ```

   A refusal over drift means the realm was changed after the backup's revision was recorded:
   [Console drift](console-drift.md).

6. **Confirm** the key set publishes the same `PS256` `kid` as before the loss, which the ceremony
   record names, then start identity-control and organization-control.

## Gaps

- **RPO.** A daily dump loses up to 24 hours, against the 1-minute RPO of PAD-PLT-001 §6.2. That needs
  continuous WAL archiving on the production platform; the drill records it as not met.
- **Off the host.** The backups live on the same host. A copy off the host is required before
  production (STD-GLB-009 1.10.0 rule 9); a development server records its absence.
- **A restore to an older point** is not drilled. It gives back users and clients identity-control has
  changed since, and identity-control's reconciliation handles them.
