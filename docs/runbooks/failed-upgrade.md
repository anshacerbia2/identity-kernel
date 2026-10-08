# Failed upgrade

Version 1.0.0. Last reviewed 2026-10-07.

A Keycloak upgrade is a change to `image/keycloak.ref`, with `image/keycloak.previous.ref` and the
digest in `deploy/dev/compose.yaml` moved in the same commit (TDD-identity-kernel-005). It can fail
in two places: in CI, before it merges, or on a server, after.

## Before every upgrade

The cheapest failed upgrade is one that can be undone. Before `git pull` on a server:

1. **A release record exists for this digest.** The `compat` workflow's `upgrade` job writes it to
   its job summary. Note its run id and its `rollback_boundary`: `reversible` or
   `irreversible-after-start`.
2. **No drift.** The read-only plan shows no `DRIFT` ([Console drift](console-drift.md)). An upgrade
   over drift discards it (TDD-identity-kernel-005 §Drift Detection Before Upgrade).
3. **A backup, taken now.** `deploy/dev/README.md` §Backups: `pg_dump`, the globals, `.env` and
   `keys/`. Keycloak's own guide says to "Back up the database" before an upgrade, because "The
   database schema will no longer be compatible with the old server after the upgrade" [R1].
4. **What consumers depend on, written down.** Save the discovery document and the key set, so
   step 6 below can compare the `issuer` and every key's `kid`:

   ```sh
   curl -fsS https://$KEYCLOAK_HOSTNAME/realms/scnehaux/.well-known/openid-configuration > before-discovery.json
   curl -fsS https://$KEYCLOAK_HOSTNAME/realms/scnehaux/protocol/openid-connect/certs > before-jwks.json
   ```

## A. The candidate fails in CI

The pull request that moves the digest fails one of these. Do not merge it.

| Job | Fails when | It means |
| :-- | :-- | :-- |
| `compat` / `contract` | Any assertion of the declared realm contract: issuer form, a covered claim, a closed creation path, the claim closure, a proof-of-concept answer | The release changes what another repository built against. TDD-identity-kernel-005: "a release that changes them is a migration rather than an upgrade" |
| `compat` / `upgrade` | `the previous release did not start on an empty database`, or `the candidate did not start on the previous release's database`, or the realm is out of sync after the upgrade | There is no working upgrade path from what the servers run |
| `compat` / `contract`, step "the theme's copied templates match the release" | A copied template is no longer the new release's template with the declared replacements | Make the copies again with `go run ./cmd/theme-overrides -jar <the new themes jar> -write`. It writes nothing when a replacement no longer finds its stock text: then a person decides (TDD-identity-kernel-004 §Override Surface) |
| `compat` / `browser` | A login page fails WCAG 2.2 A or AA in axe-core, a keyboard path, or the Content Security Policy | The new release's templates changed what the theme or the realm's policy relies on |
| `image-scan` | A High or Critical vulnerability with a fix | Move to a release that has the fix |
| `image-build` | A difference between two builds outside Keycloak's build output, or a file the kernel's layers may not hold | The build is no longer the one TDD-identity-kernel-005 §Build Reproducibility describes |

Then:

1. Read the failing test's output in the job log. Every contract property is asserted on its own,
   so the failure names it (TDD-identity-kernel-005 §Contract Assertion).
2. Decide with the owner of the repository that consumes that property: stay on the current
   release, or treat it as a migration with its own design change.
3. **A security release** may defer the `browser` job's assertions, and only those, on the
   accelerated path of TDD-identity-kernel-005 §Security Releases. The realm contract and the
   closed creation paths are "never deferred". Record the deferral in the pull request.

## B. The server does not come back

`git pull && docker compose up -d --build --wait` exits non-zero, or a consumer reports failures
after it.

1. **Stop the restart loop.** The kernel has `restart: unless-stopped`, so a release that cannot
   start retries forever, and every retry runs against the database.

   ```sh
   docker compose stop keycloak
   docker compose logs --tail=300 keycloak > upgrade-failure.log
   ```

2. **Find where it stopped.** Which schema the database now holds:

   ```sh
   docker compose exec -T postgres psql -U keycloak -d keycloak -Atc \
     "SELECT version FROM migration_model ORDER BY update_time DESC LIMIT 1"
   ```

   | The kernel log and the version say | State |
   | :-- | :-- |
   | The old version; the log fails before migration | Nothing changed. Fix the cause (configuration, database reachability) or roll back the image |
   | The new version; the kernel started, then misbehaved | Migrated. The release record's boundary decides (step 3) |
   | A migration error in the log | Partly migrated: an unknown state. Restore (step 4) |

   If the kernel is ready and only `realm-apply` failed, it is not a failed upgrade. Exit 2 is
   [Console drift](console-drift.md). Exit 1 names its cause in the log.

3. **Roll back the image**, only when the release record says `reversible`. Revert the upgrade commit
   in a pull request, merge it, then on the server `git pull && docker compose up -d --build --wait`.
   `reversible` is the CI's finding for this pair of releases: the previous release started on a
   database the candidate migrated, and the realm stayed in sync (TDD-identity-kernel-005
   §Determining the Rollback Boundary). It is not the vendor's promise. Keycloak "does not support
   rolling back the database changes" [R1]. So if the previous release then fails to start, or
   behaves differently, go to step 4.

4. **Restore from the backup**, when the record says `irreversible-after-start`, when the
   migration failed midway, or when step 3 did not work. Keycloak's guide: "first restore the old
   installation, and then restore the database from the backup copy" [R1]. Revert the upgrade
   commit, then follow `deploy/dev/README.md` §Backups, "Restoring".

   Everything written after the backup is lost:
   - users created, credentials enrolled, and sessions. identity-control's Principal sweep records
     a mapping whose user is gone as `dangling` (TDD-identity-control-001 §Reconciliation Sweep);
   - clients registered, and client keys installed, after the backup. identity-control's client
     reconciler records a registered client absent from the kernel as `missing`, and a client whose
     keys differ from its registration as a finding;
   - realm changes applied after the backup. The next `realm-apply` applies them again;
   - signing keys created after the backup. Tokens they signed are then unknown to every consumer
     ([Consumer reports an unknown `kid`](unknown-kid.md)).

   Tell the owners of identity-control and organization-control before they start, because both
   reconcile against the kernel.

5. **A security release cannot simply be rolled back.** Rolling back reinstates the vulnerability it
   fixed. Take that decision with security, and record it.

6. **Confirm.**
   - `docker compose ps` shows `keycloak` healthy, and `docker compose logs realm-apply` ends in
     `applied revision`.
   - The issuer is the one written down before the upgrade. A changed `iss` invalidates every stored
     reference to it (ROADMAP question 4).
   - The JWKS holds the `kid` set written down before the upgrade, or a superset.
   - identity-control's reconciliation reports nothing new.

## Gaps

- **Production.** No production kernel exists, and TDD-identity-kernel-005 also requires a
  restore-from-backup rehearsal for any release recorded as irreversible. None has been needed yet:
  26.7.4 to 26.7.5 is `reversible` (compat run 37683329327, one data changeset,
  `26.7.0-backfill-group-org-id`).
- **No release record store.** The record lives in the job summary of the run that wrote it.
  TDD-identity-kernel-005 §Promotion's rule that a digest without a passing record cannot be
  promoted is not enforced by anything yet.

## References

| # | Source |
| :-- | :-- |
| R1 | Keycloak, *Upgrading Guide*, "Upgrading the Keycloak server", <https://www.keycloak.org/docs/latest/upgrading/index.html>, accessed 2026-10-07: "Back up the database using the instructions in the documentation for your relational database. The database schema will no longer be compatible with the old server after the upgrade. Because Keycloak does not support rolling back the database changes, if you need to roll back to the previous version, first restore the old installation, and then restore the database from the backup copy." |
