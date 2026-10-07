# Console drift

Version 1.0.0. Last reviewed 2026-10-07.

A setting the realm definition (`realm/`) declares was changed outside `realm-apply`, usually in the
Admin Console. `realm-apply` refuses to apply over it and changes nothing.

## Signal

`realm-apply` exits **2**. On the development server it is the `realm-apply` job that runs on every
`docker compose up`. Its log holds one of two refusals:

```text
DRIFT -- changed outside this tool since revision <revision>:
  <kind> <name>: <path>: live <value>, definition <value>
  <kind> <name>: removed from the live realm

realm-apply: refusing: the live realm carries changes the definition at <revision> does not. ...
```

```text
realm-apply: refusing: realm scnehaux exists and was never applied by this tool, so there is no
baseline to detect drift against. ...
```

`<kind>` is one of `realm`, `signing key`, `client scope`, `user-profile attribute`,
`realm default client scopes`, `authentication flow`, `flow binding` or `required action`
(`internal/realmdef/plan.go`, `flows.go`, `requiredactions.go`).

Severity: a warning, a ticket for the next working day (TDD-identity-kernel-001 and -005
§Operational Notes). It becomes urgent when an upgrade is waiting, because an upgrade must not be
applied over drift (step 5).

Two other failures look similar and are not drift. Both exit **1**:

| Message | Cause | Action |
| :-- | :-- | :-- |
| `the realm was last applied from revision X, which this checkout cannot read` | The checkout lacks the recorded commit | `git fetch` in the checkout the job mounts, then `docker compose up -d` |
| `the definition at revision X does not reproduce what was applied` | That revision was applied from an uncommitted tree | Compare the live realm with `realm/` by hand, then step 4b |

## What the code does

- Every apply records the commit and the definition's digest in the realm, as the attributes
  `scnehaux.definition.revision` and `scnehaux.definition.digest` (`internal/realmdef/apply.go`).
- The next run reads `realm/` at that commit from git and compares it with the live realm. Any
  difference was made outside the tool (`cmd/realm-apply/main.go`).
- Only what the definition declares is compared. A field it does not name is Keycloak's default,
  so a new Keycloak release that adds a field is not drift (`diff` in `plan.go`).
- A refused run writes nothing. The realm keeps serving with the drift in place.

This runbook covers realm configuration only. Users and the clients identity-control registers are
reconciled by identity-control (its ROADMAP §Proof B), not by `realm-apply`.

## Steps

1. **Save the plan.** Put the log in the incident record:

   ```sh
   docker compose logs realm-apply
   docker compose run --rm realm-apply -environment=development -definition=/repo/realm \
     -url=http://keycloak:8080          # read-only: no -apply
   ```

2. **Find who changed it, and when.** The realm keeps admin events for 7 days, with the
   representation each change wrote (`realm/scnehaux.json`, TDD-identity-kernel-003).
   - Admin Console, on the owner-only admin URL: realm `scnehaux`, **Events**, **Admin events**.
     Filter by resource path, such as `client-scopes/<id>`.
   - Or the Admin API: `GET /admin/realms/scnehaux/admin-events?operationTypes=UPDATE&dateFrom=<yyyy-MM-dd>`.
     It also takes `operationTypes=CREATE,DELETE`, `resourcePath`, `authUser`, `first` and `max`.

   Record the administrator (`authDetails`), the time and the representation. A change older than
   7 days has no event left: record it as unexplained.

3. **Check the signing key first.** If a drift line names `signing key rsa-ps256-3072`, read
   [Consumer reports an unknown `kid`](unknown-kid.md) before you act. Recreating the provider makes
   a new key with a new `kid`, and so does changing its `keySize` either way: Keycloak generates a new
   key whenever the size differs from the key it holds. Every token the old key signed then fails at
   every consumer. While the key is disabled or gone, Keycloak signs with a 2048-bit `fallback-PS256`
   key that no consumer accepts.

4. **Decide, then act.**

   a. **Not wanted** (a mistake, a test, or nobody can explain it). Revert it in the Admin Console to
      the value the drift line gives as `definition`. Then run `docker compose up -d`. The job must
      end with `applied revision <commit> to realm scnehaux`.

   b. **Wanted.** Put the change in `realm/` through a pull request, with its TDD change if it changes
      behaviour, as any realm change. After it merges, `git pull` on the server and adopt it once:

      ```sh
      docker compose run --rm realm-apply -environment=development -definition=/repo/realm \
        -url=http://keycloak:8080 -apply -adopt
      ```

      `-adopt` skips the drift check and converges the live realm to the definition at the new
      commit. Any drift line that `realm/` does not now declare is overwritten, without a record. It
      is "the one way to overwrite a change nobody recorded" (`internal/realmdef/apply.go`). So
      revert every other line first (4a), and confirm with the read-only plan that only the change
      you committed is left.

5. **Before an upgrade.** Resolve the drift first. TDD-identity-kernel-005 §Drift Detection Before
   Upgrade: "An upgrade applied over unmanaged drift silently discards whatever the drift
   represented, and nobody learns what was lost."

6. **Confirm.** The read-only plan shows no `DRIFT` section and no pending change. In CI terms,
   `-require-in-sync` would exit 0.

## Why refuse instead of overwrite

ADR-IAM-001 §5.7 prohibits unmanaged Admin Console changes to controller-owned configuration.
Overwriting silently would hide that one happened. A refusal makes someone look at it, and the admin
event says who made it. This is the reconcile model Kubernetes controllers use: compare the declared
state with the observed state, and act on the difference [R1]. Here the action on an unexplained
difference is to stop, because the controller cannot know whether the change was a fix.

## Gaps

- **Production.** `realm-apply` refuses any environment but `local`, `ci` and `development` until key
  custody exists (`ParseEnvironment`). A production pipeline must run the same plan before each
  deployment and fail on exit 2 (TDD-identity-kernel-005 §Drift).
- **No alert.** Drift is found when `realm-apply` next runs, not when the change is made. On the
  development server that is the next `docker compose up`. An admin event is written at once, but
  nothing watches for one yet.
- **Retention.** Admin events older than 7 days are gone, so drift found late may be unexplained.

## References

| # | Source |
| :-- | :-- |
| R1 | Kubernetes, *Controllers*, <https://kubernetes.io/docs/concepts/architecture/controller/>, accessed 2026-10-07: "In Kubernetes, controllers are control loops that watch the state of your cluster, then make or request changes where needed. Each controller tries to move the current cluster state closer to the desired state." |
