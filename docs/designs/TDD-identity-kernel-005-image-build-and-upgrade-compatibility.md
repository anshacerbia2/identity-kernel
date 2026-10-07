---
doc_meta:
  id: TDD-identity-kernel-005
  title: Image Build, Digest Pinning, and Upgrade Compatibility
  owner: Identity Platform Team
  version: 1.6.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-10-07
  parent_sad: SAD-001
---

# Image Build, Digest Pinning, and Upgrade Compatibility

## Purpose

Specify how the Keycloak image is built, what the upgrade compatibility suite asserts,
and how the rollback boundary for a candidate release is determined before that release
reaches production rather than during the incident that needs it.

Three other repositories build against properties this repository publishes: the issuer
form, the claim set present on each token surface, and the four closed Principal
creation paths. A Keycloak upgrade can change any of them. This design makes that a
build failure rather than a production discovery.

## Scope

**In scope**

- Reproducible image build from a digest-pinned upstream release.
- Packaging of the event listener extension and the login theme.
- Realm definition rendering, application, and drift detection per environment.
- The upgrade compatibility suite and what it asserts.
- Determining and recording the rollback boundary per candidate release.
- The accelerated path for security releases.

**Out of scope**

- Realm content: topology, issuer, mappers, and creation paths — owned by
  `TDD-identity-kernel-001`.
- Signing key custody and rotation — owned by `TDD-identity-kernel-002`.
- The event listener's own behavior — owned by `TDD-identity-kernel-003`.
- Theme content and accessibility conformance — owned by `TDD-identity-kernel-004`.
- Cluster topology, replica count, and database provisioning.

## Technical Context

Keycloak is adopted under ADR-IAM-001 and now carries a technology radar entry with
`identity-kernel` as its category. Version selection follows the technology lifecycle
and is pinned by artifact digest, per SAD-001 §9.4.

Two constraints shape the build.

**Immutable artifact promotion.** EAD-005 §6.5 requires the same verified artifact to
move between environments rather than being rebuilt for production. A Keycloak image
assembled separately per environment is a different kernel per environment, which makes
a staging result evidence of nothing.

**Rollback is not free.** SAD-001 §9.4 states that rollback boundaries are explicit
because database migrations may constrain downgrade. Keycloak applies schema migrations
on startup. After a migration runs, the previous release may be unable to read the
database at all. Treating rollback as always available is the assumption that turns a
failed upgrade into an outage.

## Component Design

### Build Inputs

```text
upstream Keycloak image        pinned by sha256 digest, never by tag
event listener extension       built from this repository, signed
login theme                    built from this repository
realm definition               rendered per environment, applied at deploy
```

**As built (1.4.0).** `image/Dockerfile` builds the kernel image `FROM` the digest in
`image/keycloak.ref`, passed as `KEYCLOAK_IMAGE`, and copies the login theme. No extension is packaged
yet. Every run uses it: `compat`'s `contract` and `browser` jobs build it before starting Keycloak, the
`upgrade` job builds it from both the candidate and the previous release, and `deploy/dev/compose.yaml` builds
it, so the development server runs what the suite asserts. Since 1.6.0 every change also builds it
twice and writes its bill of materials (§Testing Strategy, Build Reproducibility as built). Signing and
the provenance attestation of §Supply Chain follow when the image is published to a registry; until
then it is built where it runs, from a pinned digest and this repository's files.

**Optimized, with health and metrics (1.5.0, ADR-IAM-001 §5.8).** The image is built the way
Keycloak's container guide recommends: a builder stage sets `KC_HEALTH_ENABLED`, `KC_METRICS_ENABLED`
and `KC_DB=postgres` and runs `kc.sh build`, and the image copies its result. A server starts it with
`start --optimized`, so the build-time options are the image's and no deployment can differ. `compat`
starts it with `start-dev` on its own file database, which builds again in development mode.

The two ports have different audiences:

| Port | Serves | Reached by |
| :-- | :-- | :-- |
| `8080` | the realms' protocol paths, `/resources`, `/admin` | the public entrance for `/realms/scnehaux` and `/resources` only; `/admin` and `/realms/master` from the internal network |
| `9000` | `/health/started`, `/health/live`, `/health/ready`, `/metrics` | the orchestrator and the monitoring system, internally |

The probes follow Keycloak's operator: startup on `/health/started` every second, up to 600 failures;
liveness on `/health/live` and readiness on `/health/ready`, every 10 seconds, three failures. Liveness
checks no dependency, so a database outage makes the kernel unready and does not restart it.
`deploy/dev/compose.yaml` checks readiness, and `caddy` and `realm-apply` wait for it.
`compat/management_test.go` asserts the three probes and the OpenMetrics output on 9000, and that none
of them answers on 8080.

The Admin Console is in the image and is not an operating surface (ADR-IAM-001 §5.8). It is a
build-time feature and the image is the same in every environment, so it is reached only internally:
on the development server, the owner-only tunnel port; in production, the internal network.

A tag is mutable. `quay.io/keycloak/keycloak:26.0` can point at different bytes next
week, and an image built from a tag is not reproducible. The digest is recorded in this
repository and changed by a reviewed commit, so a kernel version change is visible in
history rather than absorbed by a rebuild.

### Build Output

One image, one digest, promoted unchanged:

```text
local → integration → staging → production
        ^
        one digest, recorded at promotion
```

The realm definition travels separately because it differs per environment. The image
does not.

### Supply Chain

Per SAD-001 §7.6:

- Upstream image pinned by digest.
- Extensions built from owned source and signed.
- Dependency and vulnerability scanning over the upstream image, the JVM extensions,
  and the build tooling.
- A software bill of materials produced per build and retained with the artifact.
- Provenance attestation linking the image digest to the commit that produced it.

## Data Model

### Release Record

One record per candidate release, produced by the compatibility suite and retained as
upgrade evidence:

```text
candidate_version         upstream release identifier
upstream_digest           sha256 of the pinned base image
image_digest              sha256 of the built artifact
extension_versions        event listener and theme versions
realm_contract_result     pass | fail, per asserted property
creation_paths_result     pass | fail, per closed path
key_invariants_result     pass | fail
schema_migration_applied  yes | no
rollback_boundary         reversible | irreversible-after-start
rollback_rehearsed        yes | no, with the result
evaluated_at
```

`rollback_boundary` is a finding, not a configuration. The suite determines it by
attempting the downgrade, and records what it found.

## API / Interface

### The Declared Realm Contract

This is what other repositories build against. Changing any of it is a breaking change
under the compatibility window in SAD-001 §11.

| Property | Asserted by the suite | Consumer |
| :-- | :-- | :-- |
| Issuer form | `iss` matches the recorded value exactly | Every protected resource, and every evidence record retaining `iss` |
| `principal_id` on the access token | Present, and equal to the user attribute | Every internal-audience verifier, per STD-IAM-002 §3.5 |
| Claim presence on other covered surfaces | Present on each surface the adopted configuration claims | Consumers reading those surfaces |
| User registration closed | Self-registration unreachable | `identity-control` reconciler |
| Federated auto-creation closed | First-login creates no user | `identity-control` reconciler |
| Attribute not user-editable | Self-service cannot modify it | `TDD-identity-control-001` immutability assumption |
| Admin Console creation restricted | Only break-glass roles | `identity-control` reconciler |

## Algorithms / Logic

### Compatibility Suite

Runs per candidate release, before promotion:

```text
1. build the image from the candidate upstream digest with pinned extensions
2. start a clean instance against a clean database
3. apply the realm definition
4. assert every audience client scope, required claim, and prohibited external claim
5. assert the four closed creation paths
6. assert the key invariants: kid equals thumbprint, PS256 with RSA >=3072 bits,
   identical JWKS across replicas, startup refuses when custody is unreachable
7. run the event listener compatibility tests
8. render the theme and assert the login, MFA, and recovery pages
9. determine the rollback boundary
10. produce the release record
```

**Step 5 as built (1.3.0).** Each of the four paths is asserted against the pinned image on every
change: self-registration (`TestSelfRegistrationIsClosed`), the user-editable attribute
(`immutability_test.go`), federated auto-creation and Admin Console creation
(`creation_paths_test.go`). The `contract` job runs them on a clean instance with the realm applied,
which is steps 2 to 5, so a candidate digest put in `image/keycloak.ref` that reopens a path fails
there before it is merged.

A failure at step 4, 5, or 6 stops promotion. Those are the properties downstream
domains have already persisted against, and a release that changes them is a migration
rather than an upgrade.

### Determining the Rollback Boundary

This step is the reason the suite exists in this shape:

```text
snapshot the database after the candidate has started and migrated
attempt to start the previous release against that database
    if it starts and serves:      rollback_boundary = reversible
    if it refuses or misbehaves:  rollback_boundary = irreversible-after-start
record which schema migrations the candidate applied
```

An `irreversible-after-start` finding does not block the upgrade. It changes the
deployment plan: the recovery path becomes restore-from-backup rather than
redeploy-previous, and the maintenance window is sized for a restore.

Recording it is what makes the difference. A team that believes rollback is available
plans a five-minute recovery; a team that knows it is not plans a restore and tests it
first.

**How CI determines it.** The `upgrade` job in `.github/workflows/compat.yml` runs the
sequence on PostgreSQL, the database every server runs, rather than on the in-process
database `start-dev` uses:

```text
previous := image/keycloak.previous.ref     -- the release the servers run before this one
candidate := image/keycloak.ref
start previous on an empty database; apply the realm; stop it
start candidate on that database            -- the upgrade, with its migrations
record the Liquibase changesets the candidate applied
the realm is in sync after the upgrade (realm-apply -require-in-sync)
stop it; start previous on the migrated database
    ready within the bound, and the realm in sync:  reversible
    otherwise:                                       irreversible-after-start
write the release record to the job summary
```

Starting from the previous release rather than from an empty database is what makes it an
upgrade: a server's database was migrated by the previous release, and the candidate's
migrations run over that. The job fails when the previous release cannot start on an empty
database or the candidate cannot start over it, because then there is no upgrade to judge.
An `irreversible-after-start` finding does not fail it: it is recorded, as above.
`image/keycloak.previous.ref` changes in the same commit as `image/keycloak.ref`, to the
digest it replaces.

### Drift Detection Before Upgrade

```text
before applying a candidate:
    render the realm definition for the target environment
    diff it against the live realm through the supported Admin API
    if the live realm carries changes the definition does not:
        fail the deployment and report the difference
```

ADR-IAM-001 §5.7 prohibits unmanaged Admin Console changes to controller-owned
configuration, and SAD-001 §9.4 requires drift to be caught before an upgrade rather
than discovered during one. An upgrade applied over unmanaged drift silently discards
whatever the drift represented, and nobody learns what was lost.

### Security Releases

A security release takes an accelerated path with the same minimum evidence:

```text
required, unchanged:   steps 1 through 6, and the rollback boundary
may be deferred:       theme rendering assertions, non-security event tests
never deferred:        the declared realm contract and the closed creation paths
```

The properties that may be deferred are those whose failure degrades experience. The
properties that may not are those whose failure breaks another repository's assumption
about identity.

26.7.5 took this path on 2026-10-01: a patch release of the pinned minor line whose fixes
include CVE-2026-93999, a token-exchange refresh that kept issuing tokens for a disabled
audience client, and which carries one data changeset (`26.7.0-backfill-group-org-id`, a
backfill of `KEYCLOAK_GROUP.ORG_ID` for Organizations). There is no theme or extension to
defer yet. Its release record is in ROADMAP.md.

## Configuration

| Setting | Value | Reason |
| :-- | :-- | :-- |
| Upstream image reference | `sha256:` digest, recorded in this repository | A tag is mutable and not reproducible |
| Preview features | disabled | ADR-IAM-001 §5.8 requires a separate decision to enable any |
| Extension packaging | built from owned source, signed | SAD-001 §7.6 |
| Realm application | pipeline only, above local development | ADR-IAM-001 §5.7 |
| Promotion | same image digest across environments | EAD-005 §6.5 |

The database credential, the administration client's credential, and the signing keystore
are resolved at runtime from the approved secret manager and are never present in the
image, in the realm export, or in the build context. Registered clients hold no secret in
the kernel at all. They authenticate with registered public keys (`ADR-IAM-001 §5.12`).

## Testing Strategy

### Build Reproducibility

- Two builds from the same commit and the same upstream digest produce the same image
  digest.
- The image contains no secret, no realm export carrying credentials, and no
  development keystore.
- The software bill of materials lists every extension and its version.

**As built (1.6.0).** The `image-build` workflow runs `scripts/image-build-check.sh` on every change.
It builds the image twice from nothing, with two BuildKit instances that share no cache. Both builds
take `SOURCE_DATE_EPOCH` from the commit and export with `rewrite-timestamp`. Docker: the variable
"makes the timestamps in the image index, config, and file metadata reflect the specified Unix time",
and the option will "Rewrite the file timestamps to the `SOURCE_DATE_EPOCH` value" [R1] [R2]. So the
build date is not a difference. `scripts/image-build-compare.py` then checks each of the three
requirements.

| Requirement | As built | Met |
| :-- | :-- | :-- |
| Same image digest | **Not met; a recorded gap.** The digests differ (below). Every other layer and file is compared byte for byte, and a difference outside Keycloak's build output fails | no |
| No secret, realm export or development keystore | The bottom layers must be the pinned upstream manifest's, unchanged. The layers above may hold only `lib/quarkus/` and `themes/scnehaux/`, each theme file byte-identical to git's copy. No key, certificate, `.json`, `.conf` or `.env` file may be added, no file deleted, and no `Env` name may carry a password, secret, token or credential | yes |
| The bill of materials lists every extension and its version | CycloneDX 1.7 JSON, written by Syft pinned by digest. Every jar in `providers/` must be listed with a version; none is packaged yet. The theme is added as a component, versioned by its git tree id, and Keycloak's own version must be listed | yes |

**Why the digests differ.** A reproducible build is one where "any party can recreate bit-by-bit
identical copies of all specified artifacts" [R3]. Two of the kernel's files are not: the jars that
Keycloak's `kc.sh build` writes, `lib/quarkus/generated-bytecode.jar` and
`lib/quarkus/transformed-bytecode.jar`. CI measured 26.7.5 on 2026-10-07:

- **Generated class names.** About 130 classes differ. Hibernate's proxies carry ByteBuddy field names
  such as `cachedValue$LDoFC2eQ$…`. ByteBuddy's default factory "uses a random suffix for accessors"
  [R4]. Quarkus also numbers its recorded proxies (`proxykey108`) in the order its build steps finish.
- **Dates.** Every jar entry carries the build's clock, and `keycloak-persisted.properties` begins with
  the date `java.util.Properties` wrote it.

The upstream layers, the theme, `quarkus-application.dat` and `build-system.properties` are identical.
This repository cannot remove the gap without rewriting Keycloak's output. Starting without
`--optimized` does not remove it either: each start would run the same build, and every container
would differ instead of every image. The comparison therefore records the differing classes in the job
summary and fails on any difference elsewhere. The gap closes when Keycloak's build is deterministic,
and the check then reports one digest.

What the gap costs. Promotion is unaffected, because the one digest evaluated is the one promoted
(§Build Output); nothing is rebuilt for production. What a rebuild cannot do is confirm a published
digest bit for bit. That has to rest on the provenance attestation (§Supply Chain), which links the
digest to its commit.

**Where the bill of materials is kept.** The run keeps it as the artifact `identity-kernel-sbom`. By
default, GitHub "stores build logs and artifacts for 90 days" [R5]. That is enough for review, not
retention. When the image is published to a registry, the bill of materials travels with the image,
as §Supply Chain requires. CycloneDX 1.7 is ECMA-424 2nd edition [R6], the format ADR-UIP-SEC-001
chose for the UI Platform's packages.

### Contract Assertion

- Every property of the declared realm contract is asserted individually, so a failure
  names the property rather than the suite.
- A deliberately broken realm definition — registration re-enabled — fails the suite.
- A deliberately removed protocol mapper fails the suite at the claim assertion.
- Internal, privileged, and workload tokens carry exactly their STD-IAM-002 profile;
  an external token carries none of the enterprise or context claims.
- Baseline tokens use `PS256`, and a candidate unable to issue and verify it fails.
- `none`, symmetric algorithms, header-selected fallback, and unregistered `RS256` are
  rejected by the reference verifier suite.

### Rollback

- The rollback boundary is determined by attempting the downgrade, not by reading
  release notes: the `upgrade` job starts the previous release on the database the
  candidate migrated.
- The candidate starts on a database the previous release created, and the realm is in
  sync after the upgrade.
- An `irreversible-after-start` finding is recorded in the release record and surfaced
  in the deployment plan.
- Restore-from-backup is rehearsed for any release recorded as irreversible.

### Drift

- A realm changed through the Admin Console is detected by the diff and fails the
  deployment.
- Applying the definition twice produces no change on the second run.

### Promotion

- The digest promoted to production equals the digest evaluated by the suite.
- A digest not carrying a passing release record cannot be promoted.

## Security Notes

The image is the most privileged artifact in the estate: it authenticates every human
and workload. Digest pinning, signed extensions, provenance attestation, and a retained
bill of materials exist so that what runs in production is traceable to a reviewed
commit rather than to a tag someone moved.

Preview features stay disabled. A preview feature in the authentication path is a
dependency on behavior the vendor has not committed to, in the one system where a
behavior change is a security event.

Deferring theme assertions on a security release is a deliberate trade: a delayed
security patch is a larger risk than a temporarily unstyled recovery page. Deferring
the realm contract assertions would not be a trade, because it would ship an identity
change nobody verified.

## Performance Notes

The suite starts a clean Keycloak instance and applies a full realm, so it runs per
candidate release rather than per commit. Its cost is dominated by container startup
and database migration, both of which are inherent to what it verifies.

Image build time does not affect any runtime path.

## Operational Notes

| Signal (1.5.0) | Source | Meaning |
| :-- | :-- | :-- |
| Readiness failing | `/health/ready` | Out of rotation: usually the database. Not restarted |
| Liveness failing | `/health/live` | The process is stuck; the orchestrator restarts it |
| Startup past its budget | `/health/started` | The image does not start: an incompatible build or database |
| `/metrics` scrape failing | monitoring | The management port is unreachable from where it must be |

| Signal | Warning | Critical |
| :-- | :-- | :-- |
| Candidate release failing a contract assertion | — | any occurrence |
| Drift detected before an upgrade | any occurrence | — |
| Upstream digest changed without a reviewed commit | — | any occurrence |
| Release promoted without a passing release record | — | any occurrence |
| Critical vulnerability in the pinned upstream image | any occurrence | past the response window |

Runbooks required before production: failed upgrade and rollback, restore-from-backup
for an irreversible release, console drift reconciliation, and emergency security
release.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-001 — Scnehaux Identity Runtime |
| Realizes capability | PAD-PLT-001 — Identity & Access Platform |
| Governed by | ADR-IAM-001 — extension policy, preview-feature prohibition, operational baseline |
| Governed by | GDC-004 — technology lifecycle; `keycloak` carries a radar entry with this ADR as its rationale |
| Conforms to | STD-IAM-002 §3.5 — claim presence is what local verification depends on |
| Enterprise constraint | EAD-005 §6.5 — the same verified artifact is promoted between environments |
| Enterprise constraint | EAD-005 §6.8 — recovery is proven by exercise, not by existence |
| Publishes to | `identity-control`, `identity-experience`, and every protected resource — the declared realm contract |
| Related design | `TDD-identity-kernel-001` — realm content this suite asserts |
| Related design | `TDD-identity-kernel-002` — key invariants this suite asserts |

### Open Questions

1. ~~Which upstream Keycloak release is pinned for the initial baseline.~~ Answered:
   26.7.4 was the proof-of-concept baseline (2026-09-25), and 26.7.5 is the first release
   with a release record (2026-10-01, ROADMAP.md).

## References

| Ref | Source |
| :-- | :-- |
| R1 | Docker Docs, *Reproducible builds with GitHub Actions*, accessed 2026-10-07. <https://docs.docker.com/build/ci/github-actions/reproducible-builds/>. "Setting the environment variable for a build makes the timestamps in the image index, config, and file metadata reflect the specified Unix time." |
| R2 | Docker Docs, *OCI and Docker exporters*, accessed 2026-10-07. <https://docs.docker.com/build/exporters/oci-docker/>. `rewrite-timestamp`: "Rewrite the file timestamps to the `SOURCE_DATE_EPOCH` value." |
| R3 | Reproducible Builds, *Definitions*, accessed 2026-10-07. <https://reproducible-builds.org/docs/definition/>. "A build is reproducible if given the same source code, build environment and build instructions, any party can recreate bit-by-bit identical copies of all specified artifacts." |
| R4 | ByteBuddy, `Implementation.Context.Default.Factory`, accessed 2026-10-07. <https://github.com/raphw/byte-buddy/blob/master/byte-buddy-dep/src/main/java/net/bytebuddy/implementation/Implementation.java>. "A factory for creating a `Default` that uses a random suffix for accessors"; the cached field is named `FIELD_CACHE_PREFIX + "$" + suffix + "$" + RandomString.hashOf(hashCode)`. |
| R5 | GitHub Docs, *Removing workflow artifacts*, accessed 2026-10-07. <https://docs.github.com/en/actions/how-tos/manage-workflow-runs/remove-workflow-artifacts>. "By default, GitHub stores build logs and artifacts for 90 days, and this retention period can be customized." |
| R6 | Ecma International, *ECMA-424, CycloneDX Bill of materials specification*, 2nd edition, December 2025. <https://ecma-international.org/publications-and-standards/standards/ecma-424/>. "This Standard defines the CycloneDX v1.7 Bill of materials specification". |
