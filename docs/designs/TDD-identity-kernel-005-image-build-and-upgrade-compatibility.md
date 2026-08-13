---
doc_meta:
  id: TDD-identity-kernel-005
  title: Image Build, Digest Pinning, and Upgrade Compatibility
  owner: Identity Platform Team
  version: 1.1.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-08-14
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

## Configuration

| Setting | Value | Reason |
| :-- | :-- | :-- |
| Upstream image reference | `sha256:` digest, recorded in this repository | A tag is mutable and not reproducible |
| Preview features | disabled | ADR-IAM-001 §5.8 requires a separate decision to enable any |
| Extension packaging | built from owned source, signed | SAD-001 §7.6 |
| Realm application | pipeline only, above local development | ADR-IAM-001 §5.7 |
| Promotion | same image digest across environments | EAD-005 §6.5 |

The database credential, the client secrets, and the signing keystore are resolved at
runtime from the approved secret manager and are never present in the image, in the
realm export, or in the build context.

## Testing Strategy

### Build Reproducibility

- Two builds from the same commit and the same upstream digest produce the same image
  digest.
- The image contains no secret, no realm export carrying credentials, and no
  development keystore.
- The software bill of materials lists every extension and its version.

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
  release notes.
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

1. Which upstream Keycloak release is pinned for the initial baseline. The technology
   radar entry carries the adoption; the digest is recorded here once the
   proof-of-concept has run against a candidate and the compatibility suite has
   produced its first release record.
