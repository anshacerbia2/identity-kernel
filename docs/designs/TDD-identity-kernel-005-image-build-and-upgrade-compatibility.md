---
doc_meta:
  id: TDD-identity-kernel-005
  title: Image Build, Digest Pinning, and Upgrade Compatibility
  owner: Identity Platform Team
  version: 1.8.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-10-10
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
- The server options the image fixes for every environment, the session store among them (1.7.0).
- The other images the stack builds or runs (the reverse proxy, realm-apply, Postgres), how each is
  built, and how their scan findings are fixed or excepted (1.8.0).

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

### Session Store (1.7.0)

Sessions are read from the database, and the in-memory session cache in front of it is off. The image
sets `KC_SPI_USER_SESSIONS__INFINISPAN__USE_CACHES=false`, the environment form of
`spi-user-sessions--infinispan--use-caches`, a runtime option, so `start --optimized` and the suite's
`start-dev` both read it. Persistent user sessions, on by default, stay on. Every environment runs the
image, so none can differ.

**Why.** With the cache on, the pinned 26.7.5 kernel kept refreshing sessions it had removed.
Organization Experience's stack proof found it: identity-control removed a session with
`DELETE /admin/realms/{realm}/sessions/{id}`, the Admin API stopped listing it, and the BFF's refresh
four minutes later was granted. The source gives the mechanism:

- A commit sends its cache changes first and writes the database after: "sends all the cache requests
  and queues any pending database writes", then "apply the database changes in a blocking fashion, and
  in a single transaction" [R7]. A delete therefore empties the cache entry while its row is still
  committed.
- A read that misses the cache loads the session from the database and puts it into the cache with
  `putIfAbsent` [R8]. Between the two steps of a delete, that read restores the entry.
- The Admin API lists a user's sessions from the database, so the restored session is not listed. A
  refresh reads the cache first, finds it, and is granted; the refresh's own database update finds no
  row and is dropped with a debug message, "No user session found" [R9].

The vendor knows it as keycloak#51127, "cache-miss unconditionally re-hydrates cache from DB,
resurrecting deleted sessions". Its maintainer's advice is this setting: "As a workaround, I recommend
to disable the cache, but keep persistent sessions enabled. Use the option
`spi-user-sessions--infinispan--use-caches` for that" [R10]. The fix, a short-lived tombstone written
on removal, is in 26.8.0 and not in 26.7.x; by its own description it protects user sessions and
not client sessions [R11]. The option exists in 26.7.5 and is read at startup [R12]. Keycloak's own
guide documents it from 26.8.0 [R13].

**Measured.** `compat/removed_session_test.go` removes sessions while something else reads them, which
is what a deployed estate does: identity-control lists the sessions to confirm a removal, and a BFF
calls UserInfo or refreshes. Two runs on the pinned image, each in four configurations. With the cache
on, 801 of 1,800 removed sessions were refreshed after their removal answered, under `start-dev` and
under `start --optimized` on PostgreSQL alike. With it off, none of 1,800 was. ROADMAP.md (A removed
session refreshed) has the table.

**What else was tried and why it is not the setting.**

| Alternative | Result |
| :-- | :-- |
| Persistent user sessions off (`--features-disabled=persistent-user-sessions`) | Online sessions are memory-only and stay removed, but offline sessions are still database-backed and cached: 36 of 100 were refreshed after removal. Online sessions would also be lost on every restart |
| identity-control ending a session by user logout (`POST /users/{id}/logout`) instead | Not affected, 0 of 200 with the cache on: the logout sets the user's not-before, and the refresh refuses a token issued before it [R14]. It ends every session of the user, so it is no substitute for ending one |
| Rotating refresh tokens (`revokeRefreshToken`) | Not measured. It limits each refresh token to one use, and the session's holder, the BFF, always presents the latest one; the session itself is untouched. Not a fix |
| Upgrading to 26.8.0 | Carries the tombstone fix for user sessions, and the option stays. An upgrade goes through this design's suite on its own; the setting stays until the suite shows it can go |

**What it costs.** "When session caching is disabled, every session read goes directly to the
database. This may increase database connection usage and CPU load, especially for workloads that rely
heavily on token introspection or token exchange" [R13]. Consumers verify access tokens locally
(STD-IAM-002), so the reads are sign-ins, refreshes, UserInfo and the Admin API: sized by the database,
not by API traffic.

**What remains.** A refresh whose read reaches the database before the removal commits is granted, and
its access token lives out its lifetime. That is a refresh ordered before the removal, not a removed
session coming back: its next refresh is refused. It is bounded by the access token lifetime
(STD-IAM-002 §3.3).

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

### Images the Stack Runs (1.8.0)

`deploy/dev/compose.yaml` runs three images beside the kernel's, and each is in scope of STD-GLB-009
1.8.0 §Container Images, which lands with scnehaux-architecture #86. The `image-scan` workflow builds
the three this repository builds and scans them, and Postgres from its registry, on every change and
daily.

| Image | Source | Publicly exposed (rule 8) | Remedy in 1.8.0 |
| :-- | :-- | :-- | :-- |
| kernel | `image/Dockerfile` on `image/keycloak.ref` | no: reached only through the proxy | none needed: no fixable High or Critical |
| `caddy` | `deploy/dev/caddy.Dockerfile`: Caddy 2.11.7 built from source on `caddy:2.11.7-builder-alpine`, overlaid on `caddy:2.11.7-alpine`, both by digest | **yes**: ports 80 and 443, or the tunnel's anonymous port | rebuilt from source (rule 9); `zlib` upgraded (rule 10) |
| `realm-apply` | `deploy/dev/realm-apply.Dockerfile`: `alpine:3.24` by digest with `git`, binaries from `golang:1.26.9-alpine` by digest | no: a one-shot job on the internal network | base replaced (rule 10); `zlib` upgraded |
| `postgres` | `postgres:17.11-alpine`, pulled by digest | no: the internal network, no published port | `affected` exception until the upstream rebuild (rules 5, 8, 10) |

**What the scan found.** On 2026-10-10 the Go advisories GO-2026-6603 to GO-2026-6613 were re-rated and
the daily scan, run 38047364279, failed on two third-party Go binaries: `/usr/bin/caddy` in
`caddy:2.11.7-alpine` (go1.26.8, `golang.org/x/net` v0.59.0) and `/usr/bin/git-lfs` in `alpine/git`
(go1.26.8, x/net v0.57.0). The `zlib` rule, written for Postgres, also hid `zlib` 1.3.2-r0 in both
images, because it named only the package, and the `pcre2` rule rested on
`vulnerable_code_cannot_be_controlled_by_adversary`, a justification rule 7 no longer accepts.

**The proxy is rebuilt from source (rule 9).** It is the one publicly exposed image, so its time comes
from the exposed half of BOD 26-04 Table 1 [R18]. CISA's Vulnrichment values [R19], none of them in
the KEV catalog of 2026-10-08:

| Advisory | CVE | Automatable | Technical impact | Fixed within | By |
| :-- | :-- | :-- | :-- | :-- | :-- |
| GO-2026-6612, HTTP/2 flow control [R20] | CVE-2026-78663 | yes | total | 3 days | 2026-10-13 |
| GO-2026-6608, MIME header parsing [R20] | CVE-2026-94440 | yes | partial | 14 days | 2026-10-24 |
| GO-2026-6613, HTTP/1 desynchronization after CONNECT [R20] | CVE-2026-94439 | yes | partial | 14 days | 2026-10-24 |

No Caddy release carries the fix: 2.11.7 (2026-10-03) is the latest, and the upstream moved x/net to
v0.60.0 on its main branch on 2026-10-09 (caddyserver/caddy#8179) [R21]. So the repository builds
that release itself, by the path Caddy documents: the `:builder` image builds "a new Caddy binary with
custom modules", and the second `FROM` overlays "the newly-built binary on top of the regular `caddy`
image" [R15]. `--replace` "only writes a replace directive to `go.mod`" [R16], so the module graph is
Caddy 2.11.7's with x/net moved and nothing else:

```dockerfile
# caddy:2.11.7-builder-alpine, resolved 2026-10-10 (go1.27.2, xcaddy v0.4.7)
FROM caddy@sha256:aa705b1e8e4bce41a7a30de934c1e00f6821667c1d1206424465065c92cb7674 AS build
RUN xcaddy build v2.11.7 --replace golang.org/x/net=golang.org/x/net@v0.60.0 --output /usr/bin/caddy
# caddy:2.11.7-alpine, resolved 2026-10-07
FROM caddy@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
RUN apk add --no-cache 'zlib>=1.3.2-r1'
COPY --from=build /usr/bin/caddy /usr/bin/caddy
```

The builder's Go is 1.27.2, which fixes the standard library half of every advisory above (fixed in
1.26.9 and 1.27.2) [R20]. The build fails unless `go version -m` on the binary reads x/net v0.60.0 as
the module compiled in (`=> golang.org/x/net v0.60.0` under `dep golang.org/x/net v0.59.0`) and a Go
no older than go1.26.9. Measured on 2026-10-10: `go1.27.2`, x/net v0.60.0; `caddy list-modules`
identical to the official binary's, 135 standard modules; both Caddyfiles validate; the scan finds no
Go module finding in the image. The binary keeps `cap_net_bind_service`, which the builder sets.

Two remedies were rejected. Turning HTTP/2 off is not a remedy: "enabling HTTP/2 (including H2C)
necessarily implies enabling HTTP/1.1 because the Go standard library does not let us disable HTTP/1.1
when using its HTTP server" [R17], and GO-2026-6608 and GO-2026-6613 are reached over HTTP/1. An
`affected` exception is not one either: rule 9 bounds it by the 3 days above, which a source build
meets. The build goes, and compose pulls a release by digest again, when a Caddy release carries x/net
v0.60.0 or later and is built with Go 1.26.9 or later; ROADMAP.md tracks it.

**realm-apply's base carries only git (rule 10).** `alpine/git` brought `git-lfs`, a Go binary
realm-apply never runs, and perl, which it does not run either. CISA: "Base layer container images
often contain unused packages" [R24]. The base is now `alpine:3.24` by digest with
`apk add --no-cache git 'zlib>=1.3.2-r1'`, and no git-lfs. Measured in the built image on 2026-10-10:
git 2.54.0-r0, pcre2 10.49-r0, zlib 1.3.2-r1, nghttp2-libs 1.70.0-r0; no `git-lfs`, no perl. The `pcre2`
exception is therefore gone, not decided again. realm-apply and client-key are built on
`golang:1.26.9-alpine` by digest, and `go version` reads go1.26.9 for both.

**The trade-off of an upgrade line.** apk resolves `git` and the `zlib` constraint against Alpine's
index on the day of the build, not against the digest. apk keeps the installed version "unless an
upgrade is requested or a world constraint or package dependency requires an alternate version" [R22],
so the constraint is what moves `zlib`, and a constraint no repository meets fails the build. The base
stays named by digest (rule 1); the packages added on top float within the `v3.24` branch, which takes
fixes, and the constraint sets the floor. Docker states the price of the alternative: pinning by digest
alone means "you're opting out of automated security fixes" [R23]. Two builds on different days can
therefore differ in a package version. That is acceptable for these two images, which are built where
they run and never promoted; the kernel image, which is promoted (§Build Output), has no such line.
Each line carries a comment naming CVE-2026-85091 and goes when its pin moves to an image that has
the fix.

**Postgres waits for its upstream (rules 5, 8 and 10).** `postgres:17.11-alpine` carries `zlib`
1.3.2-r0, and the official image has not been rebuilt: on 2026-10-10 the tag still resolves to the
pinned digest, and its base `alpine:3.24` (3.24.2, built 2026-09-17) still carries 1.3.2-r0. Official
images "are subject to their own maintenance schedule" [R25]. The image is run, not built, and not
exposed; CVE-2026-85091 is not in the KEV, and Vulnrichment gives Automatable no, Technical Impact total
[R19]. Table 1 gives fix on system upgrade, which for an image run without building is the next pin move
within 90 days of detection (2026-10-07): by 2027-01-05. `.grype.yaml` holds it as an `affected` rule on
`zlib` 1.3.2-r0, type `apk`; the version keeps it off the proxy and realm-apply, which carry 1.3.2-r1.
Its review date, 2026-10-21, is earlier than that limit so the pin moves as soon as the rebuild lands.
If 2027-01-05 would come first, the stack builds its own Postgres image from the pinned one with the
upgrade line.

**A built image is never pulled under its name.** A service with both `build:` and an `image:` name is
pulled first: "If `pull_policy` is missing in the service definition, Compose attempts to pull the image
first and then builds from source if the image isn't found in the registry or platform cache" [R27].
`deploy-dev` run 38067696612 shows it: `keycloak Warning pull access denied for scnehaux/identity-kernel`,
and the same for the proxy's name at that commit. The `scnehaux` namespace on Docker Hub is not this
project's, so anyone who publishes `scnehaux/identity-kernel:dev` would have the server run their image
instead of the one built from `image/keycloak.ref`. Every such service therefore sets
`pull_policy: build`: "Compose builds the image. Compose rebuilds the image if it's already present"
[R27]. `keycloak` is the one service with both; the proxy and realm-apply carry no name, and compose
does not pull them. The cost is a build on every `up`, which BuildKit's cache answers when nothing
changed. The kernel keeps its name, which `docker image ls` shows; the policy, not the absence of a
name, is what keeps the registry out.

**How exceptions are checked.** `scripts/image-scan-rules.py` runs before every scan (§5 Enforcement
item 4). It fails on a rule without vulnerability, package name, version or type; on a package found
inside a file (any type but `apk`, `deb`, `rpm`) without a full `package.location`, or on any location
with a wildcard, because Grype reads it as a glob [R26]; on a reason that is not `review-by …: <status>:
detected …: <images>: <statement>` with `affected` or one of the three justifications rule 7 accepts;
on a review date that has passed, is more than 90 days ahead, or, for `affected`, is more than 90 days
after detection. Whether a statement is true, and whether Table 1 was read correctly, is left to review.

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
defer yet. Its release record is the `upgrade` job's summary, which every run writes again; main run
37683329327 records `reversible`, with that one changeset applied.

## Configuration

| Setting | Value | Reason |
| :-- | :-- | :-- |
| Upstream image reference | `sha256:` digest, recorded in this repository | A tag is mutable and not reproducible |
| Preview features | disabled | ADR-IAM-001 §5.8 requires a separate decision to enable any |
| User session cache (`spi-user-sessions--infinispan--use-caches`) | `false`, set in the image | A removed session stays removed (§Session Store) |
| Persistent user sessions | on, Keycloak's default | Sessions survive a restart; the database is the one store |
| Extension packaging | built from owned source, signed | SAD-001 §7.6 |
| Realm application | pipeline only, above local development | ADR-IAM-001 §5.7 |
| Promotion | same image digest across environments | EAD-005 §6.5 |
| Reverse proxy (1.8.0) | Caddy 2.11.7 built from source, x/net v0.60.0, Go 1.27.2 | §Images the Stack Runs; until a Caddy release carries the fix |
| realm-apply base (1.8.0) | `alpine:3.24` by digest, with `git` | Only what the job runs (§Images the Stack Runs) |
| Built images and the registry (1.8.0) | `pull_policy: build` on every service with `build:` and an `image:` name | A built image is never pulled under its name (§Images the Stack Runs) |
| Upgrade lines (1.8.0) | `apk add --no-cache 'zlib>=1.3.2-r1'` in the proxy and realm-apply | CVE-2026-85091; goes when the pin moves |

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
`lib/quarkus/transformed-bytecode.jar`. Measured on 26.7.5 on 2026-10-07, `image-build` run 37686287003:

- **Generated class names.** About 130 classes differ (132 in that run). Hibernate's proxies carry ByteBuddy field names
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

The release record's `extension_versions` names the theme by the same git tree id, so a record and a
bill of materials for one commit agree.

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

### Session Removal (1.7.0)

- `TestTheKernelReadsSessionsFromTheDatabase` reads the user session provider's `useCaches` from the
  server info and requires `false`, so an image built without the setting fails the `contract` job.
- `TestARemovedSessionIsNotRefreshed` removes online and offline sessions by identifier, and online
  sessions by user logout, each while the user's sessions are listed, UserInfo is called, or a refresh
  is sent with the removal, and with nothing else reading. Every iteration waits 1 to 1.5 s after
  sign-in. No refresh may be granted once the removal has answered. The job summary carries the counts
  per variant.

### Image Scan (1.8.0)

- The `image-scan` workflow builds the kernel, realm-apply and Caddy images as compose builds them,
  and scans them and Postgres on every change and daily. It fails on a High or Critical vulnerability
  with a fix.
- `scripts/image-scan-rules.py` fails the run on an ignore rule out of rule 5's form or past its
  review date, before any scan.
- The Caddy build fails unless the binary reads x/net v0.60.0 and Go 1.26.9 or later. A `zlib` upgrade
  line fails the build when no repository offers 1.3.2-r1.
- `deploy-dev`'s `stack` and `tunnel` jobs bring the stack up with the built proxy, in both modes, and
  their logs carry no pull attempt for an image this repository builds (`pull_policy: build`).

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

The session cache is off because a removal has to hold (§Session Store). A session ended by its
owner, by identity-control's containment, or by an operator is otherwise refreshed for as long as
something keeps refreshing it, while the Admin API reports it gone. The setting is a provider option,
not a feature flag, and the vendor recommends it for this defect [R10].

The reverse proxy is the one image clients on a public network reach. A finding in it whose code serves
those clients is fixed within its BOD 26-04 time, by a source build when no release has the fix
(§Images the Stack Runs), and never excepted as not affecting it. The source build is this
repository's to keep current until a Caddy release ends it.

Deferring theme assertions on a security release is a deliberate trade: a delayed
security patch is a larger risk than a temporarily unstyled recovery page. Deferring
the realm contract assertions would not be a trade, because it would ship an identity
change nobody verified.

## Performance Notes

The suite starts a clean Keycloak instance and applies a full realm, so it runs per
candidate release rather than per commit. Its cost is dominated by container startup
and database migration, both of which are inherent to what it verifies.

Image build time does not affect any runtime path.

The session store setting does (§Session Store): every sign-in, refresh, UserInfo call and Admin API
session read goes to the database instead of memory. Access tokens are verified locally by consumers,
so API traffic does not reach it.

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
| Conforms to | STD-GLB-009 1.8.0 §Container Images, rules 4, 5, 7, 8, 9 and 10 (lands with scnehaux-architecture #86) — §Images the Stack Runs |
| Consumed by | `TDD-identity-control-002`, `TDD-identity-control-005` — a session removed through the Admin API stays removed (§Session Store) |

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
| R7 | Keycloak 26.7.5, `model/infinispan/src/main/java/org/keycloak/models/sessions/infinispan/transaction/DefaultInfinispanTransactionProvider.java`, `commitImpl`: "// sends all the cache requests and queues any pending database writes. transactionList.forEach(transaction -> transaction.asyncCommit(stage, databaseWrites)); // all the cache requests has been sent // apply the database changes in a blocking fashion, and in a single transaction. commitDatabaseUpdates(databaseWrites);". `prepareStep` does the same inside the request's own transaction. |
| R8 | Keycloak 26.7.5, `model/infinispan/.../changes/UserSessionPersistentChangelogBasedTransaction.java`, `get`: "if (wrappedEntity == null) { LOG.debugf("user-session not found in cache for sessionId=%s offline=%s, loading from persister", key, offline); wrappedEntity = getSessionEntityFromPersister(realm, key, userSession, offline);"; `PersistentSessionsChangelogBasedTransaction.importSession`: "existing = getCache(offline).putIfAbsent(key, session, …)". `PersistentUserSessionProvider.getUserSessionsStream` lists a user's sessions with "persister.loadUserSessionsStream(realm, user, offline, 0, null)". |
| R9 | Keycloak 26.7.5, `model/infinispan/.../changes/JpaChangesPerformer.java`, `processUserSessionUpdate`: "case REPLACE -> { … if (userSessionModel != null) { mergeUserSession(…); } else { LOG.debugf("No user session found for %s", entry.getKey()); } }". |
| R10 | keycloak/keycloak#51127, *Persistent User Sessions: cache-miss unconditionally re-hydrates cache from DB, resurrecting deleted sessions*, opened 2026-07-24, closed 2026-09-30, labelled `release/26.8.0`, <https://github.com/keycloak/keycloak/issues/51127>, accessed 2026-10-09: "the Admin UI/Admin REST API's "list sessions" queries the database directly and correctly shows zero sessions"; Alexander Schwartz (`ahus1`, listed in the repository's `MAINTAINERS.md`), 2026-09-22: "As a workaround, I recommend to disable the cache, but keep persistent sessions enabled. Use the option `spi-user-sessions--infinispan--use-caches` for that." |
| R11 | keycloak/keycloak#53250, *Minimal tombstone implementation for user sessions*, merged 2026-09-30 as `a84a001`, <https://github.com/keycloak/keycloak/pull/53250>, accessed 2026-10-09: "On removal, `InfinispanChangesUtils` writes a short-lived tombstone marker"; "Only the user session caches are protected (not client session caches, which are out of scope for this minimal fix)". Tag 26.8.0 (published 2026-10-01) contains the commit; no 26.7 release carries it. |
| R12 | Keycloak 26.7.5, `model/infinispan/.../InfinispanUserSessionProviderFactory.java`, `init`: "useCaches = config.getBoolean(CONFIG_USE_CACHES, !Profile.isFeatureEnabled(Profile.Feature.STATELESS)) && InfinispanUtils.isEmbeddedInfinispan();"; its configuration metadata: "Enable or disable caches"; `getOperationalInfo` reports `useCaches`, which the Admin API's server info shows. With it false, every cache holder is created "WithoutCache". |
| R13 | Keycloak 26.8.0, *Upgrading Guide*, "Disabling caching of persistent user sessions", <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/upgrading/topics/changes/changes-26_8_0.adoc>: "To disable caching, set `--spi-user-sessions--infinispan--use-caches=false`"; *Configuring distributed caches*, "Disabling session caching", <https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/server/caching.adoc>: "When session caching is disabled, every session read goes directly to the database. This may increase database connection usage and CPU load, especially for workloads that rely heavily on token introspection or token exchange." Accessed 2026-10-09. |
| R14 | Keycloak 26.7.5, `services/.../resources/admin/UserResource.java`, `logout`: "session.users().setNotBeforeForUser(realm, user, Time.currentTime());"; `services/.../protocol/oidc/refresh/AbstractRefreshTokenProvider.java`: "TokenVerifier.createWithoutSignature(oldRefreshToken).withChecks(…, TokenManager.NotBeforeCheck.forModel(session, realm, user)).verify(); } catch (VerificationException e) { throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Stale token");". `RealmAdminResource.deleteSession` sets no not-before. |
| R15 | Caddy, *Build from source*, accessed 2026-10-10. <https://caddyserver.com/docs/build>. "You can use the `:builder` image as a short-cut to building a new Caddy binary with custom modules"; "Note the second `FROM` instruction — this produces a much smaller image by simply overlaying the newly-built binary on top of the regular `caddy` image." |
| R16 | Caddy, *xcaddy* README, v0.4.7, accessed 2026-10-10. <https://github.com/caddyserver/xcaddy/blob/v0.4.7/README.md>. "`--replace` is like `--with`, but does not add a blank import to the code; it only writes a replace directive to `go.mod`, which is useful when developing on Caddy's dependencies (ones that are not Caddy modules)." |
| R17 | Caddy, *Global options*, `protocols`, accessed 2026-10-10. <https://caddyserver.com/docs/caddyfile/options#protocols>. "Default: `h1 h2 h3`"; "Currently, enabling HTTP/2 (including H2C) necessarily implies enabling HTTP/1.1 because the Go standard library does not let us disable HTTP/1.1 when using its HTTP server." |
| R18 | CISA, *BOD 26-04: Prioritizing Security Updates Based on Risk*, 2026-06-10, accessed 2026-10-10. <https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk>. "Publicly exposed: Any agency-owned or agency-managed IT resource accessible to unauthenticated or untrusted entities via public networks, such as the internet, regardless of its physical or logical location"; "CISA publishes answers to KEV Status, Exploit Automation, and Technical Impact for every CVE ID through services such as the Vulnrichment Program"; "Fix on system upgrade means that, unless conditions change as described in item (e) above, the vulnerability should be remediated the next time the vulnerable asset receives a scheduled major upgrade or rebuild." Table 1 as transcribed in STD-GLB-009 1.8.0 rule 8: exposed, not in the KEV, automatable, total: 3 days; automatable, partial: 14 days; not exposed, not in the KEV, not automatable: fix on system upgrade. |
| R19 | CISA, *Vulnrichment*, `cisagov/vulnrichment`, branch `develop`, accessed 2026-10-10, ADP "CISA Coordinator" SSVC options: CVE-2026-78663 (2026-10-09T16:40Z) Exploitation none, Automatable yes, Technical Impact total; CVE-2026-94440 (2026-10-09T16:09Z) none, yes, partial; CVE-2026-94439 (2026-10-09T16:45Z) none, yes, partial; CVE-2026-85091 (2026-09-03T13:21Z) poc, no, total. <https://github.com/cisagov/vulnrichment/tree/develop/2026>. CISA, *Known Exploited Vulnerabilities Catalog*, version 2026.10.08, <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>: none of the four is listed. |
| R20 | The Go Project, *Go Vulnerability Database*, accessed 2026-10-10. <https://vuln.go.dev/ID/GO-2026-6612.json>: "Double flow control refund on HTTP/2 server streams in net/http", alias CVE-2026-78663, stdlib fixed in 1.26.9 and 1.27.2; <https://vuln.go.dev/ID/GO-2026-6608.json>: "Memory limit bypass when parsing MIME headers in net/textproto, mime/multipart", alias CVE-2026-94440, fixed in 1.26.9 and 1.27.2; <https://vuln.go.dev/ID/GO-2026-6613.json>: "HTTP/1 server connection desynchronization after 2xx CONNECT response in net/http", alias CVE-2026-94439, fixed in 1.26.9 and 1.27.2. |
| R21 | caddyserver/caddy#8179, *go.mod: update golang.org/x/net to v0.60.0*, merged 2026-10-09 as `1b3838c`, <https://github.com/caddyserver/caddy/pull/8179>, accessed 2026-10-10. The latest release, v2.11.7, was published 2026-10-03 and does not carry it. |
| R22 | Alpine Linux, apk-tools v3.0.8, *apk-world(5)*, accessed 2026-10-10. <https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/v3.0.8/doc/apk-world.5.scd>. "When modifying existing installation, the installed version is preferred unless an upgrade is requested or a world constraint or package dependency requires an alternate version." |
| R23 | Docker, *Building best practices*, accessed 2026-10-10. <https://docs.docker.com/build/building/best-practices/>. On pinning by digest: "And you're opting out of automated security fixes, which is likely something you want to get"; "To keep your images up-to-date and secure, rebuild your images regularly with updated dependencies." |
| R24 | CISA, *Vulnerability Exploitability eXchange (VEX) – Status Justifications*, June 2022, §3.3.1, accessed 2026-10-10. <https://www.cisa.gov/sites/default/files/publications/VEX_Status_Justification_Jun22.pdf>. "Base layer container images often contain unused packages. A later layer could remove one or more of these packages." |
| R25 | Docker Official Images, *FAQ*, "Why does my security scanner show that an image has CVEs?", accessed 2026-10-10. <https://github.com/docker-library/faq#why-does-my-security-scanner-show-that-an-image-has-cves>. "Many Official Images are maintained by the community or their respective upstream projects, like Ubuntu, Alpine, and Oracle Linux, and are subject to their own maintenance schedule." |
| R26 | Anchore, *Grype: Filter scan results*, accessed 2026-10-10. <https://oss.anchore.com/docs/guides/vulnerability/filter-results/>. "# Ignore by package location (supports glob patterns)". Grype v0.120.1, `grype/match/ignore.go`, <https://github.com/anchore/grype/blob/v0.120.1/grype/match/ignore.go>: "all specified criteria must be met by the vulnerability match in order for the rule to apply". |
| R27 | Compose Specification, commit `914ec15`, accessed 2026-10-10. `build.md`, "Using `build` and `image`", <https://github.com/compose-spec/compose-spec/blob/914ec15d1fa498969c0df5c1d672306db3256089/build.md#using-build-and-image>: "When Compose is confronted with both a `build` subsection for a service and an `image` attribute. It follows the rules defined by the [`pull_policy`](05-services.md#pull_policy) attribute"; "If `pull_policy` is missing in the service definition, Compose attempts to pull the image first and then builds from source if the image isn't found in the registry or platform cache." `05-services.md`, `pull_policy`, <https://github.com/compose-spec/compose-spec/blob/914ec15d1fa498969c0df5c1d672306db3256089/05-services.md#pull_policy>: "`build`: Compose builds the image. Compose rebuilds the image if it's already present." |
