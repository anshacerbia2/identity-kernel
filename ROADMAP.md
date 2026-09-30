# Identity Kernel — Roadmap

Execution tracker for this repository only. Architecture lives in
`scnehaux-architecture`; nothing here overrides a SAD, an ADR, or a standard.

Week numbers are relative to the first build week, not calendar dates.

## Position in the build order

This repository runs the **proof-of-concept track**, in parallel with the control-plane
build rather than ahead of it. Every question below is answered against a
digest-pinned Keycloak release, and no answer invalidates an authority schema, a state
machine, an outbox engine, or a boundary control in the other repositories.

Four of the seven enterprise proof-of-concept questions are answered here. The other
three concern adapters in `identity-control`.

## Design status

| TDD | Subject | Status |
| :-- | :-- | :-- |
| `TDD-identity-kernel-001` | Realm topology, issuer identity, claim projection | approved |
| `TDD-identity-kernel-002` | Signing key custody, identity, rotation | approved |
| `TDD-identity-kernel-003` | Event listener extension and completeness reconciliation | approved |
| `TDD-identity-kernel-004` | Hosted login theme, accessibility, and disclosure discipline | approved |
| `TDD-identity-kernel-005` | Image build, digest pinning, and upgrade compatibility | approved |

## Proof-of-concept, in order

Run in this order. The first is the only one whose answer can force an extension or a
standard amendment, so it reports by day three.

| # | Question | Failure consequence |
| :-- | :-- | :-- |
| 1 | **Protocol mapper coverage** — which of access token, ID token, UserInfo, introspection can carry `principal_id` | Access token uncovered is the escalation case. Partial coverage of the other three is pre-decided in `TDD-identity-kernel-001` and needs no amendment |
| 2 | **Attribute search semantics** — is `q=scnehaux_principal_id:{id}` exact-match, and how does it paginate | Changes the recovery mechanism in `identity-control`; the creation path is unaffected |
| 3 | **Attribute immutability** — does the declarative user profile prevent administrator edits as well as self-service edits | Determines whether immutability is enforced or only detected |
| 4 | **Issuer URI form** — can `/realms/{name}` be removed while remaining supported | **Irreversible once tokens are issued.** Both outcomes are already decided; the answer is recorded either way before the first token |

Questions 5 through 7 — projected context representation, session removal granularity,
and context switch mechanism — are exercised here but decided in `identity-control` and
`organization-control`, because their consequences land there.

## Week 1 · Pinned instance and the realm contract

- ⏳ Digest-pinned Keycloak running from a reproducible image build — **the upstream image is
  pinned by digest** (`image/keycloak.ref`, 26.7.4) and runs in CI; there is no image of our own
  yet, because there are no extensions to package. The reproducible build lands with the first one
- ✅ Realm definition applied and diffed by the pipeline — `cmd/realm-apply`, which the development
  server runs as a one-shot job on every `docker compose up`, so a pulled change reaches the realm without
  a remembered command, and console drift fails the next up instead of being overwritten. CI applies the realm
  with it, and a second run must find nothing to change, before the suite and again after it.
  Console drift is judged against the definition at the recorded revision and refused. Rendering
  per environment is only an environment guard so far, because nothing in `realm/` varies by
  environment yet. The first value that does is the hostname of a long-lived server
- ✅ Question 1 executed and reported — **outcome 1**, all four surfaces covered; see below
- ✅ Questions 2 and 3 executed — **search is exact**; **immutability is detected, not enforced**;
  see below
- ✅ The provider-scope profile — `scnehaux-provider` and the `scnehaux_provider_scope` attribute, as
  STD-IAM-002 §3.2.1 requires. It is what identity-control accepts to mint a Principal, and `compat/`
  asserts it with a real Authorization Code + PKCE login, because `auth_time` exists only for one

- ✅ The workload profile — `scnehaux-workload`, carrying `principal_id`, `subject_type` and
  `workload_owner` (STD-IAM-002 §3.2.1). A workload's token comes from the client credentials grant
  and is issued for its client's service-account user, so identity-control writes the workload's
  attributes there. The built-in `acr` scope, a realm default, puts `acr=1` in that token, which
  STD-IAM-002 prohibits for a workload, so identity-control detaches it from a workload client
  (compat run 36739171569 found it). `compat/workload_test.go` asserts the token with a real
  key-signed grant and the scope detached, and that `workload_owner` reaches no internal token
  (first passing run 36739629606, 26.7.4). It unblocks workload registration in
  identity-control (TDD-identity-control-003) and TDD-identity-control-004. The tenant-scoped
  privileged scope is still undeclared: it needs `tenant_id` and the version claims, which wait on
  the context projection (questions 5 to 7)

**Exit:** the declared realm contract is asserted by test — issuer form, claim presence
per covered surface, and the four closed creation paths.

### Question 1, answered

Against `quay.io/keycloak/keycloak@sha256:82a77884…29b2c` (26.7.4) on 2026-09-25, compat run
36105049194: the access token, ID token, UserInfo and introspection all carry `principal_id` and
`subject_type` through the supported user-attribute mapper, with identical values. **Outcome 1:
adopt the target configuration.** No restricted extension and no standard amendment.

The answer is now the contract. `realm/contract.json` declares the four surfaces, and a release
that stops covering any of them fails `compat/` rather than quietly reporting outcome 2 — the
suite carries a negative control proving it can see a missing claim, without which that
assertion could not fail.

**One finding the question did not ask.** Introspection is audience-restricted in this release:
a client may introspect only a token whose `aud` names it, and anything else gets
`{"active":false}` with the event reason *"Client … is not in the token audience"*. It agrees
with the estate's model — tokens are audience-scoped, and the party that introspects is the API
they are for — but a consumer that introspects with a client outside `aud` will read every token
as inactive, which is a fail-closed outage rather than a leak. Recorded in TDD-identity-kernel-001.

### Questions 2 and 3, answered

Same image, same date, compat run 36106484382.

**Question 2, attribute search.** Search is exact: no prefix, substring, or extension
matches. It also finds disabled users, pages through `first`/`max` without loss, and
`/users/count` honours `q`. Recovery may branch on the count as returned. Two findings
land in `identity-control`:

- **Search is case-insensitive.** Identifiers must always be written in canonical
  lowercase.
- **Keycloak accepts two users holding one identifier.** The many-match branch and the
  reconciler are needed, as designed.

**Question 3, immutability.** It is detected, not enforced.

- **Self-service is closed.** The account API answers `400 error-user-attribute-read-only`.
- **An administrator's change is applied.**
- **No declarative profile gives write-once.** An attribute nobody may edit is dropped at
  creation, silently, behind a `201`.

The guarantee therefore rests on who holds `manage-users`. That role can already reset
any user's credentials, so rewriting an identifier grants its holder nothing new.
Reconciler detection sits behind it. A disable by partial PUT keeps the identifier, so
quarantine may send only `{"enabled": false}`.

Both answers are in `realm/contract.json`. `compat/` fails a release that loosens the
match or starts erasing attributes on a partial update. It logs a release that makes
write-once achievable, so question 3 gets re-answered rather than the improvement going
unused.

### What building it found

| Found | Consequence |
| :-- | :-- |
| A realm import that declares client scopes or key providers replaces Keycloak's defaults | The built-in `basic` scope carries `sub` and the generated HMAC key signs refresh tokens. The realm is therefore applied through the Admin API beside the defaults, not imported |
| Since Keycloak 24, an attribute the user profile does not declare is dropped on write | The profile is merged before any user exists, and the suite asserts the attribute survives creation — otherwise question 1 would report a configuration gap as a coverage one |

## Week 2 · Key custody and questions 4 through 7

- Key ceremony rehearsed, sealed keystore in the secret manager
- `kid` derived as the RFC 7638 thumbprint, asserted at startup
- Startup refuses to serve when custody is unreachable
- ✅ Question 4 executed and recorded — **path form retained**. `iss` is
  `{frontend URL}/realms/{realm name}`, and a realm rename moves it too (compat run 36113564506).
  The production hostname and realm name are therefore fixed together before the first token.
  Answered early because it is irreversible and cheap to ask
- Questions 5, 6, 7 exercised and handed to the consuming repositories
- ✅ Client key rotation, asked by identity-control — **signed-JWT keys overlap and revoke at
  once**; see below
- ⏳ Client suspension and deletion, asked by identity-control — what a disabled and a deleted
  client can still do; see below

### Client key rotation, asked by identity-control

TDD-identity-control-003 required a confidential or workload client's old and new credential to be
valid together through an overlap window, and the retiring one to stop working when revoked. It
first specified client secrets. A client secret cannot do that in 26.7.4 without a preview feature:
Keycloak holds one secret per client, and its secret-rotation policy (`client-secret-rotation`) is
classified preview, "not recommended for use in production".

`compat/client_keys_test.go` asks whether signed-JWT client authentication (`private_key_jwt`,
RFC 7523), a supported feature, gives both instead. The client's public keys are held as a JWKS on
the client, so identity-control registers them and no application has to serve a key endpoint.
The test covers four steps:

1. A client authenticates with key A.
2. With A and B both registered, each authenticates.
3. With A removed, A is refused at once and B still authenticates.
4. An assertion already used is refused.

**Answered.** Against `quay.io/keycloak/keycloak@sha256:82a77884…29b2c` (26.7.4) on 2026-09-29,
compat run 36606481342, every step held:

| Step | Accepted |
| :-- | :-- |
| A only registered, signed with A | yes |
| A and B registered, signed with A | yes |
| A and B registered, signed with B | yes |
| A removed, signed with A | **no**: refused on the next request |
| A removed, signed with B | yes |
| The same assertion used twice | **no**: the second is refused |

So identity-control can build rotation on supported features. The mechanism:

- Rotation adds a key to the client's JWKS.
- Revocation removes the key, and Keycloak refuses it on the next request.
- A captured assertion cannot be replayed.

No realm setting is needed. The keys are client attributes, which identity-control's registration
credential already manages. The test deletes its client, and the suite's closing `realm-apply
-require-in-sync` step passed.

**The answer is now the decision.** The following record it:

- `ADR-IAM-001 §5.12` and `STD-IAM-001 §3.2` in scnehaux-architecture: confidential and workload
  clients authenticate with `private_key_jwt`, and no client in a shared environment holds a client
  secret, development included.
- `TDD-identity-control-003` §Client Key Records and §Client Key Rotation.
- `TDD-identity-kernel-002` §Scope, which puts client keys out of its custody: the kernel holds only
  their public halves.

The test stays in the suite. A release that stops honouring the overlap or the removal fails
`compat/` rather than silently breaking rotation.

### Client suspension and deletion, asked by identity-control

TDD-identity-control-003 is to stop a registered client in two ways. `:suspend` disables its
Keycloak client and can be undone by `:restore`. `:retire` removes its keys and deletes the client,
so its `client_key` can be registered again. Both rest on what the kernel does to a client that is
disabled or deleted, and to the tokens it already holds. Consumers verify an access token locally
(STD-IAM-002), so a token issued before the stop is outside the kernel's reach until it expires,
and the design has to say so rather than assume it.

`compat/client_lifecycle_test.go` asks it of a client that authenticates by signed JWT, holding a
user's refresh token and a service-account token:

1. Disabled, the client gets no token by the client credentials grant.
2. Disabled, the refresh token it holds is refused.
3. Disabled, an access token issued before still verifies offline, until it expires.
4. Enabled again, the client gets a token again. Whether the refresh token from before works again
   is recorded, not required: it decides whether a restored BFF's users sign in again.
5. Deleted, it gets no token, and its refresh token is refused.
6. Deleted, an access token issued before still verifies offline.
7. Deleted, its service-account user is gone with it. Recorded, not required: it decides what a
   workload's retirement leaves behind.
8. After the deletion, a new client with the same `clientId` is accepted.

✅ **This repository's own client uses a key.** realm-apply's master-realm service account
authenticates by signed JWT:

- `internal/admin` signs the assertion, and reads its audience from the master realm's discovery,
  so a tunnel's frontend URL needs no configuration. Client-secret support is removed.
- `cmd/client-key` makes key pairs and installs public keys on any client. The development server's
  other clients use it too: identity-control's and the BFF's.
- `compat/admin_key_test.go` proves the path end to end: a service account with a registered key
  administers the realm, and a replaced key is refused at once.

The bootstrap administrator's password remains for a throwaway instance, such as CI's, and for the
first start of a server, before the service account exists.

**Exit:** a token signed by one replica verifies against every other replica; a replica
with an empty secret-manager response exits non-zero and signs nothing.

## Week 3 · Event listener

- Minimal listener capturing user, admin, and security events
- Delivery failure does not erase the source event
- Completeness reconciliation against supported event and admin state
- Compatibility tests against the pinned release

**Exit:** an event dropped in transit is detected by reconciliation rather than lost.

✅ Admin events are enabled in `realm/`, as TDD-identity-kernel-003 specifies: with representation
details (`adminEventsEnabled`, `adminEventsDetailsEnabled`), and kept 7 days
(`adminEventsExpiration`, 604800 seconds). Proof B depends on them. identity-control tells a
sanctioned console change from drift through the admin event that recorded it (identity-control
ROADMAP §Proof B, step 1). `compat/events_test.go` asserts that a change made by hand is recorded
with the user who made it and what it changed to.

Retention has no top-level key: Keycloak keeps it as a realm attribute. So `realmdef` now accepts
declared realm attributes, as strings, except the two that record the applied revision. It lays
them over the live attributes on apply, so the record is never dropped.

## Week 4 · Theme and upgrade suite

- Hosted login, MFA enrollment, and recovery theme against WCAG 2.2 AA
- Rotation rehearsed end to end, including the retirement window
- Upgrade compatibility suite: apply realm to a clean instance, assert the declared
  contract, assert the closed creation paths, rehearse rollback

**Exit:** a candidate release that changes the issuer form, drops a claim from a
covered surface, or reopens a creation path fails the suite.

## Not this repository

Recorded so scope creep is visible rather than convenient:

- Minting `principal_id` — `identity-control`.
- Applying Membership context projection and removing sessions — `identity-control`.
- Tenant, Workspace, and Membership authority — `organization-control`.
- Account security, administration, and developer console applications —
  `identity-experience`. Only the hosted login theme lives here.

## Gates

**Design gate.** All five designs at `1.0.0`, with questions 1 through 4 answered
against the pinned release and their outcomes recorded in the designs that depend on
them.

**Production gate.** The design gate, plus: key rotation and emergency rotation
rehearsed in staging, restore-to-earlier-point key reconciliation exercised, upgrade
and rollback rehearsed against production-like realm data, and runbooks written for
key ceremony, console drift, failed upgrade, and consumer reporting an unknown `kid`.
