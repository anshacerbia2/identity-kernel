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
  pinned by digest** (`image/keycloak.ref`, 26.7.5 since 2026-10-01; 26.7.4 before) and runs in CI; there is no image of our own
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

- ✅ `provider_scope` is no longer issued (TDD-identity-kernel-001 1.9.0). identity-control decides
  provider authority from its projection of Organization's grants (TDD-identity-control-006), and
  STD-IAM-002 §3.1.1 forbids reading a grant from a claim, so the mapper and the
  `scnehaux_provider_scope` attribute leave the definition. `realm-apply` deletes the mapper from a
  live realm; the attribute stays there unread, because removing one is a migration.

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
- Rotation through the five states of TDD-identity-kernel-002 1.1.0 (ADR-IAM-002 §5.2, NIST SP
  800-57): a staged key is published before it signs, and its private material is destroyed when it
  leaves the JWKS, every stored version of the sealed keystore included. No retention period
- ✅ Question 4 executed and recorded — **path form retained**. `iss` is
  `{frontend URL}/realms/{realm name}`, and a realm rename moves it too (compat run 36113564506).
  The production hostname and realm name are therefore fixed together before the first token.
  Answered early because it is irreversible and cheap to ask
- Questions 5, 6, 7 exercised and handed to the consuming repositories
- ✅ Client key rotation, asked by identity-control — **signed-JWT keys overlap and revoke at
  once**; see below
- ⏳ The claim closure (STD-IAM-002 §3.2, §3.2.1) — the realm's default client scopes are `basic` and
  `acr` only, declared in `realm/default-client-scopes.json` and held as closed sets by
  `realm-apply`; `scnehaux-profile` gives a BFF its name in the ID token alone;
  `compat/claim_closure_test.go` asserts no access token carries a claim outside the closure, for a
  BFF's user token and a workload's (TDD-identity-kernel-001 1.8.0 §Claim Projection)
- ✅ `service_account` keeps only its `client_id` mapper (STD-IAM-002 §3.2.1). Keycloak attaches the
  scope again on every update of a client with service accounts enabled
  (`ClientManager.updateClientServiceAccount`), so identity-control's detachment from a workload was
  undone by its next key rotation (identity-control#30, run 36828339504). `realm/client-scopes.json`
  declares the scope with its `Client ID` mapper alone, so `realm-apply` removes `Client Host` and
  `Client IP Address`, and a workload holds the scope without its address reaching a token.
  `compat/claim_closure_test.go` records the re-attachment and asserts the closure with the scope
  held
- ✅ RFC 9068 access tokens, asked by STD-IAM-002 §3.2 — **the kernel issues them once a client
  carries the `at+jwt` attribute and a `client_id` mapper**; the realm's built-in default scopes put
  claims the claim closure prohibits into both tokens; see below
- ✅ Client suspension and deletion, asked by identity-control — **a disabled or deleted client
  gets no new token and no refresh**; an access token issued before verifies offline until it
  expires; see below

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

### RFC 9068 access tokens, asked by STD-IAM-002

STD-IAM-002 §3.2 makes every access token an RFC 9068 token: header `typ` `at+jwt`, and the claims
`iss`, `exp`, `aud`, `sub`, `client_id`, `iat` and `jti`. §3.5 has a verifier refuse any other
type, which is what keeps an ID token from passing as an access token. Two properties of 26.7.4,
read from its source, decide who realizes it:

- The `at+jwt` header is a per-client attribute, `access.token.header.type.rfc9068`, off by
  default (Keycloak 26.2 release notes, "New client configuration for access token header type").
  identity-control sets it on every client it registers.
- `client_id` reaches a service-account token through the built-in `service_account` scope, and
  nothing puts it in a user's token. identity-control adds a hardcoded claim mapper per client.

`compat/rfc9068_test.go` sets both the way identity-control will and asks whether a user's token
and a workload's then conform, and whether the ID token stays distinguishable. It records, without
requiring, whether the built-in scope alone gives a workload token its `client_id`, and every claim
name the kernel issues, which STD-IAM-002's claim closure is measured against.

**Answered.** Against `quay.io/keycloak/keycloak@sha256:82a77884…29b2c` (26.7.4) on 2026-09-30,
compat run 36775603547, every required step held:

| Step | Observed | Required |
| :-- | :-- | :-- |
| Realm alone: a workload token carries `client_id` | yes | recorded |
| Realm alone: the header `typ` is `at+jwt` | **no** | recorded |
| Workload token: `typ` `at+jwt`, PS256, the seven claims, `client_id` names the client | yes | yes |
| User token: `typ` `at+jwt`, PS256, the seven claims, `client_id` names the client | yes | yes |
| The ID token's `typ` is not `at+jwt` | yes | yes |

So identity-control can make every token it registers a client for an RFC 9068 token: the
attribute for the header, and the mapper for a user's `client_id`. A workload's `client_id` also
comes from the built-in `service_account` scope.

**The claim list is the finding that matters.** A client made in this realm holds Keycloak's
built-in default scopes, because `realm/` does not declare the realm's default client scopes, and
they put into its tokens:

| Token | Claims beyond STD-IAM-002 §3.2 and RFC 9068 §2.2 |
| :-- | :-- |
| User | `email`, `email_verified`, `name`, `given_name`, `family_name`, `preferred_username`, `realm_access`, `resource_access`, `acr`, `azp`, `sid`, `typ` |
| Workload | `clientHost`, `clientAddress`, `email_verified`, `preferred_username`, `realm_access`, `resource_access`, `acr`, `azp`, `typ` |

Some come from scopes the realm attaches by default (`profile`, `email`, `roles`, and
`service_account`'s client address), and some Keycloak writes itself (`azp`, `sid`, `typ`).
STD-IAM-002 §3.2 prohibits personal data beyond what the audience requires and any claim it does
not define, so the next step is a decision on both groups, recorded in STD-IAM-002 and realized in
`realm/` and in identity-control. The test stays in the suite, and its claim list shows the effect.

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
   - With the client's not-before set while it was disabled, the refresh token from before is
     refused once it is enabled again, and a new sign-in works. Asked because the answer to 4 is
     yes (below): it is how a suspension ends what it paused.
5. Deleted, it gets no token, and its refresh token is refused.
6. Deleted, an access token issued before still verifies offline.
7. Deleted, its service-account user is gone with it. Recorded, not required: it decides what a
   workload's retirement leaves behind.
8. After the deletion, a new client with the same `clientId` is accepted.

**Answered.** Against `quay.io/keycloak/keycloak@sha256:82a77884…29b2c` (26.7.4) on 2026-09-30,
compat run 36765130059, every required step held:

| Step | Observed | Required |
| :-- | :-- | :-- |
| Enabled: client credentials | yes | yes |
| Disabled: client credentials | **no** | no |
| Disabled: the refresh token issued before | **no** | no |
| Disabled: the access token issued before verifies offline | yes | yes |
| Enabled again: client credentials | yes | yes |
| Enabled again: the refresh token issued before | **yes** | recorded |
| Deleted: client credentials | **no** | no |
| Deleted: the refresh token issued before | **no** | no |
| Deleted: the access token issued before verifies offline | yes | yes |
| Deleted: the service-account user is gone | **yes** | recorded |
| After deletion: a new client with the same `clientId` | yes | yes |

The two recorded answers are design inputs for identity-control:

- **A disable pauses a client's sessions; it does not end them.** A refresh token refused while the
  client was disabled is accepted again once it is enabled. So a suspension that contains a
  compromised client cannot rest on the disable alone, and TDD-identity-control-003 decides what
  else `:suspend` does.
- **Deleting a client deletes its service-account user.** A workload's Keycloak user is that user
  (TDD-identity-kernel-001 §Claim Projection), so retiring a workload's client removes the
  workload's projection in the kernel as well, and TDD-identity-control-004 has to retire the
  workload with it.

An access token issued before either stop is outside the kernel's reach until it expires, which the
lifetime class bounds (STD-IAM-002 §3.3). The test stays in the suite, so a release that changes any
required answer fails `compat/`.

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

### User containment, asked by identity-control

TDD-identity-control-005 2.2.0 contains a Principal through four Admin API calls:
- `:suspend` disables the user with a partial `PUT` and logs it out.
- `:restore` enables it.
- `sessions:terminate-all` logs it out.
- `:revoke` deletes one credential.

Each call is confirmed by a read-back before the operation counts as applied.

`compat/user_containment_test.go` asks the following of the pinned image:

1. **A disable alone.** The user reads back disabled, and a partial `PUT` of `enabled` keeps
   `scnehaux_principal_id`. A sign-in is refused, and the refresh token issued before is refused.
   - Recorded, not required: whether that refresh token works again once the user is enabled. A
     client's disable only pauses its sessions, and this answer says whether a user's disable does
     the same.
2. **Disable and logout, the suspension.** The session list reads back empty, and the refresh token
   issued before is refused. A second logout is accepted, so the call is idempotent.
3. **Enable again, the restoration.** The user reads back enabled and keeps its identifier. The
   refresh token from before the suspension stays refused, and a new sign-in works.
4. **Logout alone.** The session list is empty, and the refresh token issued before is refused.
5. **Delete the one credential.** It reads back absent, and the password no longer signs in.

**Answered.** The pinned 26.7.5 image answered on 2026-10-03, in compat run 37125613572, and every
required step held:

| Step | Observed | Required |
| :-- | :-- | :-- |
| Disabled: the user reads back disabled; `scnehaux_principal_id` kept | yes | yes |
| Disabled: a sign-in | **no** | no |
| Disabled: the refresh token issued before | **no** | no |
| Enabled again without a logout: the refresh token issued before | **yes** | recorded |
| Suspended (disable + logout): the session list is empty | yes | yes |
| Suspended: the refresh token issued before | **no** | no |
| Suspended: a second logout is accepted | yes | recorded |
| Restored: reads back enabled; identifier kept | yes | yes |
| Restored: the refresh token from before the suspension | **no** | no |
| Restored: a new sign-in | yes | yes |
| Logged out: the session list is empty; the earlier refresh token refused | yes; **no** | yes; no |
| Revoked: the credential reads back absent; the password signs in | yes; **no** | yes; no |

**A user's disable pauses its sessions; it does not end them**, as a client's does. So a suspension
that rested on the disable alone would hand every session back on restore. TDD-identity-control-005's
suspension logs the user out as well, and the restoration after that brings no session back.

### One session ended, asked by identity-control

TDD-identity-control-005 2.3.0 lets a person end one of their own sessions. The session is named by
the identifier the Admin API lists, and the session a request came from is marked by the access
token's `sid`. `compat/single_session_test.go` asks of the pinned image:
- whether that `sid` is the listed identifier;
- whether `DELETE /admin/realms/{realm}/sessions/{id}` ends that session and refuses its refresh
  token, while the user's other session keeps working;
- what a second delete answers. This is recorded, not required: the executor treats an absent session
  as ended either way.

**Answered.** The pinned 26.7.5 image answered on 2026-10-03, in compat run 37137921752, and every
required step held:
- The access token's `sid` is the listed session identifier.
- The delete ends that session alone: its refresh token is refused, and the other session keeps
  refreshing.
- A second delete answers `404`.

### Authentication levels, for ADR-IAM-004

The realm maps `acr` `aal1` and `aal2` to LoA 1 and 2 (`acr.loa.map`) and binds
`scnehaux-browser-v1`: a password at level 1, and TOTP at level 2 reused for 300 seconds
(TDD-identity-kernel-001 §Authentication Levels). realm-apply now manages authentication flows:
- they are declared in `realm/authentication-flows.json`;
- a missing flow is built whole, then bound;
- a bound flow is never edited in place;
- a partly built, unbound flow is rebuilt;
- the bound flow is compared for drift.

**Answered.** The pinned 26.7.5 image answered on 2026-10-03, in compat run 37150434728, and every
required step held:
- A password sign-in carries `aal1`.
- Asking for `aal2` with no second factor enrolls TOTP in that sign-in. The access and ID tokens
  then carry `aal2`.
- Within 300 seconds, `aal2` is reused without a page. `max_age=0` asks for the password and the code
  again.
- An unmapped `acr` (`phr`) is never answered with that level. It got the session's `aal2`.

**A second TOTP** (ADR-IAM-004 §5.5) is asked of the same test.
- After a sign-in at `aal2` with the first code, `kc_action=CONFIGURE_TOTP` sets up another TOTP.
- The person then holds two.
- Each of the two signs in at `aal2` alone.

**Answered** on 2026-10-03, in compat run 37153685891: every step held.

One finding changed the flow. With TOTP and WebAuthn as alternatives, the kernel refused a person who
held neither ("Invalid username or password") instead of offering enrollment. Level 2 therefore
requires TOTP, and WebAuthn waits for a flow version that follows its enrollment.

**WebAuthn at level 2.** `scnehaux-browser-v2` succeeds v1: level 2 asks for a WebAuthn
authenticator or a TOTP code. The OTP Form sits in a sub-flow of its own, so a person with neither
factor is still taken to TOTP enrollment (TDD-identity-kernel-001 1.11.0 §Authentication Levels). The
compat suite answers the WebAuthn pages with a software authenticator.

**Answered** on 2026-10-03, in compat run 37159258798. Every required step held:
- `kc_action=webauthn-register` after an `aal2` sign-in registers a key.
- With the TOTPs deleted, `aal2` asks for the password and the key and carries `aal2`.
- A person with neither factor enrolls a TOTP at their first `aal2` sign-in.
- Recorded: a person who holds both, TOTP enrolled first, is shown the TOTP page.

One finding fixed realm-apply. Setting a step's requirement without its priority reset the step to
priority 0. On Postgres, the upgrade job then listed two steps swapped. realm-apply now gives every
step its position as its priority.

### Recovery and guessing limits, for ADR-IAM-005

`scnehaux-browser-v3` adds the *Recovery Authentication Code Form* to level 2. `realm/required-actions.json`
is new, and realm-apply now governs required actions. It declares two things:
- *Configure OTP* issues recovery codes with the first TOTP;
- *Recovery Authentication Codes* and *Webauthn Register* stay enabled.

The realm enables brute-force detection in the mixed mode. The permanent lockout comes at the 100th
consecutive failure (TDD-identity-kernel-001 1.12.0 §Guessing Limits). `compat/` proves:
- codes at enrollment;
- recovery through *Try Another Way*;
- the next code asked for next;
- on a throwaway realm, the lockout mode and its release by enabling the user.

### Tenant context, for ADR-IAM-006

The realm enables Organizations. The `organization` scope is declared with one mapper, a flat
`tenant_id`: the alias of the Organization the client asked for with `organization:<tenant_id>`
(TDD-identity-kernel-001 1.13.0 §Tenant Context). This answers identity-control's questions 5 and 7.
The proof of concept ran on a throwaway realm in compat run 37207537199. `compat/` now requires:
- a flat `tenant_id`;
- the Tenant chosen per sign-in and kept by a refresh;
- `invalid_grant` after the member is removed or the Organization disabled, other Tenants
  unaffected;
- a workload's token;
- on the declared realm, the scope's flat claim, and no `tenant_id` for a client without the scope.

The tenant-scoped privileged profile, `scnehaux-privileged`, is declared (TDD-identity-kernel-001
1.14.0 §Claim Projection). The design named it and the realm did not, so no client could be issued
the tenant-scoped form a Tenant administrator needs (ADR-ORG-003 §5.3). `compat/privileged_test.go`
signs in with Authorization Code and PKCE, asks for `organization:<tenant_id>`, and requires
`principal_id`, `subject_type`, `acr`, `auth_time` and that `tenant_id`, and no `tenant_id` without
the request.

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

✅ User events are saved, for 7 days (`eventsEnabled`, `eventsExpiration` 604800), as
TDD-identity-kernel-003 1.1.0 specifies. Keycloak keeps none by default, so until now the native
store held admin events and not a single login. `realmdef` refuses a definition that saves either
kind below the floor of TDD-003 §Retention Constraint, one hour times twenty-four.
`compat/user_events_test.go` asserts that a login and a failed login are recorded with the user and
the client and carry no password.

✅ identity-control keeps the record (its TDD-007): it sweeps both stores through the Admin API in
overlapping windows and writes each event once, until Audit & Evidence has it. **Exit met by
construction:** with no listener there is no event in transit, and the sweep reads every event the
kernel recorded. The listener follows when a consumer needs events sooner than one reconcile
interval (TDD-003 1.1.0 §Technical Context, ADR-IAM-001 §5.7); an event it drops is then recovered
by the same sweep.

## Week 4 · Theme and upgrade suite

- Hosted login, MFA enrollment, and recovery theme against WCAG 2.2 AA
- Rotation rehearsed end to end, including the retirement window
- Upgrade compatibility suite: apply realm to a clean instance, assert the declared
  contract, assert the closed creation paths, rehearse rollback

**Exit:** a candidate release that changes the issuer form, drops a claim from a
covered surface, or reopens a creation path fails the suite.

✅ The upgrade suite, as `compat.yml` runs it: the `contract` job applies the realm to a clean
instance of the pinned image and asserts the declared contract, the issuer form (question 4), every
covered claim surface, and the four closed creation paths; the `upgrade` job has the candidate
upgrade the previous release's database, keeps the realm in sync, starts the previous release on
the migrated database to find the rollback boundary, and writes the release record. The four paths
are now all asserted (TDD-005 1.3.0): federated auto-creation is closed by a first login flow that
denies (TDD-001 1.15.0), and only service accounts manage users. **Not yet:** the signing key rotation
rehearsal, which waits on Week 2's custody.

✅ The login theme, first part (TDD-004 1.1.0, ADR-IAM-001 §5.7). `scnehaux` names `keycloak.v2` as its
parent and overrides no template: the kernel ships both locales, and the theme changes one message, so
a disabled account no longer tells itself apart from an unknown one. The realm uses it, with `en` and
`id`. The kernel image is built from the pinned digest plus the theme (TDD-005 1.4.0), and every CI job
and the development server run it.

✅ The login pages' browser security headers (TDD-004 1.2.0, STD-IAM-001 2.4.0 §3.9). The realm
declares them: no page can be framed, nothing loads from another origin, and HSTS, `nosniff` and
`no-referrer` are sent. `realmdef` refuses a weaker set, and `compat/browser_headers_test.go` asserts
them on the login page, a failed sign-in and an error page. Inline script stays allowed, a recorded
gap that closes when the kernel ships template nonces; `form-action` is not set, because Chrome
would block the redirect back to the client.

✅ The login pages in a real browser (TDD-004 1.3.0). `browser/` drives Chromium through one person's
sign-ins in each locale: the password and a one-time code typed from the keyboard, recovery codes
acknowledged, and a passkey bound and used through the virtual authenticator. axe-core scans every
surface reached against WCAG 2.2 A and AA in both colour schemes, and no page may raise a Content
Security Policy violation, which proves the realm's policy against the stock templates. The
`compat` workflow's `browser` job runs it, and it also uses a recovery code through "Try another
way". It found three stock templates that fail WCAG, so the theme copies each with one fix and
nothing else:

- `template.ftl` and `login-config-totp.ftl` have fields with no accessible name; their labels are
  corrected (keycloak#51206 for the second);
- `select-authenticator.ftl` has choices that cannot be activated from the keyboard; a key handler is
  added (keycloak#45227 left it out). `cmd/theme-overrides` proves each copy against
the image's themes jar in the `contract` job, and `-write` makes the copies again for a new release.

✅ The sign-in's timing (TDD-004 1.4.0, STD-IAM-001 2.5.0 §3.1). `compat/timing_test.go` measures by
dudect's method: the classes interleaved at random, Welch's t, and a threshold of 10. An unknown
identifier, a wrong password and a disabled account answer in about 44 ms, and no pair is
separable. An empty password (keycloak#51887) and an account under lockout answer an existing
account in about 16 ms, because the kernel skips the hash. Both are recorded gaps, measured on every
run.

✅ The kernel's operational surfaces (TDD-005 1.5.0, ADR-IAM-001 §5.8). The image is built optimized
with health and metrics, and a server starts it with `start --optimized`. The probes are Keycloak's
own, bound as its operator binds them, on the management port, which only the orchestrator and the
monitoring system reach; metrics are on, which also deepens readiness. `/admin` and `/realms/master`
are internal in every environment, and the Admin Console, kept in the one image for break-glass, is
not an operating surface. `compat/management_test.go` asserts the probes and metrics on 9000 and
their absence on 8080.

## Development server

✅ A long-lived development Keycloak, so local applications have a real issuer to develop against.
[`deploy/dev/`](deploy/dev/README.md) runs the pinned image in production mode on Postgres. The realm
is applied with `cmd/realm-apply`. Two access modes, and CI brings up both:

- **A DNS name:** Caddy obtains the certificate, and administration is allowlisted by address.
- **A dev tunnel (the current server):**
  - The public tunnel port reaches Caddy, which refuses `/admin` and `/realms/master` to everyone.
  - Administration uses an owner-only tunnel port.
  - An address allowlist cannot work behind a tunnel, because every request arrives from the tunnel
    agent.

It is development only:

- `realm-apply` refuses any environment that serves real tokens, because the signing key is generated
  in-process.
- The tunnel host is the issuer, so it is not the production issuer, and nothing may store a
  development `iss` as though it were.
- Principals are created by `identity-control`, which runs beside it (identity-control's
  `deploy/dev/`), and never by hand in the Admin Console.

## Sender constraint, the recorded gap

STD-IAM-002 §3.8 records that the baseline's access tokens are bearer tokens, although RFC 9700
§2.2.1 says they SHOULD be sender-constrained, and tracks the gap here. **Not built, by decision.**
The gap is bounded by where the tokens go:

- a browser never holds one: the BFF keeps its tokens server-side, and the browser holds a cookie;
- a service calls another over mutual TLS or with a service-mesh token (STD-GLB-001);
- an `external` relying party holds its tokens outside both paths. It is the case left open.

**When it is decided.** In an ADR, before an `external` profile is issued to a relying party the
platform does not operate, or before an access token is issued to a browser (STD-IAM-002 §3.8).
Neither has happened: no `external` registration exists, and no client but the BFF signs a user in.

**What the pinned kernel offers**, per client, both documented in the 26.7.5 Server Administration
Guide:

- **DPoP** (RFC 9449), *Require DPoP bound tokens*. A supported feature since 26.4, no longer
  preview. Without the setting a client may still send a DPoP proof, and the token is then bound.
- **Mutual TLS certificate-bound tokens** (RFC 8705), *OAuth 2.0 Mutual TLS Certificate Bound
  Access Tokens Enabled*. It needs TLS client certificates to reach Keycloak, which the dev
  server's tunnel does not carry.

**What the decision has to cover**, because the binding is worth nothing unless the resource checks
it:

- the verifier: foundation-platform `verify` would check `cnf.jkt` against the DPoP proof
  (RFC 9449 §7) or `cnf.x5t#S256` against the presented client certificate (RFC 8705 §3), and
  refuse a bound token presented as a bearer token;
- registration: identity-control setting and comparing the client attribute, as it does at+jwt;
- `compat/`: a bound token issued and refused without its proof, against the pinned image.

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
