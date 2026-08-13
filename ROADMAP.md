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

- Digest-pinned Keycloak running from a reproducible image build
- Realm definition rendered, applied, and diffed by the pipeline
- Question 1 executed and reported
- Questions 2 and 3 executed

**Exit:** the declared realm contract is asserted by test — issuer form, claim presence
per covered surface, and the four closed creation paths.

## Week 2 · Key custody and questions 4 through 7

- Key ceremony rehearsed, sealed keystore in the secret manager
- `kid` derived as the RFC 7638 thumbprint, asserted at startup
- Startup refuses to serve when custody is unreachable
- Question 4 executed and recorded
- Questions 5, 6, 7 exercised and handed to the consuming repositories

**Exit:** a token signed by one replica verifies against every other replica; a replica
with an empty secret-manager response exits non-zero and signs nothing.

## Week 3 · Event listener

- Minimal listener capturing user, admin, and security events
- Delivery failure does not erase the source event
- Completeness reconciliation against supported event and admin state
- Compatibility tests against the pinned release

**Exit:** an event dropped in transit is detected by reconciliation rather than lost.

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
