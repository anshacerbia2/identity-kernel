---
doc_meta:
  id: TDD-identity-kernel-001
  title: Realm Topology, Issuer Identity, and Token Claim Projection
  owner: Identity Platform Team
  version: 1.5.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-09-25
  parent_sad: SAD-001
---

# Realm Topology, Issuer Identity, and Token Claim Projection

## Purpose

Specify the realm topology of the Keycloak Identity Kernel, the issuer identity every
Scnehaux token carries, the protocol mappers that project required enterprise claims
into audience-scoped tokens, and the realm settings that
close every Principal creation path other than the authorized one.

Two of these are irreversible in practice. Once tokens carrying an issuer have been
accepted and downstream domains have persisted `iss` alongside `principal_id` in
evidence records, changing the issuer is an enterprise-wide migration rather than a
configuration change. The same holds for the realm a Principal was created in. This
design fixes both before the first Principal exists.

## Scope

**In scope**

- Realm topology and the criteria that would justify an additional realm.
- Issuer URI form and the decision that fixes it.
- Audience-specific client scopes and protocol mappers for every STD-IAM-002 claim.
- Declarative user profile enforcement of attribute immutability.
- Realm settings that close self-registration and federated auto-creation.
- Configuration-as-code, its validation, and its drift detection.

**Out of scope**

- Minting `principal_id` and the creation call — owned by
  `TDD-identity-control-001`.
- Context projection and session removal — owned by `TDD-identity-control-002`.
- The login theme and its accessibility obligations.
- The event listener extension and its upgrade compatibility suite.
- Access token lifetime, owned by the STD-IAM-002 Token and Verification Profile.

## Technical Context

Keycloak is the adopted identity kernel under ADR-IAM-001. This repository owns its
configuration, its extensions, its theme, and its digest-pinned image; it does not own
the enterprise identity model, which lives in PAD-PLT-001.

Two constraints from the enterprise layer shape the topology directly.

EAD-006 §5.2 establishes distinct realm policies for ATI workforce, customer
workforce, partner identities, external consumers, federated enterprise identities,
and workload identities, and states that one human may hold one stable workforce
Principal across many Tenant Memberships while customer or partner identities may stay
realm-scoped where correlation is not justified.

ADR-IAM-001 §5.4 prohibits `Tenant = Realm` as the default model and requires a small
number of realms aligned to issuer, cryptographic, policy, residency, or
administrative trust boundaries.

Those two together fix the initial answer: one realm for the populations that share a
correlation policy, and an additional realm only where a one-way trust boundary
exists. Tenant count is not a splitting criterion, and SAD-001 §4.3 states so.

## Component Design

### Realm Topology

```text
Scnehaux Primary Realm
├── ATI workforce Principals
├── approved customer and partner identities under the realm correlation policy
├── internal and external protocol clients
├── protected-resource registrations
└── bounded Membership context projection
```

An additional realm requires an ADR and evidence of at least one of: independent
issuer trust, cryptographic isolation, a regulatory or residency boundary,
independently delegated realm administration, an incompatible authentication policy,
or acquisition and migration isolation.

The cost of the alternative is what makes this the default. A realm per Tenant
duplicates every workforce identity into every Tenant a cross-client operator works
in, fragments issuer and key configuration, and turns a Membership change into an
identity migration. ATI operators working across many client Tenants are the primary
population, so that model fails on the most common case rather than an edge one.

### Issuer Identity

Keycloak derives `iss` from the realm path by default:

```text
https://identity.scnehaux.com/realms/scnehaux
```

Whether the `/realms/{name}` segment can be removed without leaving a supported
configuration is settled by proof-of-concept. Both outcomes are acceptable, and the
decision is recorded either way rather than inherited by default:

| Outcome | Consequence |
| :-- | :-- |
| A vendor-neutral issuer is supported | `iss` carries no vendor or realm name, and a future kernel change does not alter the issuer downstream domains trust |
| The path form is retained | `iss` names the realm, and a realm rename or kernel change becomes an issuer migration |

The second outcome is not a failure. It is a cost accepted with open eyes, and
recording it means a future migration is planned rather than discovered.

**Settled: the path form is retained.** Against 26.7.4 on 2026-09-25 (compat run
36113564506), Keycloak composes `iss` as `{frontend URL}/realms/{realm name}`. Its two
supported inputs set only the prefix:

- the server hostname, which may carry a path;
- a realm's `frontendUrl`, with or without a path.

No supported configuration removes the segment. A reverse-proxy rewrite does not either,
because `iss` is composed inside Keycloak rather than read from the request path. Removing
it would take a custom issuer extension, which is a restricted extension under
ADR-IAM-001 rather than configuration.

Renaming the realm moves its issuer too, so the realm name is as irreversible as the
hostname. Two things follow for production:

- **The hostname and the realm name are decided together, once, before the first token:**
  `https://identity.scnehaux.com/realms/scnehaux`.
- **A development server's issuer is not the production issuer.** Nothing may store a
  development `iss` as though it were the production one.

`compat/` asserts the composed form on every candidate release.

`iss` is retained in evidence records alongside `principal_id` and `sub`, so
protocol-level and enterprise-level identity stay reconcilable across any future
issuer change.

### Claim Projection

Identity Control writes canonical identity attributes and the chosen context projector
writes active context attributes. Identity Kernel owns the supported mapper
configuration that turns them into the STD-IAM-002 contract:

| Source attribute | Claim | Profile |
| :-- | :-- | :-- |
| `scnehaux_principal_id` | `principal_id` | internal, privileged, provider, workload |
| `scnehaux_subject_type` | `subject_type` | internal, privileged, provider, workload |
| `scnehaux_workload_owner` | `workload_owner` | workload only |
| `scnehaux_provider_scope` | `provider_scope` | provider only |
| authentication session (`AUTH_TIME` note), authentication level | `auth_time`, `acr` | privileged, provider |
| projected active Tenant | `tenant_id` | internal, privileged, tenant-scoped workload |
| projected active Workspace | `workspace_id` | optional internal/privileged/workload |
| projected Membership version | `membership_version` | whenever `tenant_id` is present |
| projected Tenant security version | `tenant_security_version` | whenever `tenant_id` is present |

These mappers live in the audience client scopes of STD-IAM-002 §3.2.1:
`scnehaux-internal`, `scnehaux-privileged`, `scnehaux-provider`, and `scnehaux-workload`.
`scnehaux-external` contains none of them and uses a pairwise `sub`.

`scnehaux-provider` is the provider-scope form of the privileged profile (§3.1.1). It carries
`principal_id`, `subject_type`, `provider_scope`, `acr`, and `auth_time`, and never `tenant_id` or a
version claim, because a provider operation belongs to no Tenant. It is what identity-control
accepts to mint a Principal. `provider_scope` is written only by identity-control's bootstrap
ceremony, and like every `scnehaux_*` attribute it is admin-managed and not user-editable.
`auth_time` exists only for an authentication ceremony, so a direct grant cannot produce a
conformant provider token. No enterprise mapper is attached as a realm default, because doing so
would leak stable correlation and Tenant context into external tokens.

| Surface | Requirement |
| :-- | :-- |
| Access token | Mandatory. STD-IAM-001 §3.3 requires internal access tokens to carry `principal_id`, and requires a protected resource to reject an internal-audience token without it |
| ID token | Target |
| UserInfo | Target |
| Introspection | Target |

**Settled: outcome 1.** Against Keycloak 26.7.4,
`quay.io/keycloak/keycloak@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c`,
on 2026-09-25, all four surfaces carry `principal_id` and `subject_type` through the supported
`oidc-usermodel-attribute-mapper`, with identical values. The target configuration is adopted, and
`realm/contract.json` declares the four surfaces as the contract `compat/` asserts on every upgrade.

Introspection is audience-restricted in that release: a client may introspect only a token whose
`aud` names it, and any other client receives `{"active":false}`. A consumer that resolves identity
through introspection must therefore introspect as the protected resource the token is for. The
failure mode of getting this wrong is every token reading as inactive — closed rather than open,
and a total outage for that consumer.

Coverage was settled by proof-of-concept, and the outcome was pre-decided so a partial
result would need no unplanned amendment:

1. All four covered — adopt the target configuration.
2. Access token covered, one or more of the others not — adopt access-token-only,
   record the uncovered surfaces in this design and in
   `TDD-identity-control-001`, and prohibit consumers from resolving enterprise
   identity through them. No standard amendment and no custom extension is required.
3. Access token not covered by any supported mapper — escalate. This is the single
   outcome that forces a restricted Keycloak extension or a standard amendment, and it
   is why this question runs before the other six.

`sub` stays the issuer-scoped protocol subject and may be pairwise for external
relying parties. STD-IAM-001 §3.3 prohibits any Scnehaux domain from using `sub` as an
enterprise foreign key, so the two claims never converge.

### Closing Unauthorized Creation Paths

`TDD-identity-control-001` establishes one authorized creation path. Every other path
is closed here, by configuration rather than by policy:

| Setting | Value | Path closed |
| :-- | :-- | :-- |
| User registration | disabled | Self-registration |
| Identity provider first-login flow | no automatic user creation | Federated auto-creation |
| Declarative user profile `scnehaux_principal_id` | admin-managed, not user-editable | Attribute mutation through account self-service |
| Declarative user profile `scnehaux_subject_type`, `scnehaux_workload_owner`, and `scnehaux_provider_scope` | admin-managed, not user-editable | Claim-source mutation through account self-service |
| Admin Console user creation | restricted to break-glass roles | Direct console creation |

Keycloak enforces no uniqueness on user attributes, so the uniqueness invariant for
`principal_id` is held by the Control Plane database and never by this realm. The
reconciler in `identity-control` treats an unmapped Principal as evidence that one of
these settings has regressed. That sweep is a compensating control; these four
settings are the primary one.

## Data Model

### User Representation

```json
{
  "username": "operator@example.com",
  "enabled": true,
  "attributes": {
    "scnehaux_principal_id": ["019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71"]
  }
}
```

### Declarative User Profile

```json
{
  "attributes": [
    {
      "name": "scnehaux_principal_id",
      "displayName": "Scnehaux Principal Identifier",
      "permissions": { "view": ["admin"], "edit": ["admin"] },
      "required": { "roles": ["admin"] },
      "multivalued": false
    }
  ]
}
```

`edit` excludes `user`, which is what removes the self-service mutation path. Against
26.7.4 the account API refuses the change with `error-user-attribute-read-only` and
does not show the attribute to its user.

**Settled: detected, not enforced.** The declarative profile does not prevent an
administrator from editing the value, and no declarative configuration can. With
`edit=["admin"]` an administrator's change is applied, as it must be for
`identity-control` to write the attribute at creation. An attribute that nobody may
edit is not a write-once alternative: the Admin API answers `201` to a creation
carrying it and silently drops the value. So immutability against administrators rests
on the narrow Admin API role set in `TDD-identity-control-001` plus reconciler
detection. That is the reduced guarantee, recorded rather than assumed away.

The reduced guarantee is narrower than it first appears. The capability that can
rewrite the attribute, `manage-users`, can already reset any user's credentials, so
rewriting an identifier gives its holder nothing that role does not already give.
Immutability here is therefore a property of who holds `manage-users`, not a separate
control. Until the sweep runs, a rewritten identifier is carried into tokens:

- A fresh value reads as an orphan.
- Another Principal's value reads as a duplicate.

Both are disabled on the next sweep.

A disable sent as the partial representation `{"enabled": false}` keeps the
identifier and the profile fields. Quarantine may therefore send only what it
changes, and `compat/` fails any release that starts erasing attributes on a partial
update.

### Attribute Search

`q=scnehaux_principal_id:{id}` is the recovery index in `TDD-identity-control-001`.
Against 26.7.4 it behaves as follows:

- **Exact.** No prefix, substring, or one-character extension of the value matches.
- **Case-insensitive.** A value differing only in case does match.
- **Disabled users.** It finds them.
- **Paging.** It pages through `first` and `max` without loss or overlap.
- **Count.** `/users/count` honours `q`.
- **Uniqueness.** Keycloak does not enforce it: two users holding one value are both
  accepted and both returned.

Case-insensitivity is harmless while identifiers are written in canonical lowercase,
which `identity-control` must therefore always do. Two stored values that differ only
in case are one identifier to the index, so recovery would quarantine both. `compat/`
fails a release that loosens the match.

### Token Shape

```json
{
  "iss": "https://identity.scnehaux.com/realms/scnehaux",
  "sub": "<issuer-scoped protocol subject>",
  "principal_id": "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71",
  "subject_type": "human",
  "tenant_id": "019235f2-4d11-7a03-b8c7-1e9f7a2c4b60",
  "membership_version": 14,
  "tenant_security_version": 3,
  "aud": ["hcm-api"],
  "iat": 1786000000,
  "exp": 1786000240
}
```

`tenant_id` and the version claims come from the projected Membership context applied
by `identity-control`. Exactly one Tenant context appears, and at most one Workspace
context, as STD-IAM-001 §3.3 requires. The Membership set is never placed in a token,
bounded or otherwise.

## API / Interface

This repository publishes no runtime API. It publishes three artifacts:

| Artifact | Consumer |
| :-- | :-- |
| Realm configuration, version controlled and applied by the deployment pipeline | The Keycloak cluster |
| Digest-pinned container image including approved extensions | The deployment pipeline |
| Declared realm contract: issuer, claim set per surface, and supported Keycloak range | `identity-control`, `identity-experience`, and every protected resource |

The declared realm contract is what other repositories build against. Changing a claim
or a surface it names is a breaking change and follows the compatibility window in
SAD-001 §11.

## Algorithms / Logic

### Configuration as Code

Realm configuration is declarative, version controlled, and applied by the pipeline.
No configuration is authored through the Admin Console in any environment above local
development.

```text
apply:
    render the realm definition for the target environment
    diff against the live realm through the supported Admin API
    fail the deployment when the live realm carries changes the definition does not
    apply the difference
    record the applied revision
```

The diff step is what detects unmanaged console drift. ADR-IAM-001 §5.7 prohibits
unmanaged Admin Console changes to controller-owned configuration, and SAD-001 §9.4
requires drift to be detected before an upgrade rather than discovered during one.

A live realm can differ from the definition for two reasons. The definition changed, and
the difference should be applied. Or someone changed the realm by hand, and the apply
should be refused. The two can only be told apart by knowing what was applied last.

`cmd/realm-apply` therefore records the applied git revision and a digest of the
definition in the realm's own attributes. The next run reads the definition at that
revision and compares it with the live realm; any difference was made outside the
pipeline. Keeping this state in the realm means every operator and every pipeline reads
the same baseline, with no state file to lose or diverge.

Two limits are part of the design rather than gaps in it:

- **The drift check reaches only what the definition declares.** An undeclared field is
  not compared. The exception is a client scope's mapper set, which is closed.
- **The apply deletes nothing but undeclared mappers.** Removing a user-profile attribute
  discards its values from every user, and removing a client scope strips its claims from
  every client using it. Both are migrations.

### Upgrade Compatibility

Every Keycloak upgrade runs the compatibility suite in this repository before the
image is promoted:

```text
for the candidate Keycloak release:
    build the image with pinned extensions
    apply the realm definition to a clean instance
    assert the declared realm contract: issuer form, claim presence per surface
    assert the four closed creation paths remain closed
    assert the declarative user profile still restricts the attribute
    run the event adapter compatibility tests
    rehearse rollback, including the database migration boundary
```

A release that changes the issuer form, drops a claim from a surface, or reopens a
creation path fails the suite. Those three are the properties downstream domains have
persisted against, so they are asserted rather than observed.

## Configuration

| Setting | Value | Reason |
| :-- | :-- | :-- |
| Realm | `scnehaux` | Single primary realm; additional realms require an ADR |
| User registration | disabled | Removes the unauthorized creation path |
| Identity provider first-login | no automatic user creation | Removes the federated creation path |
| `scnehaux_principal_id` | admin-managed, not user-editable, single-valued | Preserves immutability |
| `scnehaux_subject_type` | admin-managed, not user-editable, single-valued | Distinguishes human and workload Principals |
| `scnehaux_workload_owner` | admin-managed, workload only, single-valued | Carries workload accountability |
| `scnehaux_provider_scope` | admin-managed, not user-editable, single-valued | Names the bounded provider authority of a provider-scope token |
| Audience client scopes | exactly one of internal, privileged, provider, workload, external | Applies the STD-IAM-002 claim allowlist |
| Signing algorithm | `PS256` | STD-IAM-002 §3.2.2 initial baseline |
| Preview features | disabled | ADR-IAM-001 §5.8 requires a separate ADR to enable any |
| Image | pinned by digest | SAD-001 §7.6 |

Signing keys are provisioned through approved protected custody. Per-process or
per-replica production key generation is prohibited, including as a fallback when
custody is unreachable, and one `kid` maps to exactly one immutable key pair for its
entire lifecycle. Both rules come from STD-IAM-001 §3.5 and are asserted by the
compatibility suite rather than left to operational discipline.

## Testing Strategy

### Realm Contract

- A created Principal carries `scnehaux_principal_id` in its Keycloak representation.
- A human internal access token carries `principal_id` and `subject_type=human`.
- A provider token, obtained by Authorization Code with PKCE, carries `principal_id`,
  `subject_type`, `provider_scope`, `acr`, and the `auth_time` of the login, and no `tenant_id`,
  version claim, or `workload_owner`.
- A workload token carries `principal_id`, `subject_type=workload`, and
  `workload_owner`.
- Every surface the adopted configuration claims to cover carries the profile's claim
  set, and values are identical across all covered surfaces.
- An external token carries none of the enterprise or context claims, even when the
  same Principal also uses an internal client.
- Tokens are signed with `PS256`; changing only the untrusted `alg` header does not
  select another verifier path.
- `sub` and `principal_id` hold different values, confirming the claims are distinct.
- `iss` matches the recorded issuer form exactly.

### Creation Paths

- Self-registration is unreachable in the configured realm.
- Federated first-login creates no user.
- The `scnehaux_principal_id` attribute cannot be modified through account
  self-service.
- A non-administrative account cannot read or write the attribute.

### Configuration Integrity

- A realm changed through the Admin Console is detected by the diff before the next
  apply, and the deployment fails.
- Applying the definition twice produces no change on the second run.
- A preview feature enabled outside an approved ADR fails the pipeline.

### Upgrade

- The compatibility suite passes against the candidate release before promotion.
- A release dropping the claim from a covered surface fails the suite.
- A release loosening attribute search beyond exact match, or erasing the identifier on
  a partial update, fails the suite.
- Rollback is rehearsed, and the database migration boundary beyond which rollback is
  unavailable is recorded for the candidate release.

## Security Notes

`principal_id` is pseudonymous. It carries no name, address, or credential material,
and disclosure of the value alone authenticates nobody. It is deliberately stable and
enterprise-wide, which makes it a correlation key, so it is restricted to internal
audiences. External relying parties receive `iss` and `sub`, with pairwise subjects
where cross-relying-party correlation is not justified.

The realm holds every credential, authenticator, and session in the estate. Its
administration is not the ordinary enterprise administration interface: SAD-001 §7.2
restricts Admin Console access, and enterprise administration goes through the
Identity Control API instead.

Preview features stay disabled. A preview feature in the authentication path is a
dependency on behavior the vendor has not committed to, in the one system where a
behavior change is a security event.

## Performance Notes

Nothing in this design sits on a request path at runtime. Realm configuration is
applied at deployment, and the protocol mapper executes during token issuance at a
cost proportional to one attribute lookup already loaded with the user.

The compatibility suite runs per candidate release, not per commit, because its cost
is dominated by starting a clean Keycloak instance and applying a full realm.

## Operational Notes

| Signal | Warning | Critical |
| :-- | :-- | :-- |
| Console drift detected at apply | any occurrence | — |
| Claim absent from a covered surface | — | any occurrence |
| Creation path reopened | — | any occurrence |
| Signing key or certificate approaching expiry | 30 days | 7 days |
| Preview feature enabled | — | any occurrence |

Runbooks required before production: console drift reconciliation, failed upgrade and
rollback, signing-key incident, and issuer change assessment.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-001 — Scnehaux Identity Runtime |
| Realizes capability | PAD-PLT-001 — Identity & Access Platform |
| Governed by | ADR-IAM-001 — Adopt Keycloak Identity Kernel; realm strategy, extension policy, operational baseline |
| Conforms to | STD-IAM-001 §3.3 — `principal_id` on internal access tokens; `sub` is not an enterprise foreign key |
| Conforms to | STD-IAM-001 §3.5 — one `kid` to one immutable key pair; no per-replica production key generation |
| Enterprise constraint | EAD-006 §5.2 — distinct realm policies per identity population; correlation limited to justified realm and purpose |
| Enterprise constraint | EAD-003 — canonical identifiers are opaque, stable, and authority-scoped |
| Consumed by | `TDD-identity-control-001` — depends on the four closed creation paths and the mapper |
| Consumed by | `TDD-identity-control-002` — projected context representation is applied against this realm |

### Open Proof-of-Concept Questions

Run in this order. The first is the only one whose answer can force an extension or a
standard amendment.

1. **Protocol mapper coverage.** Which of access token, ID token, UserInfo, and
   introspection can carry each audience profile's required claim set through supported
   mappers. Any mandatory access-token claim uncovered is the escalation case.
   **Answered 2026-09-25: outcome 1, all four covered** — see §Claim Projection. Answered for
   the internal human profile; the workload profile's `workload_owner` is exercised when the
   workload path is built.
2. **Attribute search semantics.** Whether `q=scnehaux_principal_id:{id}` is
   exact-match and how it paginates. Determines the recovery mechanism in
   `TDD-identity-control-001`; the creation path is unaffected either way.
   **Answered 2026-09-25: exact, case-insensitive, finds disabled users, pages without
   loss** — see §Attribute Search.
3. **Attribute immutability.** Whether the declarative user profile prevents
   administrator edits as well as self-service edits. Determines whether immutability
   is enforced or detected. **Answered 2026-09-25: detected, not enforced** — see
   §Declarative User Profile.
4. **Issuer URI form.** Whether `/realms/{name}` can be removed while remaining
   supported. Irreversible once tokens are issued, so it is decided either way before
   the first token rather than inherited. **Answered 2026-09-25: path form retained**.
   See §Issuer Identity.
