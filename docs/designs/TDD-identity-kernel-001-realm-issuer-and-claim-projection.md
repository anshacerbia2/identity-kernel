---
doc_meta:
  id: TDD-identity-kernel-001
  title: Realm Topology, Issuer Identity, and Token Claim Projection
  owner: Identity Platform Team
  version: 1.16.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-10-07
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
| authentication session (`AUTH_TIME` note), authentication level | `auth_time`, `acr` | privileged, provider |
| the Organization selected at sign-in (its alias) | `tenant_id` | internal, privileged, tenant-scoped workload, through the `organization` scope |

`workspace_id` is not projected (`ADR-IAM-006 §5.6`). The version claims left the token in
STD-IAM-002 1.6.0.

These mappers live in the audience client scopes of STD-IAM-002 §3.2.1, except `tenant_id`
(§Tenant Context, below):
`scnehaux-internal`, `scnehaux-privileged`, `scnehaux-provider`, and `scnehaux-workload`.
`scnehaux-external` contains none of them and uses a pairwise `sub`.

`scnehaux-provider` is the provider-scope form of the privileged profile (§3.1.1). It carries
`principal_id`, `subject_type`, `acr`, and `auth_time`, and never `tenant_id`,
because a provider operation belongs to no Tenant. It is what identity-control accepts to mint a
Principal.

**It carries no `provider_scope`.** STD-IAM-002 §3.1.1 requires a resource that holds a provider
grant, or a projection of it, to check its record for each request by the token's `principal_id`,
and never to read the grant from a claim. Organization Control holds the grants and identity-control
holds the projection of `provider:identity-control` (`ADR-ORG-002 §5.3`,
`TDD-identity-control-006`). No resource in the estate checks a provider grant from a claim, so the
kernel issues none. This is how Google Cloud IAM and Kubernetes decide access: the token establishes
who the caller is, and the resource evaluates the policy it holds (STD-IAM-002 R19, R20). A claim
would also outlive an activation ended early until the token expired. The `provider_scope` mapper
and the `scnehaux_provider_scope` attribute are therefore not in the definition.

*Tradeoff.* A client still configured for the old profile stops working, because identity-control
refuses a token that carries the claim, rather than being read silently as an owner. On a realm
applied before this revision, `realm-apply` deletes the mapper, because a managed scope's mapper
set is the definition's. It leaves the attribute in the live user profile, because Apply deletes
nothing whose removal is a migration (§Configuration as Code). No mapper reads it, so a value a
user still holds reaches no token.
**`scnehaux-privileged` is the tenant-scoped form of the privileged profile (1.14.0).** A privileged
operation inside one Tenant, such as administering it at Organization Control (`ADR-ORG-003 §5.3`),
needs the same four claims as a provider token and the Tenant it acts in. The scope carries
`principal_id`, `subject_type`, `acr` and `auth_time`, with the provider scope's four mappers. The
`tenant_id` comes from the kernel's `organization` scope, which the registration authority attaches
to such a client as optional (`ADR-IAM-006 §5.3`). A sign-in asking for `organization:<tenant_id>`
gets that Tenant, and one asking for none gets no `tenant_id`. The scope never carries
`provider_scope`.

Up to 1.13.0 this design named the scope and the realm did not declare it. No client could hold it,
so the tenant-scoped form of STD-IAM-002 §3.1.1 had no way to be issued. A client holds exactly one
audience profile scope (STD-IAM-002 §3.2.1), so a provider client cannot also be tenant-scoped: a
console that does both is two clients.

`auth_time` exists only for an authentication ceremony, so a direct grant cannot produce a
conformant provider token. No enterprise mapper is attached as a realm default, because doing so
would leak stable correlation and Tenant context into external tokens.

`scnehaux-workload` is the workload profile. It carries `principal_id`, `subject_type` and
`workload_owner`, and never `acr`, `auth_time` or `provider_scope`. A tenant-scoped workload adds
`tenant_id` the way a person does (§Tenant Context). **A workload's claim-source attributes live on its client's
service-account user.** A workload authenticates as its own client with the client credentials
grant and a registered key (`ADR-IAM-001 §5.12`), and that grant issues its token for the
client's service-account user, the user Keycloak creates with the client. No other user's
attributes reach the token. identity-control therefore writes `scnehaux_principal_id`,
`scnehaux_subject_type=workload` and `scnehaux_workload_owner` on that user, under the same
declared profile as a human's. `workload_owner` is mapped by this scope alone, so a human who came
to hold the attribute still receives no `workload_owner` claim.

**A workload client does not hold the built-in `acr` scope.** Keycloak makes `acr` a realm default
client scope, so every new client holds it, and it puts `acr=1` into a client credentials token,
which STD-IAM-002 §3.2 prohibits for a workload. identity-control detaches it when it registers a
workload (`TDD-identity-control-003`). The realm default is left as it is: removing it would change
every client created after, and a provider token's `acr` comes from `scnehaux-provider` either way.
`compat/workload_test.go` asserts the workload token, the detachment included, and the absence of
`workload_owner` from an internal token.

### Tenant Context (1.13.0)

`ADR-IAM-006` decides how the active Tenant reaches a token. The realm enables Keycloak's
Organizations, a supported feature that is on by default in the pinned kernel. Each Tenant is an
Organization:
- its alias is the `tenant_id`;
- its members are the Principals with an active Membership in that Tenant;
- it is enabled while the Tenant is active.

identity-control maintains them through the Admin API (`TDD-identity-control-002`). The realm
declares none, because they are Organization's data, not realm configuration.

**The `organization` scope.** Keycloak creates this scope with every realm and makes it a realm
default optional scope [R11]. The realm declares it in `realm/client-scopes.json` with one mapper,
`tenant_id`: the *Organization Membership* mapper, single-valued, with the claim name `tenant_id`.
- A single-valued mapper emits only the selected Organization's alias [R12]. The alias is the
  `tenant_id`, so the claim is flat.
- The scope's built-in mapper, `organization`, writes a nested `organization` object. A managed
  scope's mapper set is the definition's, so `realm-apply` deletes it.
- The realm's default optional scopes are a closed, empty set (§Claim Projection). So the scope is
  never a realm default, and only a client the registration authority gives it can ask for it
  (`ADR-IAM-006 §5.3`).

**Choosing the Tenant.** A client asks with `organization:<tenant_id>`, and the kernel issues the
claim only for a member [R13].
- A refresh keeps the Tenant. Asked for another, it drops the Tenant rather than switching.
- A token asked for without the scope carries no `tenant_id`.

**Revocation in the kernel.** Each check is the kernel's own, made at every refresh [R12]:
- **A member removed:** a refresh for that Tenant is refused with `invalid_grant`, and a new token
  for it carries no `tenant_id`.
- **The Organization disabled:** a refresh for that Tenant is refused the same way.
- **The person's tokens for other Tenants** are unaffected.

**Proof.** The proof of concept answered each of these on the pinned image, the workload token
included (compat run 37207537199), and `compat/organizations_test.go` now requires them.

**The realm's default client scopes are `basic` and `acr`, and nothing else.** Keycloak creates a
realm with `profile`, `email`, `roles`, `web-origins` and others as default and optional client
scopes, so every new client held them, and compat run 36775603547 found their claims in internal and
workload access tokens: email, names, usernames, realm and client roles. STD-IAM-002 §3.2 prohibits
personal data and roles in an access token, so `realm/default-client-scopes.json` declares the two
sets, and `realm-apply` holds both as closed sets: a scope it does not name is removed from them,
and a console change to either is drift. `basic` gives `sub` and `auth_time`, and `acr` the
authentication context; the audience profile scope a client registers with adds the rest.

Changing the realm's defaults changes only the clients created after it. identity-control detaches
the built-in scopes from the clients it already registered or adopted, and its sweep holds them
detached (`TDD-identity-control-003`). Keycloak's admin endpoints authorize a client's service
account from its role mappings, not from the roles in its token, so a client without `roles` keeps
its administration access. The account API is the exception: it authorizes self-service from the
account roles in the token. The realm's built-in `account-console` client keeps the scopes it was
made with, `roles` among them, because it is made with the realm, before the defaults are narrowed,
so a user's self-service through it is unchanged. `compat/immutability_test.go` gives its probe
client `roles` for the same reason.

**`service_account` keeps only its `client_id` mapper.** Keycloak attaches the built-in scope to a
client whose service accounts are enabled, and attaches it again on every update of such a client
(`ClientManager.updateClientServiceAccount`), so a workload cannot be kept without it: identity-control
found a detachment undone by the next key rotation. Its other two mappers write the client's network
address, `clientHost` and `clientAddress`, into the token. So `realm/client-scopes.json` declares the
scope with its `Client ID` mapper alone, `realm-apply` removes the other two as it removes any
undeclared mapper of a declared scope, and a workload holds the scope without the address reaching a
token. The scope is not removed or renamed: Keycloak looks it up by name.

**`scnehaux-profile` gives a first-party BFF the name it shows, in the ID token only.** Its two
mappers write `name` and `preferred_username` into the ID token and UserInfo and never into an
access token. It is not a realm default and not an audience profile: identity-control attaches it
to a confidential client as an optional scope, and the BFF requests it at sign-in.

Three claims are written by the kernel's token code rather than by a mapper, and no scope removes
them: `azp`, `sid` and a payload `typ`. STD-IAM-002 §3.2 admits them. `compat/claim_closure_test.go`
asserts that an access token carries nothing beyond the claims STD-IAM-002 §3.2 defines, RFC 9068
§2.2 requires, and those three.

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
| Declarative user profile `scnehaux_subject_type` and `scnehaux_workload_owner` | admin-managed, not user-editable | Claim-source mutation through account self-service |
| Admin Console user creation | restricted to break-glass roles | Direct console creation |

**Federated auto-creation is closed by a flow that denies (1.15.0).** The kernel's own first login
flow runs Create User If Unique, which "creates a new local {project_name} account and links it with
the identity provider", and "By default, the `First Login Flow` option points to the `first broker
login` flow" (Server Administration Guide, First login flow; ADR-IAM-001 [R43]). Up to 1.14.0 the
realm declared no first login flow, so an identity provider added in the console would have created
an account no Principal maps. The realm now binds `firstBrokerLoginFlow` to
`scnehaux-first-broker-login-v1`, whose one execution is the kernel's `deny-access-authenticator`.
Federation is not designed yet; when it is, a flow that links to an existing Principal replaces this
one. `compat/creation_paths_test.go` asserts the binding and the flow, and records what a provider
added without a flow of its own inherits.

**Admin Console creation is held to service accounts.** In the realm, only a service account holds
`manage-users` or `realm-admin`, directly or through a group, so no person signs in to the console and
creates a user beside identity-control's path. `compat/creation_paths_test.go` asserts it.

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
  "aud": ["hcm-api"],
  "iat": 1786000000,
  "exp": 1786000240
}
```

`tenant_id` is the alias of the Organization the client asked for, which identity-control
keeps as the Tenant's identifier (§Tenant Context). Exactly one Tenant context appears, as
STD-IAM-001 §3.3 requires. The Membership set is never placed in a token,
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

### Authentication Levels

`ADR-IAM-004` names two levels, `aal1` and `aal2`, and this realm is where a person reaches them.
Keycloak maps an `acr` value to a numeric Level of Authentication (LoA). Its *Conditional - Level Of
Authentication* step lets a browser flow authenticate a person to the level a request asks for
[R1].

**The map.** The realm attribute `acr.loa.map` is `{"aal1":1,"aal2":2}`. It is set at realm level,
as Keycloak advises: "a best practice is to stick to realm mappings" [R1]. `phr` is reserved by the
ADR and is left out of the map until a flow can satisfy it, because asking for a level no flow
reaches is a failed sign-in.

**The flow.** The browser binding is a flow of this realm's own, `scnehaux-browser-v3`. It follows
the step-up flow Keycloak documents [R1]. The second factor is offered as WebAuthn or TOTP, as
Keycloak documents for a second factor [R3], and a recovery code is offered beside them
(`ADR-IAM-005 §5.2`) [R7]:

```text
scnehaux-browser-v3
├─ Cookie                                     ALTERNATIVE
└─ forms                                      ALTERNATIVE
   ├─ level 1                                 CONDITIONAL
   │  ├─ Condition - Level Of Authentication  REQUIRED   LoA 1, max age 36000 s (the SSO session maximum)
   │  └─ Username Password Form               REQUIRED
   └─ level 2                                 CONDITIONAL
      ├─ Condition - Level Of Authentication  REQUIRED   LoA 2, max age 300 s
      └─ second factor                        REQUIRED
         ├─ WebAuthn Authenticator            ALTERNATIVE
         ├─ one-time code                     ALTERNATIVE
         │  └─ OTP Form                       REQUIRED
         └─ Recovery Authentication Code Form ALTERNATIVE
```

v3 adds the last step to v2, which stays declared and unbound, as v1 does.

- **WebAuthn or TOTP at level 2.** Either is a second factor beside the password, and the pair meets
  AAL2 [R2]. `ADR-IAM-004` §5.1 names both.
- **The OTP Form sits in a sub-flow of its own, required there.** Its first version, v1, made WebAuthn
  and TOTP plain alternatives. The pinned kernel then refused the sign-in of a person who held
  neither ("Invalid username or password", compat run on identity-kernel#37); it did not offer to
  enroll one. v1 therefore required TOTP alone. In v2 the alternative is the sub-flow, and inside it
  the OTP Form is required. A person with neither factor is taken to TOTP enrollment, as under v1
  (`ADR-IAM-004 §5.4`). The compat suite proves this on the pinned image.
- **WebAuthn is enrolled, never required.** No sign-in asks a person to register a key. An
  application asks for registration with `kc_action=webauthn-register` after an `aal2` sign-in [R4].
  The *Webauthn Register* required action is enabled in a new realm, and the compat suite proves it
  answers on this one. Registration therefore follows a proof of a factor the person already holds,
  as `ADR-IAM-004 §5.5` asks of binding an additional authenticator (NIST SP 800-63B-4 §4.1.2.1).
- **A person holding both** is shown one by default. Keycloak documents: "If a user has configured
  both credential types, the credential with the highest priority will be displayed by default.
  However, the *Try Another Way* option will appear" [R3]. On the pinned image, a person who enrolled
  TOTP first and then a key was shown the TOTP page.
- **A recovery code is recovery, at level 2 (1.12.0).**
  - The kernel generates 12 one-time codes and asks for them in order. A used code is removed, and
    the next one is asked for at the next sign-in [R7].
  - Password plus one code is the recovery `ADR-IAM-005 §5.2` decides.
  - A person with TOTP and codes is shown the TOTP page. They reach the code through *Try Another
    Way*, then the selection page. The compat suite proves this path, and that the next sign-in asks
    for the next code.
- **Codes are issued with the first TOTP (1.12.0).** The *Configure OTP* action asks for recovery
  codes as it completes, by its option `add-recovery-codes` [R8]. It does so only where a flow of the
  realm uses recovery codes and their own action, *Recovery Authentication Codes*, is enabled [R8].
  The realm declares both:
  - A person enrolled through their first `aal2` sign-in leaves it with a TOTP and 12 codes.
  - A later TOTP, set up by the application-initiated action, asks for no codes when the person
    already holds them [R8].
- **The WebAuthn policy is the realm's default.** The relying party ID is the kernel's host name, and
  no attestation is required. Requiring attestation would restrict which authenticators a person may
  use, and no requirement asks for that.

- **Level 2's max age is 300 seconds.** That equals the Identity Control Service's
  `IDENTITY_STEP_UP_MAX_AGE`. Within it, a second request for `aal2` reuses the second factor; after
  it, the person proves it again. Level 1 keeps the session's own maximum, so a password is asked
  once per session, as Keycloak's example does.
- **A person with no second factor** who is asked for `aal2` enrolls a TOTP authenticator in that
  sign-in, on the kernel's own page (`ADR-IAM-004 §5.4`). The compat suite proves that the pinned
  kernel does this, and does not refuse the sign-in.
- **Not carried over from the built-in flow.** The *Identity Provider Redirector* is left out, because
  the realm federates no identity provider. A flow that declares one comes with the first identity
  provider.
- **The OTP policy is the realm's default:** TOTP, six digits, 30 seconds, `HmacSHA1`. That is what the
  authenticator apps people already hold accept. NIST SP 800-63B-4 places a single-factor OTP device,
  as the second factor, at AAL2 [R2].

**How realm-apply manages a flow.** A flow is declared in `realm/authentication-flows.json` by
alias, and is never edited in place.
- **Changing a flow** declares a new alias: `-v2` follows `-v1`. realm-apply builds the new flow
  completely, then binds it as the browser flow in one realm update, so no sign-in ever runs through
  a half-built flow. Keycloak edits a flow one execution at a time, and editing the bound flow would
  expose every intermediate state to the people signing in.
- **The previous flow stays, unbound.** The apply deletes nothing (§Configuration as Code), and a
  bound-flow rollback is a rebind.
- **A build that stopped part way** leaves a declared flow that is unbound and differs from its
  declaration. That flow is the one exception to deleting nothing: nobody signs in through it, so the
  next apply deletes it and builds it again whole. A bound flow is never replaced.
- **Drift.** The drift check compares the bound flow's executions, requirements, order and condition
  configurations with its declaration. Any difference was made by hand, and the apply is refused.
- **Required actions (1.12.0).** `realm/required-actions.json` declares the fields this realm governs
  on the kernel's required actions, by alias: whether each is enabled, and its configuration.
  - Keycloak registers its built-in required actions with every realm. realm-apply therefore never
    creates one: it lays the declared fields over the live action and writes it back whole, as
    Keycloak's update replaces every field it is sent [R5].
  - The configuration lives on the action itself, the field `config` [R5].
  - Priority and the default-action switch are not governed, because neither changes what a person
    proves. A declared field changed by hand is drift.
  - The realm declares `CONFIGURE_TOTP`, with `add-recovery-codes`, and
    `CONFIGURE_RECOVERY_AUTHN_CODES` and `webauthn-register`, both enabled.
- **Order is set, never left to the database.** A step's position in a flow is its priority.
  realm-apply adds each step with its position as its priority, and sets the requirement with the
  priority it reads back. Keycloak's execution update copies the priority it is sent onto the step
  [R5]. An update without one resets the step to 0, which leaves the order of equal steps to the
  database. On Postgres, the upgrade job listed v2's level sub-flows with their two steps swapped.

### Guessing Limits

`ADR-IAM-005 §5.6` enables Keycloak's brute-force detection. It is disabled by default, and it
applies "only to password, OTP and recovery codes" [R9]. The mode is *Lockout permanently after
temporary lockout* [R9]:

| Setting | Value | Why |
| :-- | :-- | :-- |
| `bruteForceProtected`, `permanentLockout` | `true`, `true` | The mixed mode |
| `failureFactor` | 10 | The first temporary lockout comes at the 10th consecutive failure |
| `maxTemporaryLockouts` | 90 | The permanent lockout comes at the 100th, NIST's upper bound (NIST SP 800-63B-4 §3.2.2) |
| `bruteForceStrategy` | `MULTIPLE` | The wait grows by `waitIncrementSeconds` every `failureFactor` failures |
| `waitIncrementSeconds`, `maxFailureWaitSeconds` | 60, 900 | One minute, rising to nine; 900 s caps it at Keycloak's default |
| `maxDeltaTimeSeconds` | 31536000 | A count resets on a success, or after a year with no failure |
| `quickLoginCheckMilliSeconds`, `minimumQuickLoginWaitSeconds` | 1000, 60 | Keycloak's defaults, declared |

**How the count reaches 100.** Keycloak's code decides when each lockout comes [R10]. With
`MULTIPLE`, the wait after a failure is `waitIncrementSeconds × (failures ÷ failureFactor)`, and
every failure with a wait above zero counts one temporary lockout. The permanent lockout comes once
the count exceeds `maxTemporaryLockouts`. So it comes at failure `failureFactor + maxTemporaryLockouts`,
which is 100 here.
- An attacker who keeps guessing waits about 7.5 hours in all before the 100th failure.
- A failure during a temporary lockout is not counted [R9].
- `internal/realmdef` asserts the arithmetic.

**Why the reset is a year.** NIST counts consecutive failures, which only a success ends (§3.2.2).
Keycloak also resets the count after *Failure Reset Time* with no failure. Its default, 12 hours,
would let a patient attacker make 99 guesses every 12 hours. A year makes that pause impractical.

**A permanent lockout disables the user.** Keycloak sets the user disabled and records the reason
[R10]. identity-control does not know of it, and the person is recovered by assisted recovery
(`ADR-IAM-005 §5.5`):
- suspend, which finds the user already disabled;
- revoke the lost factors, if any;
- restore, which enables the user.

The compat suite proves on the pinned image that enabling the user lets the right password in
again.

**Where the count lives.** Keycloak keeps login failures in its cache, not its database. A
restart of every Keycloak node clears them. A single-node development server therefore forgets its
counts when it restarts. A cluster keeps them through a rolling restart only while another node holds
a copy. That is a limit of the bound, recorded rather than closed.

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
| `firstName`, `lastName` | optional; Keycloak's own validations kept | PAD-PLT-001 minimizes personal data by purpose and lists no name among a Principal's PII. identity-control's API accepts none. A required family name shuts out every person with a single name. Keycloak's default requires both, which interrupted every login of a Principal identity-control created |
| Audience client scopes | exactly one of internal, privileged, provider, workload, external | Applies the STD-IAM-002 claim allowlist |
| Signing algorithm | `PS256` | STD-IAM-002 §3.2.2 initial baseline |
| `acr.loa.map` | `{"aal1":1,"aal2":2}` | ADR-IAM-004 §5.1; realm-level, as Keycloak advises |
| Browser flow | `scnehaux-browser-v3` | Password at LoA 1, plus WebAuthn, TOTP or a recovery code at LoA 2 (§Authentication Levels) |
| Recovery codes | issued with the first TOTP (`add-recovery-codes`) | ADR-IAM-005 §5.3 |
| Brute-force detection | permanent lockout after 90 temporary ones, at the 100th failure | ADR-IAM-005 §5.6; §Guessing Limits |
| OTP policy | TOTP, 6 digits, 30 s, `HmacSHA1` | The realm default, accepted by common authenticator apps |
| Preview features | disabled | ADR-IAM-001 §5.8 requires a separate ADR to enable any |
| Organizations | enabled (`organizationsEnabled`); the `organization` scope maps `tenant_id` | ADR-IAM-006; §Tenant Context |
| Image | pinned by digest | SAD-001 §7.6 |

Signing keys are provisioned through approved protected custody. Per-process or
per-replica production key generation is prohibited, including as a fallback when
custody is unreachable, and one `kid` maps to exactly one immutable key pair for its
entire lifecycle. Both rules come from STD-IAM-001 §3.5 and are asserted by the
compatibility suite rather than left to operational discipline.

## Testing Strategy

### Realm Contract

- A created Principal carries `scnehaux_principal_id` in its Keycloak representation.
- A Principal with no name logs in without the kernel interrupting the flow to collect one, and
  the name attributes keep Keycloak's validations.
- A human internal access token carries `principal_id` and `subject_type=human`.
- A provider token, obtained by Authorization Code with PKCE, carries `principal_id`,
  `subject_type`, `acr`, and the `auth_time` of the login, and no `provider_scope`, `tenant_id`,
  version claim, or `workload_owner`.
- A tenant-scoped privileged token (1.14.0), obtained the same way by a client holding
  `scnehaux-privileged` and the optional `organization` scope, carries `principal_id`,
  `subject_type`, `acr`, `auth_time` and the `tenant_id` asked for, and no `provider_scope`. The
  same client's sign-in asking for no Tenant gets no `tenant_id` (`compat/privileged_test.go`).
- **The per-sign-in form (1.16.0, `ADR-IAM-008`):** one client holding `scnehaux-provider`,
  `scnehaux-privileged` and `organization`, all optional, gets each form from the request alone.
  `compat/per_sign_in_test.go` asserts three sign-ins:
  - `scnehaux-privileged organization:<tenant_id>` carries that `tenant_id` in the access token and
    the ID token, where the client checks it.
  - `scnehaux-provider` carries no `tenant_id` in either.
  - A sign-in naming neither form carries no `principal_id`.
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
- **Tenant context (1.13.0):** `compat/organizations_test.go` asserts the following.
  - On the declared realm, an internal client given the `organization` scope gets a flat
    `tenant_id` for an Organization the person belongs to. A client without the scope gets none.
  - On a throwaway realm, the behaviour `ADR-IAM-006` relies on:
    - the Tenant is chosen per sign-in and kept by a refresh, which drops it rather than switching;
    - `invalid_grant` after removal or disabling, with other Tenants unaffected;
    - a workload's token.

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

### Authentication Levels

`compat/levels_test.go`, against the pinned image:
- A password sign-in that asks for nothing more carries `acr` `aal1`.
- A sign-in asking `acr_values=aal2`, by a person with no second factor, leads to TOTP enrollment.
  Once a valid code is given, the token carries `acr` `aal2`.
- Asked again within 300 seconds, `aal2` asks for no code. With `max_age=0` it asks for the password
  and the code again.
- A request for an unmapped `acr` is refused or reported, never silently answered with a higher level.
- `kc_action=webauthn-register`, after an `aal2` sign-in, registers a WebAuthn authenticator. With
  the person's TOTPs deleted, `aal2` asks for the password and the key, and the token carries `aal2`.
  A person with neither factor still enrolls a TOTP at their first `aal2` sign-in.
- Which page a person holding both factors is shown is recorded, not required.
- The suite answers the WebAuthn pages with a software authenticator. It holds a P-256 key, attests
  with `none`, and signs each assertion over the authenticator data and the client data's hash [R6].
- realm-apply refuses a hand-edited bound flow as drift, and building a new flow version leaves the
  previous one unbound.
- The upgrade job builds the flows on Postgres, where an order left to the database shows as drift.
- The first `aal2` sign-in enrolls a TOTP, then shows 12 recovery codes. A recovery code after the
  password, reached through *Try Another Way*, carries `aal2`, and the next sign-in asks for the next
  code.
- `compat/lockout_test.go`, on a throwaway realm in the same mode with small values:
  - a temporary lockout refuses even the right password;
  - the failure after the last temporary lockout disables the user;
  - enabling the user lets the right password in.
- realm-apply refuses a hand-edited required action as drift.

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
| Conforms to | STD-IAM-002 §3.1.1 — a resource holding provider grants or their projection checks its record; no `provider_scope` is issued |
| Consumed by | `TDD-identity-control-006` — provider authority from the projection of Organization's grants |
| Governed by | ADR-IAM-004 — authentication assurance levels `aal1`/`aal2` and step-up |
| Conforms to | STD-IAM-001 §3.1 2.2.0 — privileged access is multi-factor |
| Consumed by | `TDD-identity-control-005` §Step-Up — the levels its challenge asks for |

### Open Proof-of-Concept Questions

Run in this order. The first is the only one whose answer can force an extension or a
standard amendment.

1. **Protocol mapper coverage.** Which of access token, ID token, UserInfo, and
   introspection can carry each audience profile's required claim set through supported
   mappers. Any mandatory access-token claim uncovered is the escalation case.
   **Answered 2026-09-25: outcome 1, all four covered** — see §Claim Projection. Answered for
   the internal human profile first. The workload profile's access token is asserted by
   `compat/workload_test.go`: `principal_id`, `subject_type` and `workload_owner` from the
   service-account user, and no `acr`, `auth_time` or Tenant claim.
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

## References

| Ref | Source |
| :-- | :-- |
| R1 | Keycloak, *Server Administration Guide*, ACR to Level of Authentication (LoA) Mapping and Creating a browser login flow with step-up mechanism, <https://www.keycloak.org/docs/latest/server_admin/index.html>, accessed 2026-10-03: "The ACR can be any value, whereas the LoA must be numeric"; "a best practice is to stick to realm mappings"; the level-2 condition's Max Age "0" means the level "is valid just for the current authentication"; "if a user already has a session in Keycloak, that was logged in with username and password (LoA 1), the user is only asked for the second authentication factor". |
| R2 | NIST SP 800-63B-4, *Digital Identity Guidelines: Authentication and Authenticator Management*, August 2025, <https://pages.nist.gov/800-63-4/sp800-63b.html>, §2.2: "AAL2 provides high confidence … Proof of possession and control of two distinct authentication factors through the use of secure authentication protocols is required." |
| R3 | Keycloak 26.7.5, *Server Administration Guide*, W3C Web Authentication (WebAuthn), source `docs/documentation/server_admin/topics/authentication/webauthn.adoc` at tag 26.7.5, accessed 2026-10-03: "With this configuration, the users can choose between using WebAuthn and OTP for the second factor."; "If a user has configured both credential types, the credential with the highest priority will be displayed by default. However, the *Try Another Way* option will appear so that the user has the alternative methods to log in." |
| R4 | Keycloak 26.7.5, *Server Administration Guide*, Registering WebAuthn credentials using AIA, same source: "The actions *Webauthn Register* (`kc_action=webauthn-register`) and *Webauthn Register Passwordless* (`kc_action=webauthn-register-passwordless`) are available for the applications if enabled in the Required actions tab." |
| R5 | Keycloak 26.7.5, `services/src/main/java/org/keycloak/services/resources/admin/AuthenticationManagementResource.java`, `updateExecutions`: "if (model.getPriority() != rep.getPriority()) { model.setPriority(rep.getPriority()); updateExecution = true; }"; `addExecutionToFlow`: "int priority = data.containsKey("priority") ? (Integer) data.get("priority") : getNextPriority(parentFlow);" |
| R6 | W3C, *Web Authentication: An API for accessing Public Key Credentials, Level 2*, Recommendation, 8 April 2021, <https://www.w3.org/TR/webauthn-2/>: §6.1 Authenticator Data, §6.3.3 the authenticatorGetAssertion operation (the signature over the authenticator data concatenated with the client data hash), §8.7 None Attestation Statement Format. |
| R7 | Keycloak 26.7.5, *Server Administration Guide*, Recovery Codes, source `docs/documentation/server_admin/topics/authentication/recovery-codes.adoc` at tag 26.7.5, accessed 2026-10-04: "The Recovery Codes are a number of sequential one-time passwords (currently 12) auto-generated by {project_name}"; "When the current code is introduced by the user, it is removed and the next code will be required for the next login." |
| R8 | Keycloak 26.7.5, `services/src/main/java/org/keycloak/authentication/requiredactions/UpdateTotp.java`: `ADD_RECOVERY_CODES = "add-recovery-codes"`, described "If this option is enabled, the user will be required to configure recovery codes following the OTP configuration. If the user already has recovery codes configured, Keycloak will not ask for setting them up. As a prerequisite, enable the recovery codes required action and enable recovery codes in your authentication flow." |
| R9 | Keycloak 26.7.5, *Server Administration Guide*, Brute force attacks, source `docs/documentation/server_admin/topics/threat/brute-force.adoc` at tag 26.7.5: "{project_name} applies it only to password, OTP and recovery codes"; "Brute force detection is disabled by default"; *Lockout permanently after temporary lockout* "Locks user temporarily for specified number of times and then locks user permanently"; "`count` does not increment when a temporarily disabled account commits a login failure." |
| R10 | Keycloak 26.7.5, `services/src/main/java/org/keycloak/services/managers/DefaultBruteForceProtector.java`, `failure`: with `MULTIPLE`, "waitSeconds = realm.getWaitIncrementSeconds() * ((long) userLoginFailure.getNumFailures() / realm.getFailureFactor())"; a wait above zero calls "userLoginFailure.incrementTemporaryLockouts()"; "if(userLoginFailure.getNumTemporaryLockouts() > realm.getMaxTemporaryLockouts() ...) permanentUserLockOut(...)", which calls "user.setEnabled(false)". |
| R11 | Keycloak 26.7.5, `services/src/main/java/org/keycloak/protocol/oidc/OIDCLoginProtocolFactory.java`, realm creation: "ClientScopeModel organizationScope = newRealm.addClientScope(OAuth2Constants.ORGANIZATION); … organizationScope.addProtocolMapper(OrganizationMembershipMapper.create(ORGANIZATION, true, true, true)); newRealm.addDefaultClientScope(organizationScope, false);" |
| R12 | Keycloak 26.7.5 source. `OrganizationMembershipMapper.java`: a single-valued mapper returns "organizations.get(0).getAlias()". `TokenManager.java`, `validateSelectedOrganization`: "if (organization == null \|\| !organization.isEnabled() \|\| !organization.isMember(user)) { throw new ErrorResponseException(OAuthErrorException.INVALID_GRANT, "Invalid organization" …". |
| R13 | Keycloak 26.7.5, *Server Administration Guide*, Mapping organization claims, source `docs/documentation/server_admin/topics/organizations/mapping-organization-claims.adoc`: `organization:<alias>` "Maps to a specific organization with the given alias … If any of the aliases does not match an existing organization or the user is not a member, the request will be rejected." |
