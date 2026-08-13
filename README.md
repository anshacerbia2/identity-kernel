# Identity Kernel

Keycloak configuration, extensions, theme, and image build for the Scnehaux Identity
Runtime. This repository produces the identity kernel that authenticates every human
and workload in the estate.

It realizes part of **SAD-001 Scnehaux Identity Runtime** and the hosted-login portion
of **SAD-002 Scnehaux Identity Experience**. The Go control service that drives it
lives in `identity-control`.

## What this repository owns

- Realm configuration as code: topology, issuer, protocol mappers, declarative user
  profile, and the settings that close every unauthorized Principal creation path.
- The minimal event listener extension that surfaces user, admin, and security events.
- The hosted login, MFA, and recovery theme.
- The digest-pinned container image and its upgrade compatibility suite.
- Signing key custody, identity, and rotation.

## What it does not own

The enterprise identity model. Keycloak is a component of the Identity & Access
Platform, not its authority. It is not authoritative for Tenant, Membership,
Entitlement, Application ownership, or Product authorization, and its Organizations,
Groups, attributes, and roles are bounded local projections under ADR-IAM-001 §5.3.

It also does not mint the canonical `principal_id`. That belongs to `identity-control`,
and this repository's job is to store it immutably and project it into tokens.

## Why this is a separate repository

Release cadence. A Keycloak upgrade forces a rebuild and a full compatibility suite
across everything here. Holding the Go control service in the same repository would
make every kernel upgrade block an unrelated control-plane release.

ADR-IAM-001 §5.7 also requires each extension to declare its own source repository and
supported Keycloak range, which this satisfies structurally rather than by policy.

## Extension policy

The hierarchy is fixed by ADR-IAM-001 §5.7, cheapest first:

```text
1. standard configuration
2. supported Admin REST and protocol interfaces
3. themes and supported UI extension points
4. minimal event listener
5. restricted SPI — requires its own ADR
```

Every extension carries an owner, a supported Keycloak range, unit and integration
tests, an upgrade compatibility suite, defined failure and rollback behavior, and a
removal strategy. An extension without all seven does not ship.

Preview features are disabled. A preview feature in the authentication path is a
dependency on behavior the vendor has not committed to, in the one system where a
behavior change is a security event.

## Governance lineage

```text
PAD-PLT-001              Identity & Access Platform
    ↓
SAD-001                  Scnehaux Identity Runtime
    ↓
TDD-identity-kernel-*    Technical designs   (docs/designs)
    ↓
Realm configuration, extensions, theme, image
```

## Repository map

| Repository | Role |
| :-- | :-- |
| **`identity-kernel`** | **This repository** |
| `identity-control` | Identity Control Service, holds the Keycloak Admin credential |
| `organization-control` | Organization, Tenant, Workspace, Membership authority |
| `foundation-platform` | Shared Go substrate |
| `identity-experience` | Identity administration UI and its BFF |
| `organization-experience` | Organization administration UI and its BFF |

## Layout

| Path | Contents |
| :-- | :-- |
| `realm/` | Declarative realm configuration per environment |
| `extensions/event-listener/` | Minimal event listener, JVM |
| `themes/scnehaux/` | Hosted login, MFA, and recovery theme |
| `image/` | Container build, digest pinning, extension packaging |
| `compat/` | Upgrade compatibility suite |
| `docs/designs/` | Technical Design Documents |

## Designs

| TDD | Subject | Status |
| :-- | :-- | :-- |
| `TDD-identity-kernel-001` | Realm topology, issuer identity, and token claim projection | approved |
| `TDD-identity-kernel-002` | Signing key custody, identity, and rotation | approved |

## The declared realm contract

Other repositories build against three properties published from here. Changing any of
them is a breaking change under the compatibility window in SAD-001 §11.

| Property | Consumer |
| :-- | :-- |
| Issuer form | Every protected resource, and every evidence record that retains `iss` |
| Claim presence per token surface | Every consumer performing local verification |
| The four closed creation paths | `identity-control`, whose reconciler treats a violation as evidence of regression |

## Configuration as code

No realm configuration is authored through the Admin Console above local development.
The pipeline renders the definition, diffs it against the live realm through the
supported Admin API, and fails the deployment when the live realm carries changes the
definition does not.

That diff is what detects unmanaged console drift. ADR-IAM-001 §5.7 prohibits it, and
SAD-001 §9.4 requires it to be caught before an upgrade rather than discovered during
one.
