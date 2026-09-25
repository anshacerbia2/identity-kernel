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
| `cmd/realm-apply/` | Plans and applies `realm/` against a live Keycloak; detects console drift |
| `internal/` | The Admin API client and the plan/apply logic behind it |
| `deploy/dev/` | A long-lived development server: pinned Keycloak on Postgres behind Caddy, administration allowlisted |
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

### Applying the realm: `cmd/realm-apply`

CI applies the realm with this tool, and a server is applied with the same tool.
Credentials come from the environment, never from a flag:

- **Service account:** `KEYCLOAK_ADMIN_CLIENT_ID` and `KEYCLOAK_ADMIN_CLIENT_SECRET`, for
  a master-realm service account. Use this on a long-lived server.
- **Bootstrap administrator:** `KEYCLOAK_ADMIN_USER` and `KEYCLOAK_ADMIN_PASSWORD`.

```sh
# plan: read-only, prints what applying would change
go run ./cmd/realm-apply -environment development -url https://identity.dev.example

# apply, from a committed tree
go run ./cmd/realm-apply -environment development -url https://identity.dev.example -apply
```

**How drift is told apart from a definition change.** Each apply records its git revision
and a digest of the definition in the realm's attributes. The next run reads the
definition at that revision with `git show` and compares it with the live realm:

- **A difference between the two** was made outside the tool. The run refuses with exit
  code 2.
- **A difference between the live realm and the current definition** is what the new
  commit changed. The run applies it.

To resolve drift, revert it in Keycloak, or commit it to `realm/` and apply with `-adopt`.
`-apply` refuses an uncommitted tree, because the revision it would record could not
reproduce what it applied.

| Rule | Why |
| :-- | :-- |
| Only `local`, `ci`, and `development` are accepted | `signing-key.generated.json` has Keycloak generate the signing key in-process, which TDD-identity-kernel-002 prohibits wherever real tokens are served. It is 3072-bit because `foundation-platform`'s verifier silently discards smaller keys |
| A client scope's mapper set is closed | A mapper added by hand is how `principal_id` would reach an audience it is kept from, so an undeclared mapper is drift, and applying removes it |
| Nothing else is deleted | Removing a user-profile attribute makes Keycloak discard its values from every user on their next write. Removing a client scope strips its claims from every client using it. Both are migrations, not configuration changes |
| The drift check reaches only what `realm/` declares | A console change to an undeclared field is not seen. Declaring a field is what guards it |
| After applying, the tool re-plans before recording | A value Keycloak normalises or drops on write fails the apply, instead of reading as drift on the next run |

Exit codes:

| Code | Meaning |
| :-- | :-- |
| 0 | Success |
| 1 | Error |
| 2 | Refused: drift, or a realm this tool never applied |
| 3 | Changes are pending, reported under `-require-in-sync` |
