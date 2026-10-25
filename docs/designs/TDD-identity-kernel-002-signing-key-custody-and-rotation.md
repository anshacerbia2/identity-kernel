---
doc_meta:
  id: TDD-identity-kernel-002
  title: Signing Key Custody, Identity, and Rotation
  owner: Identity Platform Team
  version: 1.5.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-10-25
  parent_sad: SAD-001
---

# Signing Key Custody, Identity, and Rotation

## Purpose

Specify where realm signing keys come from, how a key identifier is derived so it can
never be bound to different material, how rotation preserves verification of tokens
already issued, and what the runtime does when protected custody is unreachable.

STD-IAM-001 §3.5 states four rules that are easy to write and easy to violate in
operation:

> One `kid` MUST map to exactly one immutable key pair for its entire lifecycle; a
> `kid` MUST NOT be reused, regenerated, or bound to different key material by any
> replica, restart, environment, or recovery procedure.
>
> Signing key material MUST be identical across every replica of an issuer;
> per-process or per-replica production key generation is prohibited, including as a
> fallback when protected custody is unreachable.

The previous implementation violated both. Replicas generated their own keys at
startup, so a token signed by one replica failed verification against another, and a
restart silently rebound an existing `kid` to new material. This design removes the
possibility rather than prohibiting the behavior.

## Scope

**In scope**

- Key generation, custody, and distribution to the Keycloak cluster.
- Derivation of `kid` and the property that makes reuse impossible.
- The rotation state machine and the retirement window that preserves verification.
- Startup behavior when custody is unreachable.
- Separation of duties for key operations, and recovery rehearsal.

**Out of scope**

- Approval of additional algorithms or an `RS256` external compatibility exception,
  owned by STD-IAM-002 and client registration.
- Token lifetime classes, owned by STD-IAM-002.
- Database, backup, and TLS certificate custody, which follow the enterprise secret
  and certificate lifecycle.
- Federation keys, which use the same custody mechanism but a different lifecycle.
- Client keys. A registered confidential or workload client authenticates with its own key
  pair (`private_key_jwt`, `ADR-IAM-001 §5.12`). The client keeps the private key, and the
  kernel holds only the public keys, as client attributes that `identity-control` registers
  (`TDD-identity-control-003` §Client Key Rotation). Nothing here takes custody of them.

## Technical Context

Keycloak signs tokens with realm keys held in its own realm configuration. It does not
call an external signing service per token, and this design does not introduce one:
a per-token network call on the issuance path would put a remote dependency on the
hottest path in the estate.

That shapes the requirement. What the enterprise mandates is custody, stability, and
continuity, not remote signing:

| Source | Requirement |
| :-- | :-- |
| EAD-005 §5.3 | Cryptographic custody uses a managed KMS/HSM and secret-management capability |
| EAD-006 §5.4 | Explicit key authority, managed production custody, unique and stable key identity, controlled lifecycle, separation of duties, no silent production fallback to ephemeral keys, tested continuity |
| STD-IAM-001 §3.5 | The four rules quoted above, plus published verification material for the maximum artifact lifetime with margin |
| SAD-001 §5.4 | Production keys provisioned through an approved secret or keystore custody mechanism; generated per-process production keys prohibited |

SAD-001 §5.4 says *keystore or* custody mechanism deliberately. A key pair generated
once, held in the approved secret manager, and delivered identically to every replica
satisfies every rule above without a signing service. That is the phase-one design,
and the migration path to KMS or HSM custody is specified rather than left implicit.

## Component Design

### Custody Model

```text
Key ceremony (out of band, two operators)
    → RSA key pair of at least 3072 bits generated once, offline
    → private material sealed into the approved secret manager
    → public material published to the realm and to JWKS
    → secret manager delivers the sealed keystore to every replica at startup
    → Keycloak signs locally with material identical across replicas
```

No replica generates key material. No environment shares key material with another.
The generation step happens once per key, under a ceremony with two operators, and
never inside an application process.

| Phase | Custody mechanism | Trigger to advance |
| :-- | :-- | :-- |
| Phase one | Sealed keystore in the approved cloud secret manager, mounted to the Keycloak cluster | — |
| Phase two | KMS or HSM custody with key material that never leaves the boundary | An audit obligation requiring non-exportable custody, or a regulatory or residency requirement |

Phase one is chosen because it satisfies every normative rule at negligible cost, and
because the property the rules protect — stability and identical material across
replicas — is a distribution property rather than a hardware property. Phase two is
recorded now so the migration is planned rather than discovered.

**Every environment is phase one today (1.2.0).** Keycloak 26.7.5 signs with a key pair it
holds, so the private key is in the kernel's memory while it signs, in production too, which
NIST SP 800-57 allows "provided that proper protection is afforded" (ADR-IAM-002 §5.3 [R6]).
Phase two needs a kernel integration the pinned release does not document, and is decided in its
own ADR (ADR-IAM-002 §8, Alternative F).

### Custody as Built (1.2.0)

Open Question 1 is answered by ADR-IAM-002 §5.3, amended 2026-10-20. The approved secret manager is
**AWS Secrets Manager, under a customer-managed AWS KMS key**, one key and one secret per
environment and realm. The secret holds the sealed keystore, and the kernel loads it as a file.

**One keystore per key (1.5.0, ADR-IAM-002 §5.5 Q3).** Each key is its own keystore, holding exactly one
RSA-3072 pair under the alias `realm-signing`, and its own password; in production, two secrets per key,
under the environment's one KMS key. Every name carries the key's `kid`. This is the vault-safe
spelling the ADR leaves to this design: `realm-signing-<kid>`. A `kid` is base64url, `[A-Za-z0-9_-]`,
so it needs no escaping in a file name, and Keycloak's file vault resolves `${vault.realm-signing-<kid>}`
to `scnehaux_realm-signing-<kid>` with every underscore doubled: "realm.replaceAll("_", "__") + "_" +
key.replaceAll("_", "__")" (`AbstractVaultProviderFactory`, `REALM_UNDERSCORE_KEY`) [R4]. The vault
reads the file on each use, with no cache (`FilesPlainTextVaultProvider.obtainSecretInternal`) [R4].

| Item, for key `<kid>` | In the kernel container | Development server | Production |
| :-- | :-- | :-- | :-- |
| Keystore, PKCS#12, one RSA-3072 pair, alias `realm-signing` | `/opt/keycloak/data/scnehaux/realm-signing-<kid>.p12`, read-only | `deploy/dev/keys/signing/realm-signing-<kid>.p12`, owned by the kernel's user (1000), mode 0400, in a directory of mode 0500 | the binary secret `…/realm-signing-<kid>-keystore`, mounted by the AWS Secrets and Configuration Provider (ASCP) |
| Its password | `/opt/keycloak/vault/scnehaux_realm-signing-<kid>` (underscores doubled), read-only | `deploy/dev/keys/vault/`, same owner and modes | the secret `…/realm-signing-<kid>-password`, mounted by the ASCP into the vault directory |
| Its certificate, the public half | not mounted | `deploy/dev/keys/realm-signing-<kid>.crt`, mode 0644, read by `realm-apply` and the rotation steps | kept with the ceremony record |
| Its provider | `realm-signing-<kid>`, from the template `realm/signing-key.json` | the same | the same |

- **The provider is `java-keystore`** (`realm/signing-key.json`). The Server Administration Guide:
  "The keystore should be located inside a folder named like the realm name inside the main keystores
  directory (by default data directory under Keycloak's installation folder)" [R1]. Its type is
  PKCS12, one of "JKS, PKCS12 or BCFKS" [R1].
- **Both passwords are vault references,** `${vault.realm-signing-<kid>}` (1.5.0), never literal realm
  configuration. Each "can refer a value from an external vault" [R1]. The image is built with the
  file vault, a build option: "For enabling the file-based vault you need to build Keycloak first
  using the following build option" [R2]. The realm and the secret's name give the file's name,
  `scnehaux_realm-signing-<kid>` [R2]. One entry serves both fields: keytool sets "the key
  password ... to the same password as the keystore password" when none is given [R3], and the
  generator gives none. `realmdef` refuses a literal password, a provider other than
  `java-keystore`, and an algorithm other than `PS256`.
- **The `kid` is rendered at creation, from the certificate.** The pinned release gives a
  `java-keystore` provider created without a `kid` a random identifier
  (`JavaKeystoreKeyProviderFactory.validateConfiguration`, which puts `KeycloakModelUtils.generateId()`
  in the configuration) [R4]. That identifier is unrelated to the key, which §Key Identity forbids.
  So the provider is created from the keystore's certificate, with its RFC 7638 thumbprint: by
  `realm-apply -signing-certificates` for the first key, by the rotation's `stage` for each later one
  (1.5.0). Keycloak leaves `kid` out of every representation it
  returns, because it is not one of the provider's declared properties (`StripSecretsUtils`), and an
  update skips it for the same reason (`RepresentationToModel.updateComponent`) [R4]. So the `kid` is
  never part of the definition or its comparison, and no update can rebind it.
- **Every run checks the keys as they sign** (`realmdef.VerifySigningKey`; the invariants of 1.5.0,
  §Rotation as Built). Each signing provider serves exactly one RSA `PS256` key of at least 3072 bits,
  with a `kid` equal to its own thumbprint and to its provider's name, and, with the certificates given,
  one in custody. Exactly one is active, and it is the realm's active `PS256` key. No other `PS256` key
  may exist, and no other key may be published (§The Published Key Set). An apply that fails the check records nothing.
  This is §Startup's thumbprint assertion, made against the live realm.
- **Keycloak would otherwise fall back silently.** When no active `PS256` key loads, the next token
  makes the pinned release create a `fallback-PS256` provider, a key it generates in-process and
  stores in its database (`DefaultKeyManager.getActiveKey`) [R4]. STD-IAM-001 §3.5 prohibits exactly
  that. The start check below keeps a kernel without custody from starting, and `VerifySigningKey`
  refuses a realm that holds a fallback key.
- **The keystore is never copied to a backup** (STD-GLB-009 1.10.0 rule 9). NIST SP 800-57 gives the
  backup of a private signature key as "No (in general); support for non-repudiation would be in
  question" (ADR-IAM-002 [R6]). `deploy/dev/backup.sh` reads the database alone, which holds the
  provider's configuration and no private material, and the restore drill proves it
  (§Testing Strategy). A lost keystore is replaced by a new ceremony and a new `kid`, never restored.
- **Production delivery is documented, not deployed.** [`docs/production/realm-signing-secret-provider-class.yaml`](../production/realm-signing-secret-provider-class.yaml)
  holds the two `SecretProviderClass` objects the kernel's pods mount. AWS: "To determine which
  secrets the ASCP mounts in Amazon EKS as files on the filesystem, you create a SecretProviderClass
  YAML file" [R5]. The keystore is a binary secret, which the ASCP writes as its bytes: the provider
  takes "either secret string or secret binary" [R6]. A secret value is at most 65,536 bytes
  (`--secret-binary`, "max 65536") [R7]; the keystore is about 3.5 KB. No CI job calls AWS. The
  artifact is reviewed with this design, and deployed when a production environment exists
  (STD-GLB-009 rule 12 keeps `deploy/` to environments that exist).

### The Published Key Set (1.2.0)

ADR-IAM-002 §5.1 item 2: "the enterprise JWKS advertises `PS256` keys only". The realm's JWKS therefore
holds the custody keys alone: the active one and, during a rotation, a staged or a retiring one
(§Rotation as Built, 1.5.0). Keycloak creates four other providers with every realm, and each is
decided by what depends on it:

| Provider | Key | In the JWKS when enabled | Decision | Why |
| :-- | :-- | :-- | :-- | :-- |
| `rsa-generated` | RS256, generated in-process | yes | **disabled** | No client signs RS256: the realm's default is PS256 and identity-control registers every client with `PS256` |
| `rsa-enc-generated` | RSA-OAEP, for content sent to the realm encrypted | yes | **disabled** | No client sends an encrypted request object or assertion, and the realm accepts no brokering or SAML |
| `hmac-generated-hs512` | HS512 secret | no, it has no public key | kept | The realm signs its internal tokens, refresh tokens among them, with it: `Constants.INTERNAL_SIGNATURE_ALGORITHM` is HS512 (ADR-IAM-002 [R12]) [R4] |
| `aes-generated` | AES secret | no | kept | The login's restart cookie is encrypted with it: `cekManagementAlgorithm(INTERNAL)` is `AES` (`RestartLoginCookie.encodeAndEncrypt`) [R4] |

- The JWKS publishes a key when "`k.getStatus().isEnabled() && k.getPublicKey() != null`"
  (`JWKSServerUtils.getRealmJwks`) [R4], so a disabled provider leaves it, and the two secret keys
  never enter it. `realm/key-providers.json` declares the two RSA providers disabled. A provider the
  definition declares is compared like every other object, so a console change that enables one again
  is drift. A provider deleted instead is equally out of the JWKS, so its absence is in sync.
- **A disabled RS256 provider is not the end of RS256.** The pinned release still asks for an active
  RS256 key in one place an anonymous request reaches: the legacy realm endpoint `GET
  /realms/{realm}`, which returns the realm's public key through `getActiveRsaKey`
  (`PublicRealmResource.getRealm`) [R4]. With no active RS256 key, that request makes Keycloak
  generate `fallback-RS256` in-process and publish it (`DefaultKeyManager.getActiveKey`). The SAML
  descriptor lists RS256 keys without asking for one, and every other caller needs a SAML client, the
  disabled Docker protocol, or an administrator. So:
  - the proxy closes the legacy endpoint on every listener, `(?i)^/+realms/+[^/]+/*$`, which Caddy runs
    "against the URI-decoded/unescaped path" [R9]. No client of the estate calls it: discovery,
    the key set and the token endpoint are all below it;
  - `VerifySigningKey` refuses any enabled key with a public key other than the keystore's, so a
    `fallback-RS256` made by a caller on the internal network fails the next `realm-apply` run;
  - `compat/signing_key_test.go` asks the pinned image what the legacy endpoint does with the RS256
    provider disabled, records it, and removes any fallback key it made.
  - **The production ingress carries the same rule, and it is a production gate (1.3.0).** ADR-IAM-002
    §5.4 (amended 2026-10-20) has every ingress that serves the realm answer `404` to `GET
    /realms/{realm}`, its root path and nothing below it, and STD-GLB-009 2.0.0 §Security & Access
    Governance makes it a gate: "Before the production realm serves anyone, a test against its public
    host requests the endpoint in each spelling and requires `404`, and requests discovery and the key
    set and requires `200`." A production ingress that is not Caddy "MUST match the same set of
    requests": without regard to case, with repeated or trailing slashes, matrix parameters or
    percent-encoding, on the decoded path. `deploy-dev` is that test for the development server, on
    every change: six spellings through the proxy and three on the tunnel's public port, then the key
    set holding the ceremony's `kid` alone. No production ingress exists yet. When one does, the same
    test runs against its public host before the realm serves anyone, and again after every Keycloak
    upgrade (ROADMAP §Gates).
- An external registration's RS256 exception (STD-IAM-002 §3.2.2) needs its own RS256 key from custody,
  loaded the way the PS256 key is. Until one exists, identity-control registers none, and a client
  configured for RS256 would make Keycloak generate `fallback-RS256`, which the checks above refuse.

### Startup as Built (1.2.0)

`image/start.sh` is the image's entrypoint. Before a `start` or `start-dev`, it checks every keystore in
the realm's keystore directory (1.5.0): each is named `realm-signing-<kid>.p12`, its password is mounted
and readable, it opens with that password, it holds exactly one entry, and that entry is
`realm-signing` (`keytool -list`). A keystore with a second entry is refused (ADR-IAM-002 §5.5 Q3), and so
is a directory with none. `check-keystores` runs the same checks and exits, which a rotation step uses
on a new keystore before it creates its provider. On any failure it prints why, names the
custody-outage runbook, and exits 1. Keycloak never runs, so it can never reach the fallback above.
Any other command, such as `kc.sh show-config`, runs unchecked.

- **What it cannot see:** a keystore that opens, but that the realm's provider does not name. That
  is what `VerifySigningKey` checks on every `realm-apply` run.
- **Development server:** `deploy/dev/compose.yaml` mounts `keys/signing` and `keys/vault`
  read-only. Without them the kernel restarts, refusing each time, and `docker compose logs keycloak`
  says why.
- **Production:** the ASCP mounts both. The Secrets Store CSI Driver's troubleshooting guide starts
  from the case where "the pod fails to start because of the inline volume mount", with a
  `FailedMount` event [R8]. The entrypoint's check is the second line, for a mount that succeeded
  with the wrong content.
- **CI:** every `compat` job and every stack another repository's CI starts from this checkout makes
  a throwaway keystore with the ceremony's own generator. ADR-IAM-002 §5.3: "A throwaway kernel, such
  as a test run's, may sign with a key it generated itself". `deploy/dev/compose.ci.yaml` does it
  only when `./keys` holds none, so this repository's `deploy-dev`, which runs the ceremony first,
  signs with the ceremony's key.

### Key Ceremony (1.2.0)

The ceremony that generates a key follows STD-IAM-001 2.9.0 §3.10. The runbook,
[`docs/runbooks/signing-key-ceremony.md`](../runbooks/signing-key-ceremony.md), is its script, and
`scripts/signing-key-ceremony.sh` is the step that makes the key.

| Role | Who | What the run checks or records |
| :-- | :-- | :-- |
| Operator | a named member of the Identity Platform Team with the ceremony role | named in the record |
| Witness | a second named holder of the role | named in the record; the script refuses a witness equal to the operator, compared case-folded and trimmed |
| Reviewer | a named member of Security or the Architecture Authority, neither of the two | reviews the record afterwards, before the realm serves anyone else |

- The key is generated once, by the JDK that will read it: `keytool -genkeypair` in the pinned
  upstream image, as root, with `--network none` (`scripts/signing-keystore.sh`).
- Every key is made this way (1.5.0): the realm's first, and each one a rotation stages. The generator
  writes into `keys/new`, and `signing-key place` (`cmd/signing-key`, in the realm-apply image, as root,
  with no network) computes the `kid` and moves the three files to `realm-signing-<kid>`
  (`scripts/signing-key-generate.sh`). It refuses to replace any file, so a `kid` is placed once. The
  record is `realm-signing-<kid>.ceremony.json`. The key signs nothing until a step puts it in the realm:
  `realm-apply` activates the first on an empty realm, and a rotation stages each later one
  (§Rotation as Built).
- It reads the `kid` from the new certificate, the RFC 7638 thumbprint of the public key (§Key
  Identity), with `signing-key place` (1.5.0; `client-key kid` before it). The command ships in the
  realm-apply image, which the ceremony builds and then runs with `--network none`. The provider is
  later created with the same value.
- It writes the record, `realm-signing-<kid>.ceremony.json`: operator, witness, reason, times, the
  generator's digest and the `kid`. It holds no secret. The operator attaches it to the change ticket
  the reason names (STD-IAM-001 §3.10: "kept with the change ticket ... Never in chat"). Names are
  given in the run, on the server, never in this public repository.
- In production the operator then seals the keystore and its password into the environment's two
  secrets, under the environment's customer-managed KMS key, and destroys the working copy. The
  runbook gives the commands. They are not run by any CI job.

Who holds the ceremony role and who reviews are the owner's to name (STD-IAM-001 §3.10, `OWNER
DECISION REQUIRED`). They are named in identity-control's `docs/runbooks/bootstrap-ceremony.md`, the
one runbook section both ceremonies use.

### Key Identity

`kid` is the RFC 7638 JWK thumbprint of the public key.

That single choice converts the hardest rule in STD-IAM-001 §3.5 from a policy into a
property. A thumbprint is a deterministic hash of the public key parameters, so
different material cannot yield the same `kid`, and the same material always yields
the same one. Reuse is not prohibited; it is unrepresentable.

The alternatives fail differently. A sequential identifier can be reissued by a
restart against new material. A human-assigned name can be copied into a new
environment with new material. A random identifier can collide with a stale
configuration. None of them makes the invariant self-enforcing.

A consequence worth stating: `kid` cannot be chosen, so it cannot encode a rotation
date or an environment name. That information belongs in the key registry below, not
in the identifier.

### Key Registry

The registry is operational metadata. It is not authority over the key material, and
losing it does not lose a key.

**Where it lives (1.5.0, ADR-IAM-002 §5.5 Q5).** In identity-control's Control Database, as insert-only
transition rows, with `public_jwk`, the algorithm and `custody_ref` written once at staging
(`TDD-identity-control-001` §The Signing Key Registry). A key's state is its latest completed
transition, and the fields below are read from its rows: `staged_at` from its staging, each later time
from the transition that entered the state. The keys directory keeps only the ceremony's file.

```text
kid            thumbprint, derived not assigned
algorithm      PS256 for the initial enterprise baseline
state          staged | active | retiring | retired | revoked
staged_at      when it was sealed and published to JWKS
activated_at   when it began signing
retiring_at    when it stopped signing and continued verifying
retired_at     when it left JWKS and its private material was destroyed
revoked_at     when a compromise removed it, and its private material was destroyed
custody_ref    reference into the secret manager, never the material
public_jwk     the public key, kept as evidence after retirement
```

## Data Model

### Rotation State Machine

```text
        generate and publish      activate           demote              retire
  ()  ──────────────────►  staged  ────────►  active  ────────►  retiring  ────────►  retired
                                                │
                                                └── compromise ──►  revoked
```

The states are ADR-IAM-002 §5.2's, each mapped to the state NIST SP 800-57 Part 1 defines:

| State | NIST SP 800-57 state | Signs | Published in JWKS | Private material | Meaning |
| :-- | :-- | :-- | :-- | :-- | :-- |
| `staged` | Pre-activation | No | Yes | In custody | Generated, sealed and published, so every consumer holds it before it signs |
| `active` | Active | Yes | Yes | In custody | The current signing key; exactly one per algorithm per realm |
| `retiring` | Deactivated | No | Yes | In custody | Stopped signing, still verifies tokens issued before rotation |
| `retired` | Destroyed | No | No | Destroyed | No outstanding artifact can still be in flight |
| `revoked` | Compromised | No | No | Destroyed | Compromise response; removed from JWKS immediately |

**Private material is destroyed when the key leaves JWKS, and is never archived**
(ADR-IAM-002 §5.2). A private signature key has no use after its signing period, and a
copy kept for a retention period is a copy that can still sign. Leaving JWKS and
destruction are one operation, so no state holds a private key that verifies nothing. The
kernel publishes a key only from the key pair it holds, which is why the private material
stays in custody through `retiring`. What is kept is the public key and the registry
record, as evidence of which key signed which tokens. Version 1.0 of this design had a
sixth state, `purged`, reached after an evidence retention period; it is gone, with the
retention period it waited for.

Exactly one key per algorithm is `active` in a realm at any moment. Two active keys
would make which key signed a given token a matter of chance, which removes the
ability to reason about a compromise.

### Retirement Window

The window during which a retiring key stays in JWKS is derived, not chosen:

```text
minimum_retirement  =  longest access token lifetime
                     + consumer JWKS cache lifetime
                     + clock skew allowance
```

With the `L2` class at 15 minutes from STD-IAM-002 §3.3, a JWKS cache of 10 minutes,
and a 60-second skew allowance, the minimum is 26 minutes. The operational default is
**7 days**, which exceeds the minimum by a wide margin because the cost of a longer
window is a published public key and the cost of a shorter one is a verification
failure on a valid token.

Raising any token lifetime class raises this minimum. The rotation job recomputes it
from the live class configuration rather than reading a constant, so a lifetime change
cannot silently shorten the window below its own requirement.

### Rotation as Built (1.5.0)

1.4.0 built the pinned release's mechanism for each state and the retirement floor, and stopped the
steps on seven questions. ADR-IAM-002 §5.5, amended 2026-10-24, decides them, and 1.5.0 builds the
steps. Each is one command an operator runs, `scripts/signing-key-rotation.sh`, and the registry in
identity-control holds every approval and transition (`TDD-identity-control-001` §The Signing Key
Registry, called through its `identity-signing-key` command, the `signing-key` service on the development
server).

**The states on Keycloak 26.7.5.** A state is two flags of the key's `java-keystore` provider, plus the
provider's presence. The Server Administration Guide: "Keycloak has a single active key pair at a
time, but can have several passive keys as well. The active key pair is used to create new
signatures, while the passive key pair can be used to verify previous signatures" [R10]. The key set
publishes every enabled key with a public key (`JWKSServerUtils.getRealmJwks`) [R4].

| State | Provider `realm-signing-<kid>` | In the key set | Signs | Custody | Registry |
| :-- | :-- | :-- | :-- | :-- | :-- |
| `staged` | enabled, passive | yes | no | keystore and password | `stage` |
| `active` | enabled, active, the highest priority | yes | yes | keystore and password | `activate` |
| `retiring` | enabled, passive | yes | no | keystore and password | `demote`, with the next key's activation |
| `retired` | removed | no | no | destroyed | `retire`, or `abandon` for a staged key |
| `revoked` | removed | no | no | destroyed | `revoke` |

**Who owns the providers (Q4).** The steps alone. `realm-apply` never changes or removes a signing
provider that exists. On an empty realm it creates the first, active, from the one certificate in
custody (`-signing-certificates`), and refuses when there is more than one. Every run checks the
invariants (`realmdef.VerifySigningKey`): exactly one active `PS256` key, which is the realm's active
key; every key a signing provider serves is RSA `PS256` of at least 3072 bits, under its own RFC 7638
thumbprint, named by it, active or passive, and in custody; every signing provider serves its one key;
and no other `PS256` key and no other published key exists, so no `fallback-PS256` and no RS256 key.

**The steps.** Each reads the key's provider and its registry state first and refuses when they
disagree, as after a restore of either. Each asks the registry's `check` for its approval and records
the outcome with `record`; a step that fails part way records `failed` with its error, which changes no
state and leaves the approval unused.

| Step | Waits | Kernel side (`cmd/signing-key`) | Then |
| :-- | :-- | :-- | :-- |
| `stage <kid> <operator> <witness> <reason> <correlation>` | — | registers the key from its certificate (`jwk`), checks the keystores (`check-keystores`), creates the provider enabled and passive (`stage`), checks the invariants | the key is published and signs nothing |
| `approve <kid> <transition> <operator> <approver> …` | — | — | an approval row, `--emergency` for an activation after a compromise |
| `activate <kid> <operator>` | the cache window since staging, unless the approval is an emergency (Q7) | makes the key active above every other key's priority, then demotes every other active key, then checks that it is the one active key | the registry writes the activation and the previous key's demotion in one transaction |
| `retire <kid> <operator>` | the retirement window since it became `retiring` | removes the provider (Q8 step 1), then destroys the keystore, password and certificate and reads them back absent | the registry records `retired` with that evidence, and not before (Q8 step 5) |
| `abandon <kid> <operator>` | — | the same, for a staged key | `retired`, reason `abandoned` (Q6) |
| `revoke <kid> <operator>` | — | the same, for a staged or retiring key | `revoked` |

- **No moment has no active key.** With none, the next token makes the pinned release generate
  `fallback-PS256` (§Custody as Built), so the new key is made active first, at a priority above every
  other: "The highest number makes the key pair active" [R10]. No step removes the active key: a
  compromised active key is demoted by a replacement's emergency activation, then revoked (Q7).
- **A retiring key is never active again** (Q6): the registry lets a key enter each state once.
- **The windows** are §Configuration's: 10 minutes of consumer cache before an activation, and the
  7-day retirement window, whose floor every run recomputes from the live token lifetimes
  (`realmdef.VerifyRetirementWindow`, below). The registry measures each from the time the key entered
  its state, on the database's clock. Only a throwaway environment, `local` or `ci`, may shorten them,
  through `SIGNING_KEY_CACHE_WINDOW` and `SIGNING_KEY_RETIREMENT_WINDOW`: ADR-IAM-002 §5.3 lets a test
  run's kernel sign with a key of its own, because "nothing outside that run verifies its tokens". Any
  other environment refuses either variable (`realmdef.StepWindows`).
- **The first key.** `realm-apply` activates it on the empty realm, before identity-control can run,
  because identity-control needs the realm (Q4). Once the Control Database exists, the operator stages it
  in the registry and records its activation under an approval; the step sees the provider already
  active and alone, so it changes nothing in the realm and does not wait.
- **Staging on the development server** needs no restart: the keys directories are bind-mounted, the
  `java-keystore` provider reads its keystore when a session uses it, and the vault reads the password on
  each use [R4]. In production a staged key's two secrets are added to the `SecretProviderClass` objects
  and the replicas rolled before `stage` runs, and removed and rolled before a destruction deletes them
  (Q3, Q8 step 2; `docs/production/`).
- **Destruction in production** is Q8's five steps, in order, after the approval and the registry's
  state check: remove the provider; remove the key's two objects and roll the replicas; delete both
  secrets with `ForceDeleteWithoutRecovery`; read each until Secrets Manager no longer returns it and
  take both `DeleteSecret` events from CloudTrail; record `retired_at` or `revoked_at` with those events
  as the evidence. `docs/runbooks/signing-key-rotation.md` gives the commands. No production
  environment exists, so they have never run, and no CI job calls AWS.

**The retirement floor is computed on every `realm-apply` run** (1.4.0, `realmdef.VerifyRetirementWindow`).
The longest access token lifetime is the largest of the realm's `accessTokenLifespan`, every
client's `access.token.lifespan` override, which identity-control sets from the client's lifetime
class (STD-IAM-002 §3.3), and, for a client with the implicit flow enabled, the realm's
`accessTokenLifespanForImplicitFlow`. The floor adds the 10-minute consumer cache and the 60-second
skew allowance (§Configuration). The run fails when the floor exceeds the 7-day window. The `retire`
step waits the window, and the `windows` command it reads it from computes the floor first.

**Proved.**

- `compat/rotation_steps_test.go`, in the `rotation` job of `compat.yml`, with identity-control built
  from `identity_ref` (its `main` by default; a branch by `workflow_dispatch`). Four keys made by the
  ceremony go through every state by the steps above. A staged key is published and signs nothing. An
  activation is refused without its approval and before the cache window, and an emergency one is not
  delayed. After an activation, new tokens carry the new `kid`, and a token the old key signed verifies
  against the key set while that key is retiring. A retirement is refused before its window, and the key
  stays published until it runs; then the key leaves the key set, a token it signed fails, and its files
  are gone. An abandoned key and a revoked key leave at once, and the active key cannot be revoked
  first. At every step the key set holds RSA `PS256` keys alone, and no step makes a fallback or an
  RS256 key. The registry ends with the states each step recorded, and `realm-apply -require-in-sync`
  passes after the rotation.
- `internal/realmdef/signingkey_test.go`: each invariant `VerifySigningKey` holds, the template's
  rendering, custody read from certificates named by their kids, and the windows only a throwaway
  environment may shorten.
- The registry's own refusals are identity-control's tests (`internal/signingkey`).

## API / Interface

This design publishes no runtime API. It fixes three contracts other systems build
against:

| Contract | Consumer |
| :-- | :-- |
| JWKS endpoint and its publication window | Every protected resource performing local verification |
| `kid` derivation rule | Any consumer pinning or caching keys by identifier |
| Rotation schedule and retirement window | Consumers sizing their JWKS cache |

A consumer MUST resolve an unknown `kid` by refetching JWKS with rate limiting, and
MUST reject the token when the `kid` remains unknown. Fetching signing material from a
source named inside the token is prohibited by STD-IAM-002 §3.5.

## Algorithms / Logic

### Startup

```text
on startup:
    resolve the sealed keystore from the approved secret manager
    if resolution fails:
        log the failure with the custody reference, never the material
        exit non-zero
    load the keystore
    assert every kid equals the thumbprint of its own public key
    if any assertion fails:
        exit non-zero
    serve
```

The failure branch is the design. STD-IAM-001 §3.5 prohibits per-process key
generation *including as a fallback when protected custody is unreachable*, so an
instance that cannot resolve its keys refuses to start. A replica that generated a
key here would sign tokens no other replica could verify, and would do it during the
exact incident when nobody is reading logs.

The thumbprint assertion at startup is cheap and catches a keystore assembled by hand
or copied between environments with a stale identifier.

### Rotation

```text
scheduled rotation:
    generate the next key pair under ceremony, seal it, register it staged,
        and publish its public material to JWKS
    wait for the consumer cache window so every consumer holds the new public key
    promote staged to active; demote the previous active to retiring
    hold the retiring key in JWKS for the computed retirement window
    retire it: remove it from JWKS and destroy its private material, in one operation
        destroy means removed from the keystore and from every stored version
        of the sealed keystore in the secret manager that carries it
    keep its public key and registry record as evidence
```

Publishing the public key while the key is `staged` is what makes rotation invisible to
consumers. A consumer whose cache has not refreshed when the new key begins signing
would see an unknown `kid` and reject valid tokens, which is a self-inflicted outage
during a routine operation.

### Compromise

```text
on suspected compromise:
    generate and stage a replacement, publish it, activate it
    move the compromised key directly to revoked: remove it from JWKS immediately and
        destroy its private material, every stored version included
    accept that every token signed by it fails verification from that moment
    treat the resulting failures as containment, not as an incident to suppress
    record actor, reason, correlation, and the affected issuance window
```

Compromise skips the retirement window deliberately. The window exists to protect
valid tokens, and after a compromise there is no longer a basis for treating tokens
signed by that key as valid.

### Separation of Duties

- Key generation requires two people, an operator and a witness who is never the operator
  (STD-IAM-001 §3.10); neither alone can complete a ceremony. As built (1.2.0),
  `scripts/signing-key-ceremony.sh` refuses a witness equal to the operator and records both, and
  a third person, the reviewer, reviews the record (§Key Ceremony). The registry refuses the same
  pair when the key is staged (1.5.0).
- The operator who generates a key does not approve its activation.
- Retiring or revoking a key, which destroys its private material, requires an approval
  distinct from the operator performing it.
- Every key operation is recorded with actor, reason, correlation identifier, and
  outcome, and is emitted as a privileged-administration event.

No individual can generate, activate, and destroy a key alone, which is what EAD-006
§5.4 requires for high-impact key operations.

**As built (1.5.0, ADR-IAM-002 §5.5 Q9).** Each approval is an insert-only registry row by a holder of the
ceremony role, for one transition of one `kid` and one operator. The registry refuses an approver
equal to the operator, and for an activation one who generated the key; an approval completes one
transition and is never reused. Each step asks the registry for its approval before it acts and records
its transition after, with actor, approval, reason, correlation identifier and outcome: that row is the
privileged-administration event, kept until Audit & Evidence has it (STD-IAM-001 §3.8). The kernel's
admin events and, in production, CloudTrail corroborate it by the correlation identifier. Who holds
the ceremony role stays the owner's to name (STD-IAM-001 §3.10).

## Configuration

| Setting | Value | Reason |
| :-- | :-- | :-- |
| Key source | AWS Secrets Manager, one customer-managed KMS key per environment and realm, two secrets per key, each written once, mounted by the ASCP; on the development server, `deploy/dev/keys/signing` and `deploy/dev/keys/vault` | Custody is external to the artifact (ADR-IAM-002 §5.3, §5.5 Q3, Q8) |
| Key provider | one per key: `java-keystore`, `realm-signing-<kid>`, PKCS#12 `realm-signing-<kid>.p12`, alias `realm-signing`, passwords `${vault.realm-signing-<kid>}` | §Custody as Built |
| Who owns the providers | the rotation steps; `realm-apply` creates the first on an empty realm and checks the invariants | ADR-IAM-002 §5.5 Q4 |
| Signing algorithm | `PS256` | STD-IAM-002 §3.2.2 baseline; candidate release must prove support |
| RSA modulus | at least 3072 bits | Algorithm profile minimum |
| Key generation in process | Prohibited, including as fallback | STD-IAM-001 §3.5 |
| `kid` | RFC 7638 thumbprint | Makes reuse unrepresentable |
| Active keys per algorithm per realm | Exactly one | A compromise must name one key |
| Rotation cadence | 30 days | Bounds the issuance window a single key covers |
| Retirement window | 7 days, floor computed from live token classes | Verification continuity |
| JWKS cache guidance to consumers | 10 minutes | Feeds the retirement floor |
| Startup on custody failure | Exit non-zero, from the image's entrypoint before Keycloak runs | No silent ephemeral fallback |

No key material appears in configuration, in an image, in a realm export, in source
control, in a log, or in an event.

## Testing Strategy

**As built (1.2.0).** `compat/signing_key_test.go` runs against a throwaway keystore made by the
ceremony's generator and asserts the first four lines of §Identity and Custody, that the published key
set holds the keystore's key and nothing else (§The Published Key Set), the absence of any other
`PS256` key, and that an access token and an ID token carry the keystore's `kid` and verify with
the certificate's key alone. The `contract` job also starts the image without a keystore and requires
the refusal. `deploy-dev` proves the server's path: the kernel refuses to start before the ceremony,
the ceremony refuses a witness equal to the operator and a second key, and after it the key set and a
token carry the `kid` the record names. Its restore drill (`scripts/dev-restore-drill.sh`) proves
§Compromise and Recovery's first restore line: the restored realm signs with the same `kid`, and the
backup holds neither the keystore, nor its password, nor a private key. Unit tests in
`internal/realmdef/signingkey_test.go` cover the `kid` derivation and each refusal of
`VerifySigningKey`. Not built: replica consistency, which needs more than one replica, and everything
under §Rotation and §Separation of Duties beyond the ceremony.

**As built (1.4.0).** The mechanism under each state, against a fixture key, and the retirement floor's
computation and its failure (`internal/realmdef/retirement_test.go`).

**As built (1.5.0).** `compat/rotation_steps_test.go` replaces 1.4.0's fixture test: it takes four keys
through all five states by the steps an operator runs, with identity-control's registry
(§Rotation as Built, Proved). Every line of §Rotation below now holds, the timings included, with the
windows a `ci` environment shortens; so do §Separation of Duties' first two lines, by the registry's
refusals, and §Compromise and Recovery's first. Not built: the privileged-administration event's
delivery to Audit & Evidence, which waits on that platform, and replica consistency.

### Identity and Custody

- Every `kid` in the served JWKS equals the RFC 7638 thumbprint of its own public key.
- The active enterprise key is RSA with a modulus of at least 3072 bits and advertises
  `alg=PS256`.
- Two independently generated key pairs never produce the same `kid`.
- The same key pair loaded twice produces the same `kid`.
- No key material appears in a realm export, a log line, a trace, or an event payload.

### Replica Consistency

- A token signed by one replica verifies against every other replica.
- Every replica issues the baseline token with JOSE `alg=PS256`; `RS256`, `none`, and
  symmetric signing are absent unless an external compatibility registration explicitly
  exercises its isolated `RS256` key.
- All replicas serve byte-identical JWKS.
- A replica started with an empty secret-manager response exits non-zero and signs
  nothing.
- A replica started with a keystore whose `kid` does not match its material exits
  non-zero.

### Rotation

- A token issued before rotation verifies throughout the retirement window.
- A staged key is in JWKS and signs nothing, and it is in JWKS before it begins signing by
  at least the consumer cache window.
- A retiring key leaves JWKS only after the computed window elapses.
- A retired key's private material is in neither the keystore nor any stored version of the
  sealed keystore, and its public key and record remain.
- Raising a token lifetime class raises the computed retirement floor, and a
  configuration that would shorten the window below its floor fails.

### Compromise and Recovery

- A revoked key is removed from JWKS immediately, its private material is destroyed, and
  tokens signed by it fail verification.
- Restoring the cluster from backup reproduces the same `kid` set and does not
  generate new material.
- A restore to a point before a rotation is detected, and the missing key is
  reinstated from custody rather than regenerated. A key retired since cannot be
  reinstated, because its private material is destroyed; the restore takes the current
  active key from custody instead, and the tokens the retired key signed have expired.

### Separation of Duties

- A ceremony completed by one operator is rejected.
- Activation approved by the generating operator is rejected.
- Every key operation emits a privileged-administration event carrying actor, reason,
  and correlation identifier.

## Security Notes

Private signing material never leaves protected custody except into the memory of a
Keycloak replica, and never reaches a product consumer or a browser. Public
verification material is published by design and carries no secret.

The thumbprint `kid` has a privacy property worth stating: it is derived from the
public key, which is already public, so publishing it discloses nothing beyond JWKS.

A key held in a secret manager is exportable by anyone holding the custody
credential. That is the accepted limitation of phase one, and the compensating
controls are narrow access to the custody reference, separation of duties on key
operations, and privileged-administration events on every access. Phase two removes
the limitation rather than mitigating it, which is why the trigger for phase two is
recorded rather than left to preference.

Refusing to start when custody is unreachable trades availability for correctness. It
is the correct trade here: an issuer that signs with material other replicas cannot
verify produces an outage that looks like intermittent authentication failure, which
is materially harder to diagnose than a process that refuses to start.

## Performance Notes

Signing happens locally in the replica with material already in memory, so token
issuance carries no network call for cryptography. Key resolution costs one secret
manager call per replica startup and one per rotation.

JWKS is served from memory and cached by consumers for the published window, so the
endpoint carries no per-request cost proportional to token issuance.

## Operational Notes

| Signal | Warning | Critical |
| :-- | :-- | :-- |
| Active key age | 25 days | 35 days |
| Retiring key past its computed window | any occurrence | — |
| JWKS content differing across replicas | — | any occurrence |
| Replica exiting on custody failure | any occurrence | 2 in an hour |
| Key operation without a recorded second operator | — | any occurrence |
| Retirement floor exceeding the configured window | — | any occurrence |

Runbooks required before production: key ceremony, scheduled rotation, emergency
rotation on compromise, custody outage at startup, restore-to-earlier-point key
reconciliation, and consumer reporting an unknown `kid`.

Rotation and recovery are rehearsed in staging before any production claim, because
EAD-005 §6.8 does not accept a backup as recovery evidence without a successful
restore, and the same reasoning applies to a key lifecycle that has never been
exercised.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-001 — Scnehaux Identity Runtime |
| Realizes capability | PAD-PLT-001 — Identity & Access Platform |
| Governed by | ADR-IAM-001 — Adopt Keycloak Identity Kernel |
| Governed by | ADR-IAM-002 §5.2 — the key states, mapped to NIST SP 800-57 Part 1; private material destroyed at retirement |
| Conforms to | STD-IAM-001 §3.5 — one `kid` to one immutable key pair; identical material across replicas; no ephemeral fallback |
| Conforms to | STD-IAM-002 §3.5 — verification material published for the maximum artifact lifetime with margin |
| Enterprise constraint | EAD-005 §5.3 — managed KMS/HSM and secret-management capability |
| Enterprise constraint | EAD-006 §5.4 — unique stable key identity, controlled lifecycle, separation of duties, tested continuity |
| Enterprise constraint | EAD-005 §6.8 — recovery is proven by exercise, not by existence |
| Consumed by | Every protected resource performing local verification |
| Related design | `TDD-identity-kernel-001` — realm topology, issuer identity, claim projection |
| Governed by | ADR-IAM-002 §5.3, amended 2026-10-20 — AWS Secrets Manager and KMS, `java-keystore` with vault passwords, no development backup |
| Conforms to | STD-IAM-001 2.9.0 §3.10 — the ceremony: operator, witness, independent review |
| Conforms to | STD-GLB-009 1.10.0 rule 9 — the keystore and its vault files are never copied |
| Governed by | ADR-IAM-002 §5.4, amended 2026-10-20 — every ingress that serves the realm closes the legacy realm endpoint (1.3.0) |
| Governed by | ADR-IAM-002 §5.5, amended 2026-10-24 — rotation decisions Q3 to Q9: a keystore and two secrets per key, steps that own the providers, the registry in identity-control, abandonment, emergency activation, one-version secrets deleted whole, approvals by someone other than the operator (1.5.0) |
| Conforms to | STD-GLB-009 2.0.0 §Security & Access Governance — the production gate on the legacy realm endpoint (1.3.0) |

### Open Questions

1. ~~Which approved secret manager holds the sealed keystore in each environment.~~ Answered
   by ADR-IAM-002 §5.3, amended 2026-10-20 (1.2.0): AWS Secrets Manager under a customer-managed
   AWS KMS key, one per environment and realm, delivered by the ASCP as a file the `java-keystore`
   provider loads, with both passwords from the file vault. The development server keeps the
   keystore in `deploy/dev/keys/signing` and never backs it up (§Custody as Built).
2. ~~Whether the evidence retention period for purged key material is set by security
   policy or by a regulatory obligation.~~ Answered by ADR-IAM-002 §5.2: private material
   has no retention period. It is destroyed when the key leaves JWKS, and the evidence kept
   is the public key and the record, which NIST SP 800-57 Part 1 permits.

Questions 3 to 9 were found building rotation (1.4.0). ADR-IAM-002 §5.5, amended 2026-10-24, answers
each, and 1.5.0 builds the answers (§Rotation as Built).

3. ~~Custody of more than one key.~~ One keystore per key, alias `realm-signing`, two secrets per key
   named by the `kid` (Q3). The spelling is `realm-signing-<kid>` (§Custody as Built).
4. ~~Who owns the signing providers' state.~~ The rotation steps. `realm-apply` checks the invariants and
   creates the first provider on an empty realm alone (Q4).
5. ~~Where the registry lives.~~ identity-control's Control Database, as insert-only transition rows, with
   `public_jwk` written once at staging (Q5, §Key Registry).
6. ~~Rollback.~~ A staged key may be abandoned, as `retired` with the reason `abandoned`, or `revoked`
   when suspect. A retiring key is never activated again (Q6).
7. ~~Activation after a compromise.~~ At once, then the compromised key is revoked (Q7).
8. ~~Destroying every stored version in production.~~ Each signing secret is written once and has one
   version. A destruction deletes the key's two secrets with `ForceDeleteWithoutRecovery`, in Q8's
   order, and records the CloudTrail events (Q8).
9. ~~The approval and the event.~~ An insert-only registry row by a holder of the ceremony role who is
   not the operator, which the step refuses to run without. The transition row is the event. The
   mechanism is a command on the Identity Control deployable (Q9).

## References

Accessed 2026-10-20. Each quote was read on the page or in the source file named.

| # | Source |
| :-- | :-- |
| R1 | Keycloak, *Server Administration Guide* 26.7.5, "Loading keys from a Java Keystore", <https://www.keycloak.org/docs/26.7.5/server_admin/index.html>: "The keystore should be located inside a folder named like the realm name inside the main keystores directory (by default data directory under Keycloak's installation folder)"; "Enter the Keystore Password. The option can refer a value from an external vault."; "Enter a value for Keystore Type (JKS, PKCS12 or BCFKS)."; "Enter the Key Password. The option can refer a value from an external vault." |
| R2 | Keycloak, *Using a vault*, <https://www.keycloak.org/server/vault>: "For enabling the file-based vault you need to build Keycloak first using the following build option"; the file is named `${vault.<realmname>_<secretname>}`, and "To process the secret correctly, you double all underscores in the <secretname>"; "The file-based vault implementation is especially useful for Kubernetes/OpenShift secrets." |
| R3 | Oracle, *The keytool Command*, JDK 21, <https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html>: for `-keypass`, "If you press the Return key at the prompt, then the key password is set to the same password as the keystore password"; "file: Retrieve the password from the file named argument"; "In JDK 9 and later, the default keystore implementation is PKCS12." |
| R4 | Keycloak 26.7.5 source, <https://github.com/keycloak/keycloak/tree/26.7.5>: `services/.../keys/JavaKeystoreKeyProviderFactory.java`, `validateConfiguration`: `if (kid == null) { kid = KeycloakModelUtils.generateId(); model.put(KID_KEY, kid); }`; `server-spi-private/.../models/utils/StripSecretsUtils.java`, `stripComponentConfigMap`, which removes every configuration key that is not a declared property; `RepresentationToModel.updateComponent`, which skips such a key (`if (!internal && !providerConfiguration.containsKey(k)) { continue; }`); `services/.../keys/DefaultKeyManager.java`, `getActiveKey`, which on no active key creates fallback keys and logs "No keys found for realm={0} and algorithm={1} for use={2}. Generating keys.", and `getActiveRsaKey`, `getActiveKey(realm, KeyUse.SIG, Algorithm.RS256)`; `services/.../resources/PublicRealmResource.java`, `rep.setPublicKeyPem(PemUtils.encodeKey(session.keys().getActiveRsaKey(realm).getPublicKey()))`; `services/.../protocol/oidc/utils/JWKSServerUtils.java`, `getRealmJwks`, `.filter(k -> k.getStatus().isEnabled() && k.getPublicKey() != null)`; `server-spi-private/.../models/Constants.java`, `INTERNAL_SIGNATURE_ALGORITHM = Algorithm.HS512`; `services/.../jose/jws/DefaultTokenManager.java`, `cekManagementAlgorithm`, `case INTERNAL: return Algorithm.AES`; `services/.../protocol/RestartLoginCookie.java`, `encodeAndEncrypt`, `getActiveKey(..., KeyUse.ENC, algAlgorithm)`. Read 2026-10-25 for 1.5.0: `services/.../vault/AbstractVaultProviderFactory.java`, `REALM_UNDERSCORE_KEY((realm, key) -> realm.replaceAll("_", "__") + "_" + key.replaceAll("_", "__"))`; `services/.../vault/FilesPlainTextVaultProvider.java`, `obtainSecretInternal`, which reads `Files.readAllBytes(secretPath)` on each call; `services/.../keys/JavaKeystoreKeyProvider.java`, whose constructor loads the keystore (`loadKey`) for each provider instance a session creates. |
| R5 | AWS, *Use AWS Secrets and Configuration Provider CSI with IAM Roles for Service Accounts (IRSA)*, <https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_csi_driver.html>: "To determine which secrets the ASCP mounts in Amazon EKS as files on the filesystem, you create a SecretProviderClass YAML file"; and *AWS Secrets and Configuration Provider code examples*, <https://docs.aws.amazon.com/secretsmanager/latest/userguide/ascp-examples.html>: `objectAlias`, "The file name of the secret in the Amazon EKS Pod"; `filePermission`, "If you don't specify this field it will default to "0644"". |
| R6 | AWS, `secrets-store-csi-driver-provider-aws`, `provider/secrets_manager_provider.go` at a8f9f58, <https://github.com/aws/secrets-store-csi-driver-provider-aws/blob/a8f9f58f9dc951766134cc60a04c00b2c1a67a6a/provider/secrets_manager_provider.go>: "// Use either secret string or secret binary.", then `sValue = rsp.SecretBinary` when the secret has no string. |
| R7 | AWS CLI, `secretsmanager create-secret`, <https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/create-secret.html>: `--secret-binary`, "We recommend that you store your binary data in a file and then pass the contents of the file as a parameter", "Constraints: min 1, max 65536"; `--kms-key-id`, "If you don't specify this value, then Secrets Manager uses the key aws/secretsmanager"; `fileb://` "will always be treated as binary and use the file contents directly". |
| R8 | Kubernetes SIG Auth, *Secrets Store CSI Driver*, Troubleshooting, <https://secrets-store-csi-driver.sigs.k8s.io/troubleshooting.html>: "If the pod fails to start because of the inline volume mount", with the event "MountVolume.SetUp failed for volume "secrets-store-inline"". |
| R9 | Caddy, *Request matchers*, <https://caddyserver.com/docs/caddyfile/matchers>: `path_regexp`, "Like path, but supports regular expressions. Runs against the URI-decoded/unescaped path." |
| R10 | Keycloak, *Server Administration Guide* 26.7.5, "Configuring realm keys" and "Rotating keys", <https://www.keycloak.org/docs/26.7.5/server_admin/index.html>, accessed 2026-10-24: "Keycloak has a single active key pair at a time, but can have several passive keys as well."; "The active key pair is used to create new signatures, while the passive key pair can be used to verify previous signatures."; "The highest number makes the key pair active."; "Once new keys are available, all new tokens and cookies will be signed with the new keys." |
| R11 | AWS, *What's in a Secrets Manager secret?*, <https://docs.aws.amazon.com/secretsmanager/latest/userguide/whats-in-a-secret.html>, accessed 2026-10-24: "Secrets Manager never removes labeled versions, but unlabeled versions are considered deprecated. Secrets Manager removes deprecated versions when there are more than 100. Secrets Manager doesn't remove versions created less than 24 hours ago."; "If the original secret is deleted, and then a new secret is created with the same name, the two secrets have different ARNs". |
