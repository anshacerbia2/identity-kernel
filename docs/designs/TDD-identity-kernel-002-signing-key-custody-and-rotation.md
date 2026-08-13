---
doc_meta:
  id: TDD-identity-kernel-002
  title: Signing Key Custody, Identity, and Rotation
  owner: Identity Platform Team
  version: 0.2.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-08-14
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
- Client secrets and federation keys, which use the same custody mechanism but a
  different lifecycle.

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

```text
kid            thumbprint, derived not assigned
algorithm      PS256 for the initial enterprise baseline
state          active | retiring | retired | purged
activated_at   when it began signing
retiring_at    when it stopped signing and continued verifying
retired_at     when it left JWKS
purged_at      when the private material was destroyed
custody_ref    reference into the secret manager, never the material
```

## Data Model

### Rotation State Machine

```text
        generate            activate           retire            purge
  ()  ──────────►  staged  ────────►  active  ────────►  retiring  ────────►  retired  ──────►  purged
                                        │
                                        └── compromise ──►  revoked
```

| State | Signs | Published in JWKS | Meaning |
| :-- | :-- | :-- | :-- |
| `staged` | No | No | Generated and sealed, not yet trusted |
| `active` | Yes | Yes | The current signing key; exactly one per algorithm per realm |
| `retiring` | No | Yes | Stopped signing, still verifies tokens issued before rotation |
| `retired` | No | No | No outstanding artifact can still be in flight |
| `purged` | No | No | Private material destroyed |
| `revoked` | No | No | Compromise response; removed from JWKS immediately |

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
    generate the next key pair under ceremony, seal it, register as staged
    publish its public material to JWKS ahead of activation
    wait for the consumer cache window so every consumer holds the new public key
    promote staged to active; demote the previous active to retiring
    hold the retiring key in JWKS for the computed retirement window
    move retiring to retired and remove it from JWKS
    purge the private material after the evidence retention period
```

Publishing the public key before activation is what makes rotation invisible to
consumers. A consumer whose cache has not refreshed when the new key begins signing
would see an unknown `kid` and reject valid tokens, which is a self-inflicted outage
during a routine operation.

### Compromise

```text
on suspected compromise:
    generate and stage a replacement, publish it, activate it
    move the compromised key directly to revoked and remove it from JWKS immediately
    accept that every token signed by it fails verification from that moment
    treat the resulting failures as containment, not as an incident to suppress
    record actor, reason, correlation, and the affected issuance window
```

Compromise skips the retirement window deliberately. The window exists to protect
valid tokens, and after a compromise there is no longer a basis for treating tokens
signed by that key as valid.

### Separation of Duties

- Key generation requires two operators; neither alone can complete a ceremony.
- The operator who generates a key does not approve its activation.
- Purging private material requires an approval distinct from the operator performing
  it.
- Every key operation is recorded with actor, reason, correlation identifier, and
  outcome, and is emitted as a privileged-administration event.

No individual can generate, activate, and destroy a key alone, which is what EAD-006
§5.4 requires for high-impact key operations.

## Configuration

| Setting | Value | Reason |
| :-- | :-- | :-- |
| Key source | Approved secret manager reference | Custody is external to the artifact |
| Signing algorithm | `PS256` | STD-IAM-002 §3.2.2 baseline; candidate release must prove support |
| RSA modulus | at least 3072 bits | Algorithm profile minimum |
| Key generation in process | Prohibited, including as fallback | STD-IAM-001 §3.5 |
| `kid` | RFC 7638 thumbprint | Makes reuse unrepresentable |
| Active keys per algorithm per realm | Exactly one | A compromise must name one key |
| Rotation cadence | 30 days | Bounds the issuance window a single key covers |
| Retirement window | 7 days, floor computed from live token classes | Verification continuity |
| JWKS cache guidance to consumers | 10 minutes | Feeds the retirement floor |
| Startup on custody failure | Exit non-zero | No silent ephemeral fallback |

No key material appears in configuration, in an image, in a realm export, in source
control, in a log, or in an event.

## Testing Strategy

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
- The new public key appears in JWKS before it begins signing, by at least the
  consumer cache window.
- A retiring key leaves JWKS only after the computed window elapses.
- Raising a token lifetime class raises the computed retirement floor, and a
  configuration that would shorten the window below its floor fails.

### Compromise and Recovery

- A revoked key is removed from JWKS immediately, and tokens signed by it fail
  verification.
- Restoring the cluster from backup reproduces the same `kid` set and does not
  generate new material.
- A restore to a point before a rotation is detected, and the missing key is
  reinstated from custody rather than regenerated.

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
| Conforms to | STD-IAM-001 §3.5 — one `kid` to one immutable key pair; identical material across replicas; no ephemeral fallback |
| Conforms to | STD-IAM-002 §3.5 — verification material published for the maximum artifact lifetime with margin |
| Enterprise constraint | EAD-005 §5.3 — managed KMS/HSM and secret-management capability |
| Enterprise constraint | EAD-006 §5.4 — unique stable key identity, controlled lifecycle, separation of duties, tested continuity |
| Enterprise constraint | EAD-005 §6.8 — recovery is proven by exercise, not by existence |
| Consumed by | Every protected resource performing local verification |
| Related design | `TDD-identity-kernel-001` — realm topology, issuer identity, claim projection |

### Open Questions

1. Which approved secret manager holds the sealed keystore in each environment. The
   enterprise direction is a managed capability and the adopted cloud provider offers
   one; the specific service and its access model are recorded once the environment
   baseline is fixed.
2. Whether the evidence retention period for purged key material is set by security
   policy or by a regulatory obligation. The design holds material until the period
   elapses in either case; only the duration differs.
