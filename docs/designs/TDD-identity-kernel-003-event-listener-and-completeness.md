---
doc_meta:
  id: TDD-identity-kernel-003
  title: Event Listener Extension and Completeness Reconciliation
  owner: Identity Platform Team
  version: 1.0.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-08-11
  parent_sad: SAD-001
---

# Event Listener Extension and Completeness Reconciliation

## Purpose

Specify how identity events leave the kernel: the minimal listener extension that
delivers them quickly, the native event store that makes them durable, and the
reconciliation that proves nothing was lost.

SAD-001 §4.2 states two requirements that pull against each other:

> A delivery failure must not silently erase the source event.
>
> Completeness is checked through scheduled reconciliation against supported event and
> admin state.

The resolution is that the listener is not the durable path. It is the fast path, and
the durable path is Keycloak's own event store read through the supported Admin API.

## Scope

**In scope**

- The listener extension: what it captures, how it delivers, and how it fails.
- Why the listener never blocks or fails an authentication.
- Keycloak's native event store as the record of truth for completeness.
- Reconciliation between what was delivered and what the kernel recorded.
- Retention configuration and the constraint that binds it to the reconcile interval.
- Version compatibility with the pinned release.

**Out of scope**

- Translation into canonical Scnehaux events and the outbox — owned by
  `identity-control`.
- The event envelope and its schema — owned by `TDD-foundation-platform-001`.
- Realm configuration content — owned by `TDD-identity-kernel-001`.
- Enterprise evidence retention, which belongs to Audit & Evidence.

## Technical Context

Three constraints fix the shape of this design, and two of them are prohibitions.

**No Scnehaux table may exist in the Keycloak database.** STD-GLB-002 is explicit that
Keycloak private persistence remains owned by Keycloak and is not modified with
Scnehaux tables, triggers, policies, or row-level security. So the extension cannot
maintain its own durable queue inside the kernel's schema, which is the obvious way to
make delivery reliable and is unavailable here.

**The listener runs inside the authentication path.** A Keycloak event listener is
invoked synchronously as part of the operation that produced the event. A listener that
blocks makes login slower; a listener that throws can fail the operation entirely. The
extension that exists to observe authentication must not be able to break it.

**Keycloak already persists events.** User events and admin events are stored natively
with configurable retention and are readable through the supported Admin API. That
store is the durable record, and it exists whether or not the listener works.

Those three together give the design its shape: the listener is an optimisation that
reduces latency, and the native store plus reconciliation is the guarantee.

## Component Design

```text
Keycloak operation
    ├─► native event store            durable, the record of truth
    └─► listener extension            fast path, best effort
            └─► identity-control      low-latency delivery

identity-control reconciler
    └─► Admin API events endpoint     compares what it received against what was recorded
```

| Component | Responsibility |
| :-- | :-- |
| `ScnehauxEventListener` | Captures the event, hands it to the buffer, returns immediately |
| Bounded in-memory buffer | Decouples the authentication path from delivery |
| Delivery worker | Posts batches to the Identity Control ingest endpoint |
| Native event store | Keycloak's own persistence, the completeness reference |

### The Listener Contract

```text
onEvent(event):
    map to the wire shape
    offer to the bounded buffer
    if the buffer is full:
        drop, increment the dropped counter
    return

    never block
    never throw
    never call out synchronously
```

Dropping on a full buffer looks wrong and is correct. The alternatives are blocking,
which slows every authentication behind a delivery problem, and throwing, which fails
the authentication outright. A dropped event is recovered by reconciliation because the
native store still holds it; a failed login is not recovered at all.

The dropped counter is the signal. It says the fast path is degraded, and it does not
say an event was lost.

### Captured Event Classes

| Class | Examples |
| :-- | :-- |
| User | Login, login error, logout, register, credential update, verify email |
| Admin | Create, update, delete on users, clients, roles, realm configuration |
| Security | Brute-force detection, permission denied, invalid credentials |

The extension contains no product business logic, per ADR-IAM-001 §5.7 and SAD-001
§4.2. It maps and forwards. A conditional in this extension that depends on a domain
concept is a defect, because it puts domain logic inside the authentication path and
inside the artifact whose upgrade is bound to the vendor release.

## Data Model

### Wire Shape

The listener emits the kernel's own representation, not the canonical Scnehaux event.
Translation happens in `identity-control`, so a change to the enterprise envelope does
not require a kernel rebuild.

```json
{
  "kc_event_id": "e1f2...",
  "type": "LOGIN",
  "realm": "scnehaux",
  "kc_user_id": "8f3a...",
  "client_id": "identity-experience",
  "session_id": "b7c1...",
  "ip_address": "203.0.113.10",
  "time": 1786000000123,
  "details": { "auth_method": "openid-connect" }
}
```

`kc_event_id` is the deduplication key. The same event arriving from the fast path and
from reconciliation is applied once.

`kc_user_id` is the Keycloak-local identifier. `identity-control` maps it to
`principal_id` during translation and never exposes it downstream, per
`TDD-identity-control-001`.

No password field, no token, no credential value, and no client secret appears in the
wire shape, at any nesting level.

### Retention Constraint

This is the one configuration relationship that cannot be got wrong:

```text
native event retention  >  reconcile interval  ×  safety factor
```

If retention expires before reconciliation reads a window, the events in that window
are gone from the only durable record, and the reconciler will report completeness
against a store that has already forgotten. With a one-hour reconcile interval and a
safety factor of twenty-four, retention is at least one day; the configured default is
seven.

The relationship is asserted at startup rather than documented. A realm configured with
retention below the floor fails the configuration diff.

## API / Interface

### Delivery

```text
POST /internal/v1/kernel-events
```

Batched, authenticated with a workload credential, idempotent on `kc_event_id`. The
endpoint belongs to `identity-control`; this repository owns only the client side.

A non-2xx response returns the batch to the buffer for one retry, then drops it. The
extension does not implement escalating retry, because retry state inside the
authentication path is the thing this design refuses to hold.

### Reconciliation Source

```text
GET /admin/realms/{realm}/events?dateFrom&dateTo&first&max
GET /admin/realms/{realm}/admin-events?dateFrom&dateTo&first&max
```

Read by `identity-control` through the supported Admin API. This repository's obligation
is to keep both endpoints populated and within retention.

## Algorithms / Logic

### Completeness Reconciliation

Executed by `identity-control`, specified here because this repository owns the source:

```text
for each window of the last reconcile interval:
    recorded  := events read from the Admin API for the window
    delivered := events already ingested for the window

    missing := recorded − delivered
        → ingest, count as recovered

    extra := delivered − recorded
        → investigate; an event delivered that the kernel did not record
          means the fast path fabricated or duplicated it
```

`missing` is expected in small numbers and is what the reconciler exists for. `extra`
is not expected at all and is a defect in the listener or in ingest deduplication.

Windows overlap by one interval so an event recorded at a boundary is not missed by
both passes.

### Version Compatibility

The listener depends on the Keycloak SPI, which is version-bound. Per ADR-IAM-001 §5.7
it declares:

```text
supported Keycloak range   the pinned release, and the next candidate once verified
owner                      Identity Platform Team
tests                      unit, integration against the pinned release
upgrade suite              exercised by TDD-identity-kernel-005 before promotion
failure behavior           drop and count; never block, never throw
removal strategy           disable the listener; reconciliation alone remains correct
```

The removal strategy is the property worth stating. If the listener becomes
incompatible with a candidate release, it can be disabled and the system remains
correct — events arrive through reconciliation at reconcile-interval latency instead of
seconds. That converts a blocking upgrade problem into a temporary latency regression,
and it exists because the durable path was never the listener.

## Configuration

| Setting | Default | Purpose |
| :-- | :-- | :-- |
| User events | enabled | Native durable record |
| Admin events | enabled, with representation | Native durable record |
| Event retention | `7d` | Must exceed reconcile interval by the safety factor |
| Listener buffer size | `4096` | Bounded; overflow drops and counts |
| Delivery batch size | `100` | Events per POST |
| Delivery interval | `1s` | Flush cadence |
| Delivery timeout | `2s` | Bound on one POST |
| Listener enabled | `true` | Disabling degrades latency, not correctness |

Admin events are enabled with representation because an admin event without it records
that something changed and not what it changed to, which is not evidence.

## Testing Strategy

### Non-Interference

- A delivery endpoint returning errors does not slow authentication measurably.
- A delivery endpoint that hangs does not block authentication.
- A listener that throws internally does not fail the operation that produced the event.
- A full buffer drops and increments the counter rather than blocking.

### Completeness

- Every event dropped by the fast path is recovered by reconciliation.
- Disabling the listener entirely loses no event; all arrive through reconciliation.
- Overlapping windows do not double-apply, because ingest deduplicates on
  `kc_event_id`.
- An `extra` finding is raised when an event is delivered that the kernel did not
  record.

### Retention

- A realm configured with retention below the floor fails the configuration diff.
- Events remain readable through the Admin API for the full retention period.

### Content

- No password field, token, credential value, or client secret appears in any delivered
  event, asserted by scanning delivered payloads for credential-shaped values.
- Admin events carry their representation.

### Compatibility

- The listener builds and passes its tests against the pinned release.
- A candidate release that breaks the SPI fails the upgrade suite rather than shipping.

## Security Notes

The extension observes the authentication path, so its failure modes were chosen before
its features. It cannot block, cannot throw, and holds no retry state, because the cost
of a defect there is authentication unavailability across the estate.

It carries no credential material. `identity-control` never receives a plaintext
password, a passkey private value, a TOTP secret, or a refresh token, per SAD-001 §7.1,
and the wire shape has no field that could carry one.

The delivery credential is a workload credential scoped to the ingest endpoint alone. It
grants no Admin API access, so compromise of the kernel's delivery client does not yield
control-plane authority.

Admin event representations contain configuration changes, which are restricted. They
are transported over TLS to an internal endpoint and are never written to a log.

## Performance Notes

The listener adds one bounded-queue offer per event to the authentication path, which is
a memory write and a counter increment. It performs no I/O synchronously.

Delivery is batched and asynchronous. Reconciliation reads paged Admin API windows on a
schedule and is rate-limited so it cannot consume capacity reserved for authentication.

Native event persistence is Keycloak's own write and is the cost of having a durable
record at all. It is accepted rather than optimised, because the alternative is having
no completeness reference.

## Operational Notes

| Signal | Warning | Critical |
| :-- | :-- | :-- |
| Dropped events, fast path | any occurrence | sustained |
| Recovered events per reconciliation | above baseline | — |
| `extra` findings | — | any occurrence |
| Reconciliation age | one interval | two intervals |
| Event retention below the computed floor | — | any occurrence |
| Delivery endpoint unreachable | 5 minutes | 30 minutes |

Dropped events are a latency signal, not a loss signal, and the runbook says so
explicitly. Treating them as loss produces an unnecessary incident; treating an `extra`
finding as noise produces a real one.

Runbooks required before production: delivery endpoint outage, sustained fast-path
drops, `extra` finding investigation, and listener disable during an incompatible
upgrade.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-001 — Scnehaux Identity Runtime |
| Realizes capability | PAD-PLT-001 — identity security facts and lifecycle events |
| Governed by | ADR-IAM-001 §5.7 — minimal event listener; no product logic; declared support range |
| Conforms to | STD-GLB-002 — Keycloak private persistence is not modified with Scnehaux tables |
| Conforms to | STD-IAM-001 §3.8 — governed security and audit events |
| Enterprise constraint | EAD-002 §8 — source domains retain durable local facts until delivered |
| Consumed by | `identity-control` — translation into canonical events and the outbox |
| Related design | `TDD-identity-kernel-005` — the upgrade suite that exercises this extension |
