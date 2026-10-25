# Signing-key rotation

Version 1.0.0. Last reviewed 2026-10-25.

A realm signing key moves through `staged`, `active`, `retiring`, `retired` and `revoked` only by the
steps below (ADR-IAM-002 §5.2 and §5.5, TDD-identity-kernel-002 1.5.0 §Rotation as Built). Each step is
`scripts/signing-key-rotation.sh`, run from the kernel's checkout on the server. Each one reads the
realm and identity-control's registry, refuses when they disagree or the registry holds no approval,
acts, and records what it did in the registry (TDD-identity-control-001 §The Signing Key Registry).
The keys themselves are made by the [signing-key ceremony](signing-key-ceremony.md).

## Who performs it

| Role | Who | Never |
| :-- | :-- | :-- |
| Operator | the holder of the ceremony role who runs the step | a service account |
| Approver | a second holder of the ceremony role | the step's operator; for an activation, also the key's generating operator |

The names are the owner's (STD-IAM-001 §3.10), recorded in identity-control's
`docs/runbooks/bootstrap-ceremony.md`. The registry refuses the combinations above, compared trimmed and
case-folded, and refuses a step without an unused approval for that key, that transition and that
operator.

## Before any step

```sh
export IDENTITY_CONTROL_DEPLOY_DIR=/srv/identity-control/deploy/dev   # identity-control's checkout
scripts/signing-key-rotation.sh state
```

`state` prints the registry's keys and the realm's providers. Every key must agree: `staged` and
`retiring` are `passive` in the realm, `active` is `active`, and `retired` and `revoked` are absent. A
step on a key that disagrees exits 2. That follows a restore of the Control Database or the kernel's:
record the missing transitions first ([After a restore](#after-a-restore)).

Exit status of every step: 0 done, 1 failed (recorded as `failed` in the registry when the approval was
found; the state is unchanged), 2 refused.

## The first key

The first key is active from the kernel's first start: `realm-apply` created its provider on the empty
realm (ADR-IAM-002 §5.5 Q4). Once identity-control runs, register it, in this order, with the ceremony
record's names and ticket:

```sh
kid=<the first key's kid, from deploy/dev/keys/realm-signing-*.ceremony.json>
scripts/signing-key-rotation.sh stage "$kid" "<generating operator>" "<witness>" "the first key" "<ticket>"
scripts/signing-key-rotation.sh approve "$kid" activate "<operator>" "<approver>" "the first key" "<ticket>"
scripts/signing-key-rotation.sh activate "$kid" "<operator>"
```

The activation finds the key already active and alone, changes nothing in the realm, and records it.

## Scheduled rotation

Every 30 days (TDD-identity-kernel-002 §Configuration), and before the active key is 35 days old.

1. **Make the next key**: the [ceremony](signing-key-ceremony.md), steps 1 to 3.
2. **Stage it**:

   ```sh
   scripts/signing-key-rotation.sh stage <new kid> "<generating operator>" "<witness>" "scheduled rotation" "<ticket>"
   ```

   It registers the key, checks every keystore (`check-keystores`), and creates the key's provider
   enabled and passive. The key set now publishes both keys, and tokens still carry the old `kid`.
3. **Wait the consumer cache window**, 10 minutes, so every consumer holds the new key before it signs.
4. **Approve and activate**:

   ```sh
   scripts/signing-key-rotation.sh approve <new kid> activate "<operator>" "<approver>" "scheduled rotation" "<ticket>"
   scripts/signing-key-rotation.sh activate <new kid> "<operator>"
   ```

   Before the window the registry refuses (exit 2). The step makes the new key active above every
   other, then demotes the old one, and the registry records both. New tokens carry the new `kid`; the
   old key stays published, `retiring`, and its tokens still verify.
5. **Wait the retirement window**, 7 days. Every `realm-apply` run checks that the floor computed from
   the live token lifetimes is within it (TDD-identity-kernel-002 §Retirement Window).
6. **Approve and retire the old key**:

   ```sh
   scripts/signing-key-rotation.sh approve <old kid> retire "<operator>" "<approver>" "scheduled rotation" "<ticket>"
   scripts/signing-key-rotation.sh retire <old kid> "<operator>"
   ```

   Before the window the registry refuses. The step removes the provider, so the key leaves the key set;
   then removes `signing/realm-signing-<kid>.p12`, its password and its certificate, and reads them back
   absent; then records `retired` with that evidence. The ceremony record stays: it holds no secret.

## Emergency rotation, on a suspected compromise

ADR-IAM-002 §5.5 Q7: the replacement is activated at once, and the compromised key is revoked. Tokens
the compromised key signed fail once a consumer's key set refreshes, at most 10 minutes later; that
failure is the containment, not an incident to suppress.

1. **A replacement**: a key already staged for at least the cache window, or a new one, made by the
   [ceremony](signing-key-ceremony.md) and staged (Scheduled rotation, step 2).
2. **Activate it at once** with an emergency approval, which the registry exempts from the window:

   ```sh
   scripts/signing-key-rotation.sh approve <replacement kid> activate "<operator>" "<approver>" "compromise of <kid>" "<ticket>" --emergency
   scripts/signing-key-rotation.sh activate <replacement kid> "<operator>"
   ```

   The compromised key is now `retiring`. It is never revoked while it is active: the step refuses.
3. **Revoke it**:

   ```sh
   scripts/signing-key-rotation.sh approve <kid> revoke "<operator>" "<approver>" "compromise" "<ticket>"
   scripts/signing-key-rotation.sh revoke <kid> "<operator>"
   ```

4. **Record the issuance window** on the ticket: from the key's `activate` to its `demote`, from
   `scripts/signing-key-rotation.sh state` and the registry (TDD-identity-kernel-002 §Compromise).

A staged key whose integrity is suspect is revoked the same way, from step 3.

## Abandoning a staged key

A staged key that will not be used, and is not suspect, is abandoned: it leaves the key set and its
files are destroyed, and the registry records it `retired`, reason `abandoned` (ADR-IAM-002 §5.5 Q6).

```sh
scripts/signing-key-rotation.sh approve <kid> abandon "<operator>" "<approver>" "<why>" "<ticket>"
scripts/signing-key-rotation.sh abandon <kid> "<operator>"
```

A retiring key is never activated again (Q6). If a new key fails, fix or replace it: stage another.

## After a restore

A restored Control Database can lack transitions the kernel made, and a restored kernel database can
lack providers the registry records. `state` shows the difference. Record each missing transition in
the registry, in order, under a new approval by someone other than its operator, from the kernel's admin
events and the ceremony records (identity-control's `docs/runbooks/control-database-restore.md`). A key
whose files are gone cannot come back: a restore takes the current active key from custody, never
regenerates one (TDD-identity-kernel-002 §Compromise and Recovery).

## Production

No production environment exists, so these have never run. The steps are the same, with the key's
custody in AWS Secrets Manager instead of `deploy/dev/keys`:

- **Staging** adds the key's two objects to the two `SecretProviderClass` objects
  ([`docs/production/realm-signing-secret-provider-class.yaml`](../production/realm-signing-secret-provider-class.yaml))
  and rolls the replicas, so every replica's start check sees the keystore, before `stage` creates the
  provider (ADR-IAM-002 §5.5 Q3).
- **Retiring, abandoning or revoking** follows Q8's order, after the approval and the registry's check:

  1. remove the key's provider (`signing-key remove -kid <kid>`, the step's first half);
  2. remove its two objects from the `SecretProviderClass` objects and roll the replicas;
  3. delete both secrets, with no recovery window:

     ```sh
     aws secretsmanager delete-secret --region <region> --force-delete-without-recovery \
       --secret-id scnehaux/<environment>/identity-kernel/scnehaux/realm-signing-<kid>-keystore
     aws secretsmanager delete-secret --region <region> --force-delete-without-recovery \
       --secret-id scnehaux/<environment>/identity-kernel/scnehaux/realm-signing-<kid>-password
     ```

  4. read each until Secrets Manager no longer returns it (`aws secretsmanager describe-secret` fails
     with `ResourceNotFoundException`), and take each `DeleteSecret` event from CloudTrail
     (`aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteSecret`);
  5. record the transition with those events as the evidence:

     ```sh
     identity-signing-key record -realm scnehaux -approval <approval id from check> -outcome completed \
       -evidence "provider removed; DeleteSecret <event id>, <event id>"
     ```

Never call `put-secret-value` or `update-secret` on a signing secret: a second version is a copy the
deletion has to reach, and the policy denies both (ADR-IAM-002 §5.5 Q8).

## Gaps

- **No production environment exists.** The production section has never run.
- **The 7-day window has run only in CI's shortened form.** The `rotation` job of `compat.yml` proves the
  steps with a `ci` environment's windows; a full rehearsal on a long-lived environment is the production
  gate's (ROADMAP §Gates).
- **The privileged-administration event** is the registry's row until Audit & Evidence exists
  (STD-IAM-001 §3.8).
