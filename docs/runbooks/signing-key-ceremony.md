# Signing-key ceremony

Version 1.1.0. Last reviewed 2026-10-25.

Every realm signing key is made by two people, under this script. It follows STD-IAM-001 2.9.0 §3.10
and ADR-IAM-002 §5.3 and §5.5, and TDD-identity-kernel-002 1.5.0 §Key Ceremony describes the design. A
server is built from zero, so the first ceremony runs before the kernel's first start. Each later key is
made the same way, and [signing-key rotation](signing-key-rotation.md) stages it.

## Who performs it

| Role | Who | Never |
| :-- | :-- | :-- |
| Operator | a named member of the Identity Platform Team with production deploy rights, holding the ceremony role | a service account |
| Witness | a second named holder of the ceremony role | the operator |
| Reviewer | a named member of Security or of the Architecture Authority | the operator, the witness, or the holder of the first Principal |

The names are `OWNER DECISION REQUIRED` (STD-IAM-001 §3.10). They are written in identity-control's
`docs/runbooks/bootstrap-ceremony.md` §Who performs it, the section both ceremonies use, and never in
this public repository. The review deadline is the owner's too; proposed: before the realm serves
anyone else, and at most two working days after the ceremony.

## Before you start

- A change ticket that names the reason. Its identifier is the script's `<reason>`, and the record is
  kept with it.
- Both people present for the whole run, in person or on one shared screen. The witness reads every
  command before it runs and every line it prints.
- On the development server: the checkout and `deploy/dev/.env`, as `deploy/dev/README.md` §First start
  describes, and the stack not started. A kernel started before the ceremony refuses to start and
  says why, which is harmless ([Custody outage](custody-outage.md)).

## Steps

1. **Check the roles.** The witness confirms the operator holds the ceremony role, and the operator
   confirms the witness does. Neither is the other.

2. **Run the generator,** from the repository root:

   ```sh
   scripts/signing-key-ceremony.sh deploy/dev/keys "<operator>" "<witness>" "<change ticket>"
   ```

   It refuses a witness equal to the operator, compared case-folded and trimmed. It makes the keystore
   in the pinned upstream image, as root, with no network, names it by its `kid`
   (`signing/realm-signing-<kid>.p12`, its password and `realm-signing-<kid>.crt`), and prints each step.

3. **The witness reads the record** it prints, and finds in it: both names, the reason, the
   generator's image digest, which equals `image/keycloak.ref`, and the `kid`. The record is also
   written to `deploy/dev/keys/realm-signing-<kid>.ceremony.json`.

4. **Put the key in the realm.** The first key: start the kernel, as `deploy/dev/README.md` §First start
   continues:

   ```sh
   cd deploy/dev && docker compose up -d --wait
   docker compose logs realm-apply   # ends in "... and signs with the custody key"
   ```

   `realm-apply` creates its provider, active, with the certificate's `kid`, on the empty realm, and
   refuses unless the realm publishes that key alone (TDD-identity-kernel-002 §Rotation as Built). It is
   registered in identity-control's registry once identity-control runs
   ([signing-key rotation](signing-key-rotation.md) §The first key). A later key: stage it
   ([signing-key rotation](signing-key-rotation.md) §Scheduled rotation).

5. **The witness compares the `kid`** in the record with the one the key set publishes:

   ```sh
   curl -fsS https://$KEYCLOAK_HOSTNAME/realms/scnehaux/protocol/openid-connect/certs
   ```

   The first key: exactly one key has `"alg": "PS256"`, and its `kid` is the record's. A staged key: its
   `kid` is there beside the active key's. Any other `PS256` key, such as
   `fallback-PS256`, stops the ceremony: [Custody outage](custody-outage.md).

6. **Attach the record** (`realm-signing-<kid>.ceremony.json`) and the terminal output of steps 2 to 5 to
   the change ticket. Never paste them in chat. They hold no secret: the keystore and its password
   stay in `deploy/dev/keys/signing` and `deploy/dev/keys/vault`, and are never copied, to the ticket
   or to a backup (STD-GLB-009 rule 9).

7. **The reviewer reviews** the ticket: both names are holders of the role and different people, the
   generator is the pinned image, and the published `kid` is the record's. The review is recorded on
   the ticket with the reviewer, the outcome and the time. Until it is, the realm serves no one but the
   people setting it up.

## Production

The same steps, with two differences, and none of them is run by CI:

- **Where the key is made.** On an operator workstation without network access, from the release's
  checkout, into a directory on encrypted storage that is destroyed after step 3 below.
- **Where it goes.** Into the key's own two secrets in AWS Secrets Manager, encrypted under the
  environment's customer-managed KMS key, never `aws/secretsmanager` (ADR-IAM-002 §5.3, §5.5 Q3). Each is
  created once and never written again: the policy denies `PutSecretValue` and `UpdateSecret` (Q8). With
  the operator's credentials for that environment, after step 3:

  ```sh
  aws secretsmanager create-secret --region <region> --kms-key-id <environment key ARN> \
    --name scnehaux/<environment>/identity-kernel/scnehaux/realm-signing-<kid>-keystore \
    --secret-binary fileb://<dir>/signing/realm-signing-<kid>.p12
  aws secretsmanager create-secret --region <region> --kms-key-id <environment key ARN> \
    --name scnehaux/<environment>/identity-kernel/scnehaux/realm-signing-<kid>-password \
    --secret-string file://<dir>/vault/scnehaux_realm-signing-<kid, underscores doubled>
  ```

  `fileb://` passes the file's bytes unchanged [R1]. The kernel's pods mount both through the AWS
  Secrets and Configuration Provider, as
  [`docs/production/realm-signing-secret-provider-class.yaml`](../production/realm-signing-secret-provider-class.yaml)
  declares. The witness checks both secrets name the environment's key (`describe-secret`), and the
  working directory is then destroyed. The secret manager holds the only copy (ADR-IAM-002 §6).

## Gaps

- **No production environment exists.** The production section is written ahead of it and has never
  run. Its first run is the first production ceremony.
- **The review record is a ticket entry.** identity-control's insert-only ceremony and review records
  hold the bootstrap ceremony; a signing-key ceremony is not recorded there yet.

## References

| # | Source |
| :-- | :-- |
| R1 | AWS CLI, `secretsmanager create-secret`, <https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/create-secret.html>, accessed 2026-10-20: `--secret-binary`, "We recommend that you store your binary data in a file and then pass the contents of the file as a parameter"; "`fileb://` will always be treated as binary and use the file contents directly regardless of the `cli-binary-format` setting"; `--kms-key-id`, "If you don't specify this value, then Secrets Manager uses the key aws/secretsmanager". |
