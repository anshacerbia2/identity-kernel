# Consumer reports an unknown `kid`

Version 1.0.0. Last reviewed 2026-10-07.

A protected resource rejects access tokens because their header names a `kid` its key set does not
hold. To the consumer it looks like the kernel's fault. Often it is not: this runbook tells the cases
apart.

## Signal

A consumer that verifies with foundation-platform's `verify` package logs:

```text
verify: kid "<kid>": verify: signing key is unknown
```

That is `ErrUnknownKey`. Two other errors look alike and have other causes:

| Error | Meaning | Where to go |
| :-- | :-- | :-- |
| `kid "<kid>" unknown and the key set could not be reloaded: ... signing material is unavailable` | The consumer could not fetch the JWKS at all | Kernel availability or the consumer's network, not this runbook |
| `alg "<alg>" is not PS256` | The token was not signed with the baseline algorithm | The client or the token is not the baseline profile (STD-IAM-002 §3.2.2) |

## What the code does

**The kernel.** The realm signs with one declared key provider, `rsa-ps256-3072`: Keycloak's
`rsa-generated`, PS256, 3072 bits, priority 200 (`realm/signing-key.generated.json`). Keycloak
generates the key and keeps it in its database. Its JWKS,
`/realms/scnehaux/protocol/openid-connect/certs`, publishes every key whose status is `ACTIVE` or
`PASSIVE`. A `DISABLED` or deleted key leaves it at once [R1]. The realm also keeps Keycloak's
built-in providers beside it, so the JWKS carries keys for other algorithms and for encryption.

**Keycloak replaces a missing signing key by itself.** When no active PS256 key exists, the next
token issued makes Keycloak create a provider named `fallback-PS256`, at priority -100, and log "No
keys found for realm=scnehaux and algorithm=PS256 for use=SIG. Generating keys." The key gets the
generator's default size, 2048 bits [R4]. Every consumer drops it, because `verify` refuses a key
under 3072 bits, so every token it signs is reported as an unknown `kid`. It is also the in-process
key generation STD-IAM-001 §3.5 prohibits.

**The consumer** (`verify/jwks.go`, `verify/verify.go` in foundation-platform):

- It reads the JWKS from a URL in its configuration, never from the token.
- It keeps only RSA signing keys with a `kid`, `alg` PS256 or absent, and at least 3072 bits.
- On an unknown `kid` it fetches the JWKS once more and then rejects the token if the `kid` is still
  unknown. It fetches at most once per `MinRefetchInterval`, 60 seconds by default, so a stream of
  invented identifiers cannot flood the issuer.
- A new key set replaces the old one whole. A key the kernel removed stops verifying at the
  consumer's next fetch.
- The `kid` is checked before `iss`. So a token from another issuer is reported as an unknown `kid`,
  not as a wrong issuer.

This is the rotation model of OpenID Connect Core §10.1.1: "The verifier knows to go back to the
jwks_uri location to re-retrieve the keys when it sees an unfamiliar kid value" [R2].

## Steps

1. **Collect, without the token.** From the consumer: the `kid`, the time, the resource, and the
   JWKS URL and issuer it is configured with. Ask for the token's header and its `iss` claim, not the
   token. An access token is a bearer credential. If you are handed one anyway, decode its first two
   segments locally (base64url), and do not paste it into any tool or ticket.

2. **Read what the kernel publishes now.**

   ```sh
   curl -fsS https://$KEYCLOAK_HOSTNAME/realms/scnehaux/protocol/openid-connect/certs
   ```

3. **Read every key the realm holds**, disabled ones included. Admin Console, on the owner-only
   admin URL: **Realm settings**, **Keys**, with the filter on active, passive and disabled. Or the
   Admin API, `GET /admin/realms/scnehaux/keys`, which lists each key's `kid`, `status`,
   `providerId`, `algorithm` and `use` [R3].

4. **Classify.**

   | What you find | Cause | Action |
   | :-- | :-- | :-- |
   | The token's `iss` is not the issuer the consumer is configured for | A token from another environment or realm, such as a development token sent to another stack. The kernel is fine | The client must obtain tokens from the consumer's issuer. Close as a client fault |
   | The `kid` belongs to the provider `fallback-PS256` | The declared key `rsa-ps256-3072` was disabled or deleted, and Keycloak generated a 2048-bit replacement | Step 5 or 6 for the declared key, then delete `fallback-PS256`. No consumer ever verified a token it signed |
   | The `kid` is in the JWKS now, of a 3072-bit PS256 key | The consumer has not refetched yet, or fetches another URL | Wait one `MinRefetchInterval` and retry. If it persists, the consumer's JWKS URL is wrong: compare it with the discovery document's `jwks_uri` |
   | The `kid` is in the realm as `DISABLED` | Someone disabled the key provider. `realm-apply` reports it as drift on `signing key rsa-ps256-3072` | Step 5 |
   | The `kid` is nowhere in the realm | The key was deleted, the database was restored to a point before the key existed, or the realm was recreated (`docker compose down -v`) | Step 6 |
   | The `kid` was never issued by this kernel | A forged or corrupt token | Rejection is correct. Treat a burst as a security signal; the rate limit already protects the kernel |

5. **A disabled key.** First find out why, from the admin events
   ([Console drift](console-drift.md), step 2).
   - **Disabled by mistake, and not suspected compromised.** If it is `rsa-ps256-3072`, the declared
     key, revert the drift: enabled and active, as `realm/signing-key.generated.json` declares
     ([Console drift](console-drift.md), step 4a). At priority 200 it signs again ahead of any
     fallback key. If it is another key, enable it with `active` false. A passive key is published and
     verifies, and signs nothing [R1]. Disable it again once every token it signed has expired.
   - **Suspected compromised:** do not enable it. Every token it signed must fail. That failure is
     the containment, not an incident to suppress (TDD-identity-kernel-002 §Compromise). Tell every
     consumer owner why their users must sign in again.

6. **A key that is gone.** It cannot come back. If it was `rsa-ps256-3072`, `realm-apply` reports
   the provider "removed from the live realm" and refuses. Applying with `-adopt` creates it again,
   with a new key and a new `kid`. Do that, because the alternative is the 2048-bit fallback key.
   Tokens the old key signed fail until their `exp`.
   Sessions continue through a refresh, which issues tokens under the current key. After a database
   restore, find out from [Failed upgrade](failed-upgrade.md) §B step 4 what else the restore took
   with it.

7. **Confirm.** A token issued now carries a `kid` the JWKS publishes, and the consumer verifies it.
   The consumer reports no new `ErrUnknownKey` after its next refetch.

## Do not rotate by hand to fix this

A key made by hand signs at once. Keycloak has no staged state: "Once new keys are available, all new
tokens and cookies will be signed with the new keys" [R1]. Every consumer that has not refetched
then sees an unknown `kid`. That is the outage TDD-identity-kernel-002 §Rotation prevents by
publishing a key before it signs. If a key must be replaced before custody exists, keep the old key
passive for at least the longest access-token lifetime, plus the consumer cache, plus clock skew
(TDD-identity-kernel-002 §Retirement Window). OpenID Connect Core: the JWKS "SHOULD retain recently
decommissioned signing keys for a reasonable period of time to facilitate a smooth transition" [R2].

## Gaps

- **Custody is not built** (ROADMAP Week 2). Until it is, the `kid` is Keycloak's own, not the RFC
  7638 thumbprint TDD-identity-kernel-002 requires, and keys have no `staged` state.
- **No alert.** Nothing watches the consumers' `ErrUnknownKey` rate or compares the JWKS across
  replicas (TDD-identity-kernel-002 §Operational Notes). A report from a consumer is the signal.
- **Production.** TDD-identity-kernel-002 also requires runbooks for scheduled and emergency
  rotation, a custody outage and restore-to-earlier-point key reconciliation. They wait on custody,
  as the key ceremony runbook does.

## References

| # | Source |
| :-- | :-- |
| R1 | Keycloak 26.7.5. `JWKSServerUtils.getRealmJwks` publishes keys filtered by `k.getStatus().isEnabled()`, and `KeyStatus.isEnabled()` is `this.equals(ACTIVE) \|\| this.equals(PASSIVE)` (`services/.../protocol/oidc/utils/JWKSServerUtils.java`, `core/.../crypto/KeyStatus.java`). *Server Administration Guide*, "Rotating keys", <https://www.keycloak.org/docs/latest/server_admin/index.html>, accessed 2026-10-07: "The active key pair is used to create new signatures, while the passive key pair can be used to verify previous signatures"; "Once new keys are available, all new tokens and cookies will be signed with the new keys." |
| R2 | OpenID Foundation, *OpenID Connect Core 1.0 incorporating errata set 2*, §10.1.1, <https://openid.net/specs/openid-connect-core-1_0.html>, accessed 2026-10-07: "The verifier knows to go back to the jwks_uri location to re-retrieve the keys when it sees an unfamiliar kid value. The JWK Set document at the jwks_uri SHOULD retain recently decommissioned signing keys for a reasonable period of time to facilitate a smooth transition." |
| R3 | Keycloak 26.7.5, `services/.../resources/admin/KeyResource.java`, `getKeyMetadata`: requires `view-realm` and returns each key's `kid`, `status`, `providerId`, `algorithm` and `use`. |
| R4 | Keycloak 26.7.5. `DefaultKeyManager.getActiveKey`: with no active key it calls `createFallbackKeys` and logs "No keys found for realm={0} and algorithm={1} for use={2}. Generating keys." `AbstractGeneratedRsaKeyProviderFactory.createFallbackKeys` adds a component named `"fallback-" + algorithm` with priority `"-100"` and no key size, so `validateConfiguration` generates it at `defaultKeySize`, 2048. The same method generates a new key whenever the configured `keySize` differs from the key held: "Key size changed, generating new keys". |
