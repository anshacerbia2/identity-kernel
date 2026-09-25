# Development server

This is a long-lived Keycloak for developing against from a local machine. It runs the
same pinned image that `compat/` asserts, in production mode (`start`) on Postgres, behind
Caddy for TLS. The realm is applied with `cmd/realm-apply`, the same tool CI uses.

It is **development only**:

- `realm-apply` accepts `development` and refuses anything that serves real tokens,
  because the signing key is generated in-process.
- The issuer this server gets is not the production issuer.
- Nothing issued here is evidence of anything.

## What is exposed

| Path | Reachable from |
| :-- | :-- |
| `/realms/scnehaux/...`: discovery, JWKS, token, login | anywhere |
| `/admin/...` (console and REST API), `/realms/master/...` | `ADMIN_ALLOW_CIDRS` only; everyone else gets `404` |
| management port `9000` (health, metrics) | the container only |

CI brings this exact stack up on every change and asserts two things:

- The public issuer is served through the proxy.
- Administration answers `404` to an address outside the allowlist.

## Requirements

- **Server:** a Linux host with Docker and Compose v2.
- **Ports:** 80 and 443 open. Caddy uses port 80 to obtain the certificate.
- **DNS:** a DNS name pointing at the host.

## First start

On the server:

```sh
git clone https://github.com/anshacerbia2/identity-kernel && cd identity-kernel/deploy/dev
cp .env.example .env        # fill it in: hostname, your IP, two generated secrets
docker compose up -d --wait
./create-apply-client.sh    # prints KEYCLOAK_ADMIN_CLIENT_ID and _SECRET, once
```

Keep the two printed lines somewhere safe. They are the credential `realm-apply` uses.

On your machine, from a clean checkout of `identity-kernel` and from an address in
`ADMIN_ALLOW_CIDRS`:

```sh
export KEYCLOAK_ADMIN_CLIENT_ID=realm-apply
export KEYCLOAK_ADMIN_CLIENT_SECRET=...        # from create-apply-client.sh
go run ./cmd/realm-apply -environment development -url https://<KEYCLOAK_HOSTNAME>          # plan
go run ./cmd/realm-apply -environment development -url https://<KEYCLOAK_HOSTNAME> -apply   # apply
```

The issuer is then `https://<KEYCLOAK_HOSTNAME>/realms/scnehaux`.

## Changing the realm

Change `realm/`, commit, and run `realm-apply -apply` again. A change made in the Admin
Console makes the next run refuse with exit code 2 and list what differs. Either revert
it in the console, or commit it to `realm/` and apply with `-adopt`. See the repository
README.

## Upgrading Keycloak

The image here must equal `image/keycloak.ref`, and CI fails when they differ. Upgrade
both together, only after `compat/` passes against the new digest. Then:

```sh
git pull && docker compose up -d --wait
```

Postgres keeps the realm, users, and keys across restarts and upgrades. Rollback past a
Keycloak database migration is not available. Back up the `postgres` volume before an
upgrade.
