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

## Behind a dev tunnel instead of a DNS name

A tunnel terminates TLS itself and delivers every request from the same agent. So the
DNS-name setup above does not fit a tunnel:

- Caddy cannot obtain a certificate for the tunnel's host.
- The address allowlist cannot tell one client from another.
- A tunnel pointed straight at Keycloak exposes the Admin Console to anyone holding the URL.

Tunnel mode therefore splits the two audiences across two loopback ports:

| Server port | Serves | Tunnel access |
| :-- | :-- | :-- |
| `8080` | Caddy → Keycloak, with `/admin` and `/realms/master` answering `404` to everyone | **anonymous**: your local apps and anything else use this |
| `8081` | Keycloak directly, including the Admin Console | **owner only**: reached as `localhost:8081` through `devtunnel connect` |

Start the stack on the server:

```sh
cd identity-kernel/deploy/dev
# .env: KEYCLOAK_HOSTNAME is the tunnel host for port 8080, without https://, for example
#   KEYCLOAK_HOSTNAME=gqr8l4jz-8080.asse.devtunnels.ms
# ADMIN_ALLOW_CIDRS is unused in this mode; leave any value, e.g. 127.0.0.1/32
docker compose -f compose.yaml -f compose.tunnel.yaml up -d --wait
./create-apply-client.sh          # once
```

**A persistent tunnel, with anonymous access on one port only.** Also on the server:

```sh
devtunnel user login -g -d                                # GitHub, device code
devtunnel create scnehaux-dev                              # persistent: the host, and so the issuer, survive restarts
devtunnel port create scnehaux-dev -p 8080 --protocol http
devtunnel port create scnehaux-dev -p 8081 --protocol http
devtunnel access create scnehaux-dev --port 8080 --anonymous
devtunnel host scnehaux-dev                               # prints the https URL for each port
```

Three mistakes to avoid:

- **`devtunnel host -p 8080 --allow-anonymous` creates a temporary tunnel.** Its ID, and
  therefore the issuer, is new every time the command restarts.
- **`devtunnel create -a` makes every port anonymous, 8081 included.** Anonymous access must
  be granted per port, as above.
- **Check an existing tunnel for tunnel-wide anonymous access** with
  `devtunnel access list <id>`. If it has it, clear it with `devtunnel access reset <id>`
  before granting port 8080.

A persistent tunnel still expires after a period without hosting. Keep `devtunnel host` running
under a service manager such as systemd.

From your machine:

```sh
devtunnel user login -g           # the same account that owns the tunnel
devtunnel connect scnehaux-dev    # forwards 8080 and 8081 to localhost; keep it running
```

- **Admin Console:** `http://localhost:8081/admin`, or the tunnel's own URL for port 8081 in a browser (devtunnel asks for the owner's GitHub login), after setting `KEYCLOAK_ADMIN_URL` to that URL in `.env`
- **Realm apply:** `go run ./cmd/realm-apply -environment development -url http://localhost:8081 -apply`
- **Issuer for your apps:** `https://<KEYCLOAK_HOSTNAME>/realms/scnehaux`

The tunnel host is the issuer. If the tunnel is recreated under another host, every token and
every app's configuration changes with it. That is acceptable on a development server and one
more reason its issuer is never the production one.

CI brings this mode up too. It asserts the public issuer on port `8080`, that seven
administration paths answer `404` there, and that the console is served on port `8081` pointing
its login at that port.

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
