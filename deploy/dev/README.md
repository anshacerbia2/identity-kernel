# Development server

This is a long-lived Keycloak for developing against from a local machine. It runs the
same pinned image that `compat/` asserts, in production mode (`start`) on Postgres, behind
Caddy for TLS. The realm is applied by `cmd/realm-apply`, which runs as a one-shot job on every `docker compose up`, the same tool CI uses.

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
docker compose up -d
docker compose logs realm-apply   # the plan it applied, ending in "applied revision ..."
./create-apply-client.sh          # optional: a service account for realm-apply, printed once
```

Every `docker compose up` runs the one-shot `realm-apply` job once Keycloak is healthy. It brings
the realm to `realm/` and exits. It runs as the bootstrap administrator, or as the service account
if `KEYCLOAK_ADMIN_CLIENT_ID` and `KEYCLOAK_ADMIN_CLIENT_SECRET` are put in `.env`.

To see a plan without changing anything, run from a clean checkout on your machine, from an
address in `ADMIN_ALLOW_CIDRS`:

```sh
go run ./cmd/realm-apply -environment development -url https://<KEYCLOAK_HOSTNAME>   # no -apply: read only
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
./tunnel-admin.sh                 # after every change to KEYCLOAK_ADMIN_URL
```

`tunnel-admin.sh` points the master realm's `frontendUrl` at `KEYCLOAK_ADMIN_URL` (default
`http://localhost:8081`). `KC_HOSTNAME_ADMIN` alone moves only the Admin Console. The master realm's
login page is still built from `KC_HOSTNAME`, so its form would post to the public port, where
`/realms/master` answers 404. The value lives in Keycloak's database and `realm-apply` does not manage the
master realm, so the script sets it from `.env`. The `scnehaux` issuer is unaffected.

**A persistent tunnel, with anonymous access on one port only.** Also on the server:

```sh
devtunnel user login -g -d                                # GitHub, device code
devtunnel create scnehaux-dev                              # persistent: the host, and so the issuer, survive restarts
devtunnel port create scnehaux-dev -p 8080 --protocol http
devtunnel port create scnehaux-dev -p 8081 --protocol http
devtunnel access create scnehaux-dev -p 8080 --anonymous   # -p is --port-number; --port is refused
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
- **Realm apply:** automatic on every `docker compose up`. For a read-only plan from your machine:
  `go run ./cmd/realm-apply -environment development -url http://localhost:8081`
- **Issuer for your apps:** `https://<KEYCLOAK_HOSTNAME>/realms/scnehaux`

The tunnel host is the issuer. If the tunnel is recreated under another host, every token and
every app's configuration changes with it. That is acceptable on a development server and one
more reason its issuer is never the production one.

CI brings this mode up too. It asserts the public issuer on port `8080`, that seven
administration paths answer `404` there, and that the console is served on port `8081` pointing
its login at that port.

## Other services on this server

A service that talks to Keycloak from the same host, such as `identity-control`'s Admin API client, joins the
external network `scnehaux-identity-api` and reaches Keycloak as `http://keycloak:8080`. It does not join
`internal`. Only Keycloak sits on `api`, so a joining service can reach Keycloak and nothing else in this
stack: not its Postgres, and not the proxy. Tokens it verifies still carry the public issuer, because
Keycloak's hostname fixes `iss` whichever address a request arrives on.

## Changing the realm

Change `realm/` and merge. Then, on the server, run `git pull` and `docker compose up -d`. The
`realm-apply` job applies the change, and `docker compose logs realm-apply` shows what it did.

A change made in the Admin Console makes the next job refuse, exiting 2 and changing nothing, with
the differences listed in its log. It is refused rather than overwritten, so someone looks at it.
Either revert it in the console and run `docker compose up -d` again, or commit it to `realm/` and
adopt it once:

```sh
docker compose run --rm realm-apply -environment=development -definition=/repo/realm \
  -url=http://keycloak:8080 -apply -adopt
```

See the repository README.

## Upgrading Keycloak

The image here must equal `image/keycloak.ref`, and CI fails when they differ. Upgrade
both together, only after `compat/` passes against the new digest. Then:

```sh
git pull && docker compose up -d --wait
```

Postgres keeps the realm, users, and keys across restarts and upgrades. Rollback past a
Keycloak database migration is not available. Back up the `postgres` volume before an
upgrade.
