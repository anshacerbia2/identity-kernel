# Development server

This is a long-lived Keycloak for developing against from a local machine. It runs the
same pinned image that `compat/` asserts, in production mode (`start`) on Postgres, behind
Caddy for TLS. The realm is applied by `cmd/realm-apply`, which runs as a one-shot job on every `docker compose up`, the same tool CI uses.

It is **development only**:

- `realm-apply` accepts `development` and refuses anything that serves real tokens,
  because the signing key is generated in-process.
- The issuer this server gets is not the production issuer.
- Nothing issued here is evidence of anything.

## Against the deployment standard

Every service on the server is deployed the way STD-GLB-009 §Development Server Deployment describes:
`git pull`, then `docker compose up -d --build`, in `deploy/dev`. This stack follows it, and differs
from the layout in three places, each because the service is a vendor kernel rather than a Scnehaux
service:

- **No `migrate` target or `migrate.sh`.** Keycloak migrates its own database at start. The image is
  built from `image/`, pinned like every other base.
- **realm-apply runs on every `up`, not behind a profile.** It converges the realm to the definition
  at the recorded revision and refuses drift, so running it on every release is the point. It is the
  stack's one-off task in every other respect: a one-shot job on its own image.
- **Its callers' network is `scnehaux-identity-api`**, named before the standard's
  `scnehaux-<repository>-api` form, and joined by identity-control and organization-control as
  external. Renaming it would break both, for no change in what it carries.

## What is exposed

| Path | Reachable from |
| :-- | :-- |
| `/realms/scnehaux/...`: discovery, JWKS, token, login | anywhere |
| `/admin/...` (console and REST API), `/realms/master/...` | `ADMIN_ALLOW_CIDRS` only; everyone else gets `404` |
| management port `9000` (`/health/started`, `/health/live`, `/health/ready`, `/metrics`) | the container only: the healthcheck reads `/health/ready`; in production the orchestrator and monitoring reach it internally (TDD-005 1.5.0) |

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
./new-client-key.sh realm-apply   # the service account's key pair, in ./keys; the private key stays here
./create-apply-client.sh          # the service account, authenticating with that key; then set
                                  # KEYCLOAK_ADMIN_CLIENT_ID in .env and docker compose up -d again
```

Every `docker compose up` runs the one-shot `realm-apply` job once Keycloak is healthy. It brings
the realm to `realm/` and exits. It runs as the service account once `KEYCLOAK_ADMIN_CLIENT_ID` is
in `.env`, signing with `./keys/<that id>.pem`. Until then, on the first start only, it runs as
the bootstrap administrator.

**No client here holds a client secret** (`STD-IAM-001 §3.2`). Every confidential client on this
server authenticates with its own key by signed JWT. That covers realm-apply's account,
identity-control's clients, and the Identity Experience BFF. Two scripts manage the keys, and both
run `client-key` from the realm-apply image, so the host needs Docker only:

| Script | Does |
| :-- | :-- |
| `./new-client-key.sh NAME [DIR] [OWNER]` | Makes `DIR/NAME.pem`, mode 0600 and owned by the container user that signs with it, and `DIR/NAME.jwk.json`, its public half. It never overwrites a key. |
| `./set-client-key.sh REALM CLIENT JWK [JWK]` | Sets an existing client to authenticate with exactly those public keys, two during a rotation. It regenerates the client's old secret without printing it. |

**Moving an existing client from a secret to a key.** This applies to a server set up before keys:

1. Make the key where the client runs.
2. Run `./set-client-key.sh`.
3. Point the client at its key and restart it.

The client cannot authenticate between steps 2 and 3, so run them together. For realm-apply:

```sh
./new-client-key.sh realm-apply
./set-client-key.sh master realm-apply keys/realm-apply.jwk.json
# .env: keep KEYCLOAK_ADMIN_CLIENT_ID=realm-apply, delete KEYCLOAK_ADMIN_CLIENT_SECRET
docker compose up -d
```

**Rotating a key.** Make the new pair and install both public keys, so the old and the new key
are accepted together. Move the client to the new private key. Then install the new public key
alone.

To see a plan without changing anything, run the job on the server without `-apply`:

```sh
docker compose run --rm realm-apply -environment=development -definition=/repo/realm -url=http://keycloak:8080
```

It runs in the container because it authenticates as the service account, whose key
`./keys/realm-apply.pem` is readable by the container's user (65534) alone. That key never leaves the
server. `go run ./cmd/realm-apply` from a host works only against a throwaway instance, as the
bootstrap administrator.

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
devtunnel port create scnehaux-dev -p 8080 --protocol http --origin-header unchanged
devtunnel port create scnehaux-dev -p 8081 --protocol http --origin-header unchanged
devtunnel access create scnehaux-dev -p 8080 --anonymous   # -p is --port-number; --port is refused
devtunnel host scnehaux-dev                               # prints the https URL for each port
```

**`--origin-header unchanged` is required on every port a browser reaches.** By default devtunnel
replaces a browser's `Origin` with `http(s)://localhost`. Keycloak compares that origin with the
client's web origins, so every browser application that signs in through the tunnel fails with
`Invalid origin`: the Account Console, the Admin Console, and any BFF or SPA served on a tunnel
port. For a port that already exists:

```sh
devtunnel port update scnehaux-dev -p 8080 --origin-header unchanged
devtunnel port update scnehaux-dev -p 8081 --origin-header unchanged
```

devtunnel rewrites `Host` to `localhost` by default as well. Keycloak is unaffected: behind port
8080, Caddy states the public host in `X-Forwarded-Host`, and `KC_HOSTNAME` fixes the issuer. An
application served on a tunnel port without such a proxy, one that checks its own host, also needs
`--host-header unchanged`. The Identity Experience BFF is one: it answers only on its public
origin's host. A port reached only from code, such as a database or an API behind a BFF, needs
neither flag.

Five mistakes to avoid:

- **Do not set the realm's `sslRequired` to `none`.** `realm/` declares `external`, and it holds
  in both modes. Keycloak judges whether a request is secure by the scheme of `KC_HOSTNAME`,
  which is `https://` behind a DNS name and behind a tunnel alike, so every request passes. The
  dev server once ran a local `none`. Its Keycloak was then reached over plain HTTP on Tailscale,
  with `KC_HOSTNAME=http://…`. `external` exempts only RFC 1918 addresses, and Tailscale's
  100.64.0.0/10 is not one of them, so every endpoint answered 403 "HTTPS required".
  - The fix is TLS in front of Keycloak, as both modes here provide, not a realm that accepts
    plain HTTP from anywhere.
  - On 2026-09-30 the realm ran with `external` behind the tunnel. The public token endpoint, the
    private port, and the private port with forged `X-Forwarded-For` and `X-Forwarded-Proto` all
    passed the check, and a full login succeeded. The local `none` was then removed.
- **`devtunnel host -p 8080 --allow-anonymous` creates a temporary tunnel.** Its ID, and
  therefore the issuer, is new every time the command restarts.
- **`devtunnel create -a` makes every port anonymous, 8081 included.** Anonymous access must
  be granted per port, as above.
- **Check an existing tunnel for tunnel-wide anonymous access** with
  `devtunnel access list <id>`. If it has it, clear it with `devtunnel access reset <id>`
  before granting port 8080.
- **Do not run a local app on a forwarded port number.** A laptop app redirected to
  `http://localhost:8080/...` has the redirect rewritten to the tunnel's own URL, so the browser
  lands back on Keycloak rather than on the app. Identity Experience's BFF runs on
  `127.0.0.1:8090` for this reason (its `scripts/dev-local.ps1`).

A persistent tunnel still expires after a period without hosting. Keep `devtunnel host` running
under a service manager such as systemd.

From your machine:

```sh
devtunnel user login -g           # the same account that owns the tunnel
devtunnel connect scnehaux-dev    # forwards 8080 and 8081 to localhost; keep it running
```

- **Admin Console:** `http://localhost:8081/admin`, or the tunnel's own URL for port 8081 in a browser (devtunnel asks for the owner's GitHub login), after setting `KEYCLOAK_ADMIN_URL` to that URL in `.env`
- **Realm apply:** automatic on every `docker compose up`. For a read-only plan, run it on the
  server, in its container:
  `docker compose run --rm realm-apply -environment=development -definition=/repo/realm -url=http://keycloak:8080`.
  Leaving out `-apply` makes it read only. It must run in the container, because the service account's key,
  `./keys/realm-apply.pem`, belongs to the container's user (65534) and no other process can read
  it. The key never leaves the server, so a laptop has no credential for this.
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

The kernel image is built from `image/Dockerfile`: the upstream digest, which must equal
`image/keycloak.ref` (CI fails when they differ), plus this repository's login theme. `docker compose
up -d --build` rebuilds it. Upgrade
both together, only after `compat/` passes against the new digest and the `upgrade` job has
written its release record, which says whether the previous release still starts on the
migrated database (TDD-identity-kernel-005 §Determining the Rollback Boundary). Then:

```sh
git pull && docker compose up -d --wait
```

Postgres keeps the realm, users, and keys across restarts and upgrades. Back up the
`postgres` volume before an upgrade either way. Redeploying the previous image is a recovery
only when the release record says `reversible`; when it says `irreversible-after-start`, the
recovery is restoring that backup.
