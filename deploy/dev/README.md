# Development server

This is a long-lived Keycloak for developing against from a local machine. It runs the
same pinned image that `compat/` asserts, in production mode (`start`) on Postgres, behind
Caddy for TLS. The realm is applied by `cmd/realm-apply`, which runs as a one-shot job on every `docker compose up`, the same tool CI uses.

It is **development only**:

- `realm-apply` accepts `development` and refuses anything that serves real tokens,
  because the signing key is generated in-process.
- The issuer this server gets is not the production issuer.
- Nothing issued here is evidence of anything.

The sections below follow STD-GLB-009 §Development Server Deployment, in its order. The procedure
across the three stacks, and the order to start them in, is the architecture repository's
development server runbook (`docs/runbooks/dev-server.md`). This stack comes first.

## What runs

| Service | Image | Does |
| :-- | :-- | :-- |
| `postgres` | `postgres:17.11-alpine`, pinned by digest | Keycloak's database `keycloak`, owned by the role `keycloak`, in the volume `postgres` |
| `keycloak` | `scnehaux/identity-kernel:dev`, built from `image/Dockerfile`: the digest in `image/keycloak.ref` plus this repository's login theme | The kernel, in production mode (`start --optimized`) |
| `caddy` | `caddy:2.11.7-alpine`, pinned by digest | The TLS proxy, which keeps administration off the public internet |
| `realm-apply` | built from `realm-apply.Dockerfile` | A one-shot job on every `up`: brings the realm to `realm/` and exits |

### What is exposed

| Path | Reachable from |
| :-- | :-- |
| `/realms/scnehaux/...`: discovery, JWKS, token, login | anywhere |
| `/admin/...` (console and REST API), `/realms/master/...` | `ADMIN_ALLOW_CIDRS` only; everyone else gets `404` |
| management port `9000` (`/health/started`, `/health/live`, `/health/ready`, `/metrics`) | the container only: the healthcheck reads `/health/ready`; in production the orchestrator and monitoring reach it internally (TDD-005 1.5.0) |

CI brings this exact stack up on every change and asserts two things:

- The public issuer is served through the proxy.
- Administration answers `404` to an address outside the allowlist.

### Against the deployment standard

Every service on the server is deployed the way STD-GLB-009 §Development Server Deployment describes:
`git pull`, then `docker compose up -d --build`, in `deploy/dev`. This stack follows it, and differs
from the layout in these places, the first three because the service is a vendor kernel rather than a
Scnehaux service, the rest because the names and ports came before the standard:

- **No `migrate` target or `migrate.sh`.** Keycloak migrates its own database at start. The image is
  built from `image/`, pinned like every other base.
- **realm-apply runs on every `up`, not behind a profile.** It converges the realm to the definition
  at the recorded revision and refuses drift, so running it on every release is the point. It is the
  stack's one-off task in every other respect: a one-shot job on its own image.
- **Its callers' network is `scnehaux-identity-api`**, named before the standard's
  `scnehaux-<repository>-api` form, and joined by identity-control and organization-control as
  external. Renaming it would break both, for no change in what it carries.
- **Its project is `scnehaux-identity-dev`**, not `scnehaux-identity-kernel-dev`. The volumes belong to
  the project, so a renamed project would start with an empty database: no realm, no users, no keys.
  It keeps the name.
- **In DNS-name mode, Caddy publishes `80` and `443` on every interface**, because it is the public
  listener and obtains its certificate on port 80. It is the standard's one exception to loopback
  ports. Tunnel mode, which the development server runs, binds every port to `127.0.0.1`.
- **Its local file is listed in `COMPOSE_FILE` in tunnel mode.** Compose reads `compose.override.yaml`
  only when no file list is given, and tunnel mode gives one. See [A local override](#a-local-override).

## Before you start

This stack is the first on the server; no other stack must run before it. The host needs:

- **Server:** a Linux host with Docker and Compose v2. Every script here is `bash` and runs its tools
  in a container, so the host needs Docker and nothing else for this stack. `pwsh` is not needed here.
- **Ports:** 80 and 443 open. Caddy uses port 80 to obtain the certificate.
- **DNS:** a DNS name pointing at the host.

Behind a dev tunnel, the last two do not apply. The host needs the devtunnel CLI instead, logged in
with the account that will own the tunnel (see [Behind a dev tunnel instead of a DNS name](#behind-a-dev-tunnel-instead-of-a-dns-name)).

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
the bootstrap administrator. The keys and the scripts that make them are under [Keys](#keys).

The issuer is then `https://<KEYCLOAK_HOSTNAME>/realms/scnehaux`. The service is ready when its
discovery document answers:
`curl -fsS https://<KEYCLOAK_HOSTNAME>/realms/scnehaux/.well-known/openid-configuration`.

### Behind a dev tunnel instead of a DNS name

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

**Or set the file list once, in `.env`.** `COMPOSE_FILE` names the files compose reads, so every later
command is plain `docker compose`, the same as on every other stack:

```sh
# .env, as .env.example shows; list compose.local.yaml only once it exists (A local override, below)
COMPOSE_FILE=compose.yaml:compose.tunnel.yaml:compose.local.yaml
```

```sh
docker compose up -d --wait
```

With `COMPOSE_FILE` set, never add `-f`. A `-f` on the command line replaces the whole list, so the
command runs without the local file and the subnet pins it holds.

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

The tunnel's mistakes to avoid are under [Never do](#never-do).

A persistent tunnel still expires after a period without hosting. Keep `devtunnel host` running
under a service manager such as systemd.

From your machine:

```sh
devtunnel user login -g           # the same account that owns the tunnel
devtunnel connect scnehaux-dev    # forwards 8080 and 8081 to localhost; keep it running
```

- **Admin Console:** `http://localhost:8081/admin`, or the tunnel's own URL for port 8081 in a browser (devtunnel asks for the owner's GitHub login), after setting `KEYCLOAK_ADMIN_URL` to that URL in `.env`
- **Realm apply:** automatic on every `docker compose up`. For a read-only plan, see [One-off tasks](#one-off-tasks).
- **Issuer for your apps:** `https://<KEYCLOAK_HOSTNAME>/realms/scnehaux`

The tunnel host is the issuer. If the tunnel is recreated under another host, every token and
every app's configuration changes with it. That is acceptable on a development server and one
more reason its issuer is never the production one.

CI brings this mode up too. It asserts the public issuer on port `8080`, that seven
administration paths answer `404` there, and that the console is served on port `8081` pointing
its login at that port.

### A local override

A server's own changes are never committed (STD-GLB-009 rule 4). `compose.override.example.yaml`
shows the one this stack has needed: subnet pins for `internal` and `scnehaux-identity-api`, for a
host whose networks overlap Docker's default address pools. Copy what applies:

- **DNS-name mode:** to `compose.override.yaml`. Compose reads it beside `compose.yaml` when no file
  list is given.
- **Tunnel mode:** to `compose.local.yaml`, listed last in `COMPOSE_FILE` in `.env`, as above. The
  development server keeps its pins there.

Both names are gitignored. A network's subnet is fixed when the network is created, so a new pin
takes effect only on a network created after it: on a first start, or after the reset from zero in
the runbook.

## Updating

```sh
git pull && docker compose up -d --build --wait
docker compose logs realm-apply   # ends in "applied revision ..."
```

`--build` rebuilds the kernel image and the realm-apply image from the checkout. The `realm-apply`
job then applies the realm at the new revision. Behind a tunnel without `COMPOSE_FILE` in `.env`,
give both files: `docker compose -f compose.yaml -f compose.tunnel.yaml up -d --build --wait`.

### Changing the realm

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

### Upgrading Keycloak

The kernel image is built from `image/Dockerfile`: the upstream digest, which must equal
`image/keycloak.ref` (CI fails when they differ), plus this repository's login theme. `docker compose
up -d --build` rebuilds it. Upgrade
both together, only after `compat/` passes against the new digest and the `upgrade` job has
written its release record, which says whether the previous release still starts on the
migrated database (TDD-identity-kernel-005 §Determining the Rollback Boundary). Then:

```sh
git pull && docker compose up -d --build --wait
```

Postgres keeps the realm, users, and keys across restarts and upgrades. Back up the
`postgres` volume before an upgrade either way ([Backups](#backups)). Redeploying the previous image is a recovery
only when the release record says `reversible`; when it says `irreversible-after-start`, the
recovery is restoring that backup.

## One-off tasks

No task here sits behind a profile. The stack's one-off task, `realm-apply`, runs on every `up`
([What runs](#what-runs)). Two forms of it are run by hand.

**A read-only plan.** To see a plan without changing anything, run the job on the server without `-apply`:

```sh
docker compose run --rm realm-apply -environment=development -definition=/repo/realm -url=http://keycloak:8080
```

It runs in the container because it authenticates as the service account, whose key
`./keys/realm-apply.pem` is readable by the container's user (65534) alone. That key never leaves the
server, so a laptop has no credential for this. `go run ./cmd/realm-apply` from a host works only
against a throwaway instance, as the bootstrap administrator.

**Adopting console drift**, once, with `-apply -adopt`: see [Changing the realm](#changing-the-realm).

The scripts beside `compose.yaml` are one-time steps, not tasks: `new-client-key.sh`,
`create-apply-client.sh` and `set-client-key.sh` are under [Keys](#keys), and `tunnel-admin.sh` under
[Behind a dev tunnel instead of a DNS name](#behind-a-dev-tunnel-instead-of-a-dns-name).

## Wiring to other services

This stack creates the network `scnehaux-identity-api` and joins no other stack's network.

A service that talks to Keycloak from the same host, such as `identity-control`'s Admin API client, joins the
external network `scnehaux-identity-api` and reaches Keycloak as `http://keycloak:8080`. It does not join
`internal`. Only Keycloak sits on `api`, so a joining service can reach Keycloak and nothing else in this
stack: not its Postgres, and not the proxy. Tokens it verifies still carry the public issuer, because
Keycloak's hostname fixes `iss` whichever address a request arrives on.

The other stacks' clients are made by their own scripts, which use this checkout's key tools:
identity-control's `create-kernel-clients.sh` and `create-registration-client.sh` read this directory
from `KERNEL_DEPLOY_DIR` in identity-control's `.env`.
Nothing is run here for the wiring.

## Keys

**No client here holds a client secret** (`STD-IAM-001 §3.2`). Every confidential client on this
server authenticates with its own key by signed JWT. That covers realm-apply's account,
identity-control's clients, and the Identity Experience BFF. Two scripts manage the keys, and both
run `client-key` from the realm-apply image, so the host needs Docker only:

| Script | Does |
| :-- | :-- |
| `./new-client-key.sh NAME [DIR] [OWNER]` | Makes `DIR/NAME.pem`, mode 0600 and owned by the container user that signs with it, and `DIR/NAME.jwk.json`, its public half. It never overwrites a key. |
| `./set-client-key.sh REALM CLIENT JWK [JWK]` | Sets an existing client to authenticate with exactly those public keys, two during a rotation. It regenerates the client's old secret without printing it. |

`create-apply-client.sh` makes realm-apply's master-realm service account from
`keys/realm-apply.jwk.json`, and refuses when the account exists.

| Key | Made by | Lives in | Owned by |
| :-- | :-- | :-- | :-- |
| realm-apply's service account | `./new-client-key.sh realm-apply` | `./keys/realm-apply.pem`, gitignored | 65534, the realm-apply container's user, mode 0600 |
| identity-control's clients | identity-control's scripts, with this `new-client-key.sh` | identity-control's `deploy/dev/keys` | 65532, identity-control's distroless user |
| a BFF's client | the developer, on the laptop (`scripts/new-client-key.mjs`) | the laptop; only the public JWK reaches the server | the developer |

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

**A client identity-control has registered or adopted** has its keys in its registration. Its keys
change through identity-control (`POST /v1/registrations/{registration_id}/keys`), not through
`set-client-key.sh`: a key the registration does not declare is a difference identity-control reports.

## Backups

The database holds the realm, its users, their credentials and the realm's signing keys. Back it up
daily to storage outside the Docker volume, and before every Keycloak upgrade. The dumps are made in
the container, as the role `keycloak`, over its local socket, so no password is typed:

```sh
cd identity-kernel/deploy/dev
dir=/path/outside/docker/identity-kernel/$(date +%F)    # another disk; readable by the operator alone
mkdir -p "$dir" && chmod 700 "$dir"
docker compose exec -T postgres pg_dump -U keycloak -d keycloak -Fc > "$dir/keycloak.dump"
docker compose exec -T postgres pg_dumpall -U keycloak --globals-only > "$dir/globals.sql"
cp .env "$dir/"
sudo cp -a keys "$dir/"    # the private keys belong to container users, mode 0600
```

The same dump, daily, from the operator's crontab (`%` is escaped in a crontab line):

```text
30 2 * * * cd /path/to/identity-kernel/deploy/dev && docker compose exec -T postgres pg_dump -U keycloak -d keycloak -Fc > /path/outside/docker/identity-kernel/keycloak-$(date +\%F).dump
```

The dumps hold password hashes, and the copies hold `.env` and the keys, so the backup directory is
kept like `.env`: readable by the operator alone.

**Restoring.** Put `.env` and `keys/` back first, then:

```sh
docker compose up -d postgres
docker compose exec -T postgres psql -U keycloak -d postgres < "$dir/globals.sql"   # "role keycloak already exists" is expected
docker compose exec -T postgres pg_restore -U keycloak -d keycloak --clean --if-exists < "$dir/keycloak.dump"
docker compose up -d --build --wait
```

**`docker compose down -v` deletes the database.** It removes the named volumes `postgres`,
`caddy-data` and `caddy-config`, and a backup made into a volume goes with them.

## Never do

- **`docker compose down -v`**, except in the deliberate reset from zero the runbook describes, which
  starts with a backup. It deletes the realm, every user and credential, and the realm's signing keys,
  so every token and every client key installed here is gone. Take identity-control and
  organization-control down first: they join `scnehaux-identity-api`.
- **Rename the project or the network.** A new project name starts with an empty database; a new
  network name strands identity-control and organization-control ([What runs](#what-runs)).
- **Pass `-f` when `.env` sets `COMPOSE_FILE`.** The command then runs without the local file.
- **Rerun `new-client-key.sh` or `create-apply-client.sh` to replace something.** Both refuse when their
  output exists. Replacing a key is a rotation ([Keys](#keys)).
- **Change the realm in the Admin Console and expect it to stay.** The next `up` refuses it
  ([Changing the realm](#changing-the-realm)).

Five mistakes to avoid in tunnel mode:

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

## Troubleshooting

| Symptom | Cause | Fix |
| :-- | :-- | :-- |
| A browser sign-in through the tunnel fails with `403` "Invalid origin" | The tunnel port rewrites the browser's `Origin` | `--origin-header unchanged` on that port. It is a per-port setting, made with `devtunnel port create` or `devtunnel port update`, not a flag of `devtunnel host` |
| `devtunnel access create ... --port 8080` is refused | The CLI on the server takes `-p` or `--port-number` | `devtunnel access create <tunnel> -p 8080 --anonymous` |
| The Admin Console's login answers `404` in tunnel mode | The master realm's login form posts to the public port | `./tunnel-admin.sh`, after every change to `KEYCLOAK_ADMIN_URL` |
| A login answers "Restart login cookie not found" | It started on another host than Keycloak's fixed hostname, such as `http://127.0.0.1:8081`, so the form's post went to the public origin without the cookie | Sign in to `scnehaux` on the public origin, and to the Admin Console on `KEYCLOAK_ADMIN_URL` exactly. Laptop callbacks use `127.0.0.1`, not `localhost` |
| The browser returns to Keycloak instead of a laptop app | The app runs on a forwarded port number, and the tunnel rewrote its redirect | Run the app on a port the tunnel does not forward ([Never do](#never-do)) |
| Every endpoint answers `403` "HTTPS required" | The realm's `sslRequired` was set to `none` and Keycloak reached over plain HTTP | TLS in front of Keycloak; keep `external` ([Never do](#never-do)) |
| The public issuer stops answering while `devtunnel host` still runs | The host lost its relay and failed its token refresh without exiting, so systemd sees it active | Restart the host service. A timer that requests the public discovery URL and restarts it catches this (runbook, step 1) |
| `realm-apply` exits 2 and lists differences | Console drift | Revert it, or commit it and adopt it once ([Changing the realm](#changing-the-realm)) |
| Every apply is refused with "scnehaux.json must set eventsEnabled true", on a realm applied at an older revision | realm-apply parsed the recorded baseline by today's policy | Fixed in identity-kernel#58: `git pull && docker compose up -d --build` |
| A setting in `.env` has no effect | Compose passes a container only the variables `compose.yaml` lists | Check `compose.yaml` for it. Behind a tunnel, check the command used the tunnel file (`COMPOSE_FILE`, or `-f compose.yaml -f compose.tunnel.yaml`) |
| Containers cannot reach a host network, or a VPN drops, after `up` | A Docker network took a range the host uses | Pin the subnets ([A local override](#a-local-override)) |
| An account cannot sign in after failed passwords | Brute-force detection locked it; see below | Below |

**Account lockout.**

- _What was seen:_ the server locked an account permanently after 10 failed logins.
- _Why:_ that realm was last applied at `6beb86d`, whose definition declared no brute-force settings
  at all. The behaviour came from settings the definition did not declare, made in the console or left
  from earlier.
- _What applies on a current definition_ (`realm/scnehaux.json`, TDD-identity-kernel-001 §Guessing
  Limits): the 10th consecutive failure brings the first **temporary** lockout (`failureFactor` 10).
  The wait grows by `waitIncrementSeconds` 60 up to `maxFailureWaitSeconds` 900 (strategy
  `MULTIPLE`). After `maxTemporaryLockouts` 90 temporary lockouts, the 100th consecutive failure
  brings a **permanent** lockout.
- _To release a lock:_ a permanent lockout disables the user. Enable the user again, in the Admin
  Console or through identity-control's assisted recovery (suspend, revoke any lost factor, restore).
  A temporary lockout ends when its wait runs out. Keycloak keeps the failure counts in memory, so a
  restart also clears them.
