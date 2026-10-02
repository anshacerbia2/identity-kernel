#!/usr/bin/env bash
# Tunnel mode only: serves the master realm's login from the admin port, so administrators can
# log in. Run on the server, beside compose.yaml, after the stack is up. Rerun it whenever
# KEYCLOAK_ADMIN_URL changes; it is idempotent.
#
# Why it is needed. KC_HOSTNAME_ADMIN moves the Admin Console to the private port, but the master
# realm's login page is still built from KC_HOSTNAME -- the public host -- so the console's login
# form posts to /realms/master on the public port, where Caddyfile.tunnel refuses it with a 404.
# Setting the master realm's frontendUrl to the admin URL moves that realm's login and issuer to the
# private port. The scnehaux realm is untouched: its issuer stays on the public host.
#
# The value lives in Keycloak's database, not in this repository, and realm-apply does not manage
# the master realm. So it is set here, from .env, rather than in realm/.
set -euo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./.env
set +a

admin_url="${KEYCLOAK_ADMIN_URL:-http://localhost:8081}"

kcadm() {
	docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-tunnel.config
}

kcadm config credentials --server http://localhost:8080 --realm master \
	--user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null
kcadm update realms/master -s "attributes.frontendUrl=$admin_url"

echo "master realm login and issuer now served from $admin_url"
