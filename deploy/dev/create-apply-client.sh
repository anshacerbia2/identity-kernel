#!/usr/bin/env bash
# Creates the master-realm service account cmd/realm-apply authenticates as, and prints its secret
# once. Run on the server, beside compose.yaml, after the stack is up.
#
# A service account rather than the bootstrap administrator's password: its secret can be rotated
# without touching anyone's login, and it cannot log in to the console.
#
# It holds the master realm's admin role. That is as broad as the bootstrap administrator, and
# deliberately so for now: realm-apply creates the realm, and a narrower grant -- create-realm plus
# the scnehaux realm's management roles -- is a production-gate item, not a development one.
set -euo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./.env
set +a

client_id="${REALM_APPLY_CLIENT_ID:-realm-apply}"
secret="${REALM_APPLY_CLIENT_SECRET:-$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')}"

kcadm() {
	docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm.config
}

kcadm config credentials --server http://localhost:8080 --realm master \
	--user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null

if kcadm get clients -r master -q "clientId=$client_id" --fields id | grep -q '"id"'; then
	echo "create-apply-client: client $client_id already exists in the master realm; nothing created." >&2
	echo "To rotate its secret, regenerate it in the Admin Console or delete the client and rerun." >&2
	exit 1
fi

kcadm create clients -r master \
	-s "clientId=$client_id" \
	-s enabled=true \
	-s publicClient=false \
	-s serviceAccountsEnabled=true \
	-s standardFlowEnabled=false \
	-s directAccessGrantsEnabled=false \
	-s implicitFlowEnabled=false \
	-s "secret=$secret" >/dev/null
kcadm add-roles -r master --uusername "service-account-$client_id" --rolename admin

echo "KEYCLOAK_ADMIN_CLIENT_ID=$client_id"
echo "KEYCLOAK_ADMIN_CLIENT_SECRET=$secret"
