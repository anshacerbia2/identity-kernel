#!/usr/bin/env bash
# Creates the master-realm service account cmd/realm-apply authenticates as. Run it on the server,
# beside compose.yaml, after the stack is up and after ./new-client-key.sh realm-apply has made the
# key it authenticates with.
#
# A service account rather than the bootstrap administrator's password: it cannot log in to the
# console, and its key can be rotated without touching anyone's login. It authenticates with its
# own key by signed JWT, never a client secret (STD-IAM-001 §3.2). The private key stays in ./keys
# on this host, and the kernel is given only the public half.
#
# It holds the master realm's admin role. That is as broad as the bootstrap administrator, and
# deliberately so for now: realm-apply creates the realm, and a narrower grant -- create-realm plus
# the scnehaux realm's management roles -- is a production-gate item, not a development one.
#
# An account that already exists is left alone. To move an existing account from a secret to a key,
# or to rotate its key, use ./set-client-key.sh master realm-apply keys/realm-apply.jwk.json.
set -euo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./.env
set +a

client_id="${REALM_APPLY_CLIENT_ID:-realm-apply}"
jwk="keys/$client_id.jwk.json"
[ -f "$jwk" ] || { echo "create-apply-client: $jwk is missing; run ./new-client-key.sh $client_id first" >&2; exit 1; }

kcadm() {
	docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm.config
}

kcadm config credentials --server http://localhost:8080 --realm master \
	--user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null

if kcadm get clients -r master -q "clientId=$client_id" --fields id | grep -q '"id"'; then
	echo "create-apply-client: client $client_id already exists in the master realm; nothing created." >&2
	echo "To give it a key, or rotate its key: ./set-client-key.sh master $client_id $jwk" >&2
	exit 1
fi

kcadm create clients -r master \
	-s "clientId=$client_id" \
	-s enabled=true \
	-s publicClient=false \
	-s clientAuthenticatorType=client-jwt \
	-s serviceAccountsEnabled=true \
	-s standardFlowEnabled=false \
	-s directAccessGrantsEnabled=false \
	-s implicitFlowEnabled=false >/dev/null
kcadm add-roles -r master --uusername "service-account-$client_id" --rolename admin

# The key is installed by the same tool every client uses, which also regenerates, unprinted, the
# secret Keycloak gave the new client by default.
./set-client-key.sh master "$client_id" "$jwk"

# stdout carries only the .env line, so it can be appended or sourced as it is.
echo "Put this in .env, then docker compose up -d:" >&2
echo "KEYCLOAK_ADMIN_CLIENT_ID=$client_id"
