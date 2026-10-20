#!/usr/bin/env bash
# Sets a client to authenticate by signed JWT with exactly the public keys given (ADR-IAM-001
# §5.12). Give one JWK. Give two only for a rotation's overlap: the old and the new key of one
# registration, while its deployable moves to the new one. Never two devices' keys: each device that
# runs a BFF has a registration of its own, such as identity-experience-bff-<device>, with its own key,
# so a lost laptop is suspended without touching the other (STD-GLB-009 1.10.0 rule 15, ADR-IAM-001
# §5.12). It then regenerates the client's secret without printing it, so a secret the client held
# before stops working.
#
#   ./set-client-key.sh master realm-apply keys/realm-apply.jwk.json
#   ./set-client-key.sh scnehaux identity-control /path/identity-control.jwk.json
#   ./set-client-key.sh scnehaux identity-experience-bff bff-old.jwk.json bff-new.jwk.json   # a rotation
#
# It works on a client that already exists. It creates nothing and touches no other client. It
# authenticates as the bootstrap administrator, as the kernel's other one-time scripts do, so it
# still works when the key it replaces is the one realm-apply itself signs with.
set -euo pipefail
cd "$(dirname "$0")"

realm="${1:?usage: set-client-key.sh REALM CLIENT JWK [JWK]}"
client="${2:?usage: set-client-key.sh REALM CLIENT JWK [JWK]}"
shift 2
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || {
	echo "set-client-key: give one JWK file, or two for one registration's rotation; a second device registers its own client" >&2
	exit 1
}

mounts=()
flags=()
i=0
for jwk in "$@"; do
	path="$(cd "$(dirname "$jwk")" && pwd)/$(basename "$jwk")"
	mounts+=(-v "$path:/in/$i.jwk.json:ro")
	flags+=(-jwk "/in/$i.jwk.json")
	i=$((i + 1))
done

# --no-deps: the running Keycloak is used as it is. Without it, a run from this compose file alone
# could recreate a Keycloak started with an override file, such as tunnel mode's.
docker compose build -q realm-apply
docker compose run --rm --no-deps "${mounts[@]}" -e KEYCLOAK_ADMIN_CLIENT_ID= --entrypoint client-key realm-apply \
	install -url http://keycloak:8080 -realm "$realm" -client "$client" "${flags[@]}"
