#!/usr/bin/env bash
# Makes one realm signing keystore and names it by its kid (TDD-identity-kernel-002 1.5.0 §Custody as
# Built, ADR-IAM-002 §5.5 Q3), and prints the kid. The two halves of every key's making, shared by the
# ceremony (scripts/signing-key-ceremony.sh) and a test run's throwaway key:
#
#   1. scripts/signing-keystore.sh in the pinned upstream image, as root, with no network: the keystore
#      is written by the JDK that reads it, into <keys>/new;
#   2. `signing-key place` in the realm-apply image, as root, with no network: the kid is computed from
#      the certificate and the three files are moved to realm-signing-<kid>.
#
#   scripts/signing-key-generate.sh <keys directory>
#
# It needs Docker and nothing else.
set -euo pipefail

keys="${1:?usage: signing-key-generate.sh <keys directory>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$keys"
keys="$(cd "$keys" && pwd)"
upstream="$(grep -v '^[[:space:]]*#' "$root/image/keycloak.ref" | grep -v '^[[:space:]]*$' | head -n 1 | tr -d '[:space:]')"
printf '%s' "$upstream" | grep -Eq '@sha256:[0-9a-f]{64}$' || { echo "image/keycloak.ref does not pin a digest" >&2; exit 1; }

docker run --rm --network none --user 0:0 \
	-v "$keys:/keys" -v "$root/scripts/signing-keystore.sh:/opt/ceremony/signing-keystore.sh:ro" \
	--entrypoint /bin/bash "$upstream" /opt/ceremony/signing-keystore.sh /keys >&2
tool="$(docker build -q -f "$root/deploy/dev/realm-apply.Dockerfile" "$root")"
docker run --rm --network none --user 0:0 -v "$keys:/keys" --entrypoint signing-key "$tool" place -keys /keys
