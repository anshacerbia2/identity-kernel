#!/usr/bin/env bash
# Makes a client key pair on this host: DIR/NAME.pem, the private key, and DIR/NAME.jwk.json, its
# public half. Only the JWK ever leaves this host (ADR-IAM-001 §5.12).
#
#   ./new-client-key.sh realm-apply                                    # ./keys, owned by realm-apply's user
#   ./new-client-key.sh identity-control /srv/identity-control/deploy/dev/keys 65532:65532
#
# OWNER is the UID:GID of the container that signs with the key. The private key is mode 0600 and
# belongs to that user alone. realm-apply runs as 65534, and identity-control's distroless image as
# 65532. The key is made by client-key, which ships in the realm-apply image, so the host needs
# Docker and nothing else. The tool refuses to overwrite a key: replacing one is a rotation.
set -euo pipefail
cd "$(dirname "$0")"

name="${1:?usage: new-client-key.sh NAME [DIR] [OWNER]}"
dir="$(mkdir -p "${2:-./keys}" && cd "${2:-./keys}" && pwd)"
owner="${3:-65534:65534}"

docker compose build -q realm-apply
docker compose run --rm --no-deps --user 0:0 -v "$dir:/out" --entrypoint client-key realm-apply \
	new -out "/out/$name.pem" -owner "$owner"
echo "The public JWK is $dir/$name.jwk.json. Install it with ./set-client-key.sh."
