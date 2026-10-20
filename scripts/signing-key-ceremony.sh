#!/usr/bin/env bash
# The realm signing-key ceremony (STD-IAM-001 2.9.0 §3.10, ADR-IAM-002 §5.3, TDD-identity-kernel-002
# 1.2.0 §Key Ceremony). docs/runbooks/signing-key-ceremony.md is its script; this is the step that
# makes the key.
#
#   scripts/signing-key-ceremony.sh <keys directory> <operator> <witness> <reason>
#
#   operator   the named member of the Identity Platform Team who runs it
#   witness    a second named member, never the operator; the run refuses one equal to the operator
#   reason     the change ticket the ceremony serves, where its record is kept
#
# On the development server the keys directory is deploy/dev/keys:
#
#   scripts/signing-key-ceremony.sh deploy/dev/keys "<operator>" "<witness>" "CHG-123"
#
# It makes the keystore inside the pinned upstream image, as root, with no network
# (scripts/signing-keystore.sh), reads the kid from its certificate with client-key from the
# realm-apply image, and writes the ceremony record beside the keys, as realm-signing.ceremony.json,
# and to standard output. The record holds no secret: the operator attaches it to the change ticket,
# and the third person reviews it there (the runbook, step 7). Names are given here, in a run on the
# server, and never in this public repository.
#
# It refuses a keys directory that already holds a keystore: a second key is a rotation, which is not
# built. It needs Docker and nothing else.
set -euo pipefail

usage="usage: signing-key-ceremony.sh <keys directory> <operator> <witness> <reason>"
keys="${1:?$usage}"
operator="${2:?$usage}"
witness="${3:?$usage}"
reason="${4:?$usage}"

refuse() {
	echo "signing-key-ceremony: refusing: $*" >&2
	exit 1
}
# The same person written twice differently is still one person: compared trimmed, case-folded, and
# with inner whitespace collapsed.
person() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//'; }
[ -n "$(person "$operator")" ] || refuse "the operator is empty"
[ -n "$(person "$witness")" ] || refuse "the witness is empty"
[ "$(person "$operator")" != "$(person "$witness")" ] ||
	refuse "the witness is the operator; two people run a ceremony (STD-IAM-001 §3.10)"
[ -n "$(printf '%s' "$reason" | tr -d '[:space:]')" ] || refuse "the reason is empty; name the change ticket"
for value in "$operator" "$witness" "$reason"; do
	case "$value" in *[\"\\]* | *$'\n'*) refuse "names and the reason are plain text, without quotes, backslashes or line breaks" ;; esac
done

root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$keys"
keys="$(cd "$keys" && pwd)"
upstream="$(grep -v '^[[:space:]]*#' "$root/image/keycloak.ref" | grep -v '^[[:space:]]*$' | head -n 1 | tr -d '[:space:]')"
printf '%s' "$upstream" | grep -Eq '@sha256:[0-9a-f]{64}$' || refuse "image/keycloak.ref does not pin a digest"

started_at="$(date -u +%FT%TZ)"
echo "ceremony: realm signing key, started $started_at"
echo "  operator  $operator"
echo "  witness   $witness"
echo "  reason    $reason"
echo "  generator $upstream"

echo "1. the keystore, made offline in the pinned image"
docker run --rm --network none --user 0:0 \
	-v "$keys:/keys" -v "$root/scripts/signing-keystore.sh:/opt/ceremony/signing-keystore.sh:ro" \
	--entrypoint /bin/bash "$upstream" /opt/ceremony/signing-keystore.sh /keys

echo "2. its kid, from the certificate"
tool="$(docker build -q -f "$root/deploy/dev/realm-apply.Dockerfile" "$root")"
kid="$(docker run --rm --network none -v "$keys/realm-signing.crt:/in/realm-signing.crt:ro" \
	--entrypoint client-key "$tool" kid -certificate /in/realm-signing.crt)"
finished_at="$(date -u +%FT%TZ)"

record="$(cat <<JSON
{
  "ceremony": "realm signing key",
  "standard": "STD-IAM-001 §3.10; ADR-IAM-002 §5.3",
  "realm": "scnehaux",
  "operator": "$operator",
  "witness": "$witness",
  "reason": "$reason",
  "started_at": "$started_at",
  "finished_at": "$finished_at",
  "host": "$(hostname)",
  "generator": "$upstream",
  "key": {"algorithm": "PS256", "type": "RSA", "bits": 3072, "kid": "$kid"},
  "certificate": "realm-signing.crt",
  "kept": "the keystore and its password stay in the keys directory and are never copied to a backup",
  "review": "pending: a third person, neither the operator nor the witness, reviews this record (STD-IAM-001 §3.10)"
}
JSON
)"
# Written through a container, as the keys are: the keys directory may belong to root.
printf '%s\n' "$record" | docker run --rm -i --network none --user 0:0 -v "$keys:/keys" --entrypoint /bin/bash \
	"$upstream" -c 'cat > /keys/realm-signing.ceremony.json.partial && chmod 0644 /keys/realm-signing.ceremony.json.partial &&
		mv /keys/realm-signing.ceremony.json.partial /keys/realm-signing.ceremony.json'
printf '%s\n' "$record"
echo "3. done: the kid is $kid. Next, the runbook's step 5: start the kernel, and the witness compares this kid"
echo "   with the one the key set publishes."
