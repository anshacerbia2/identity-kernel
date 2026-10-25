#!/usr/bin/env bash
# The realm signing-key ceremony (STD-IAM-001 2.9.0 §3.10, ADR-IAM-002 §5.3 and §5.5,
# TDD-identity-kernel-002 1.5.0 §Key Ceremony). docs/runbooks/signing-key-ceremony.md is its script;
# this is the step that makes a key. Every key is made so: the realm's first, and each one a rotation
# stages after it.
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
# It makes the keystore in the pinned upstream image, as root, with no network, and names it by its kid
# in the realm-apply image (scripts/signing-key-generate.sh): signing/realm-signing-<kid>.p12, its
# password vault/scnehaux_realm-signing-<kid> (underscores doubled) and its certificate
# realm-signing-<kid>.crt. It writes the ceremony record beside them, realm-signing-<kid>.ceremony.json,
# and to standard output. The record holds no secret: the operator attaches it to the change ticket,
# and the third person reviews it there (the runbook, step 7). Names are given here, in a run on the
# server, and never in this public repository.
#
# The key is in custody and signs nothing until a step puts it in the realm: realm-apply makes the
# first key active on an empty realm, and scripts/signing-key-rotation.sh stages each later one
# (ADR-IAM-002 §5.5 Q4). It needs Docker and nothing else.
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

started_at="$(date -u +%FT%TZ)"
echo "ceremony: realm signing key, started $started_at"
echo "  operator  $operator"
echo "  witness   $witness"
echo "  reason    $reason"
echo "  generator $upstream"

echo "1. the keystore, made offline in the pinned image, and named by its kid"
kid="$("$root/scripts/signing-key-generate.sh" "$keys")"
finished_at="$(date -u +%FT%TZ)"
name="realm-signing-$kid"

record="$(cat <<JSON
{
  "ceremony": "realm signing key",
  "standard": "STD-IAM-001 §3.10; ADR-IAM-002 §5.3, §5.5",
  "realm": "scnehaux",
  "operator": "$operator",
  "witness": "$witness",
  "reason": "$reason",
  "started_at": "$started_at",
  "finished_at": "$finished_at",
  "host": "$(hostname)",
  "generator": "$upstream",
  "key": {"algorithm": "PS256", "type": "RSA", "bits": 3072, "kid": "$kid"},
  "keystore": "signing/$name.p12",
  "certificate": "$name.crt",
  "kept": "the keystore and its password stay in the keys directory and are never copied to a backup",
  "review": "pending: a third person, neither the operator nor the witness, reviews this record (STD-IAM-001 §3.10)"
}
JSON
)"
# Written through a container, as the keys are: the keys directory may belong to root.
printf '%s\n' "$record" | docker run --rm -i --network none --user 0:0 -v "$keys:/keys" --entrypoint /bin/bash \
	"$upstream" -c "cat > /keys/$name.ceremony.json.partial && chmod 0644 /keys/$name.ceremony.json.partial &&
		mv /keys/$name.ceremony.json.partial /keys/$name.ceremony.json"
printf '%s\n' "$record"
echo "2. done: the kid is $kid. Next, the runbook's step 5: on an empty realm, start the kernel; on a realm"
echo "   that signs already, stage it with scripts/signing-key-rotation.sh stage $kid."
