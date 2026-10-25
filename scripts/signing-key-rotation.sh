#!/usr/bin/env bash
# The realm signing keys' rotation steps (TDD-identity-kernel-002 1.5.0 §Rotation as Built, ADR-IAM-002
# §5.2 and §5.5). Each step reads the realm's providers and the registry's state of the key and refuses
# when they disagree, asks the registry for its approval, acts, and records the outcome in the registry
# (identity-control's identity-signing-key, TDD-identity-control-001 §The Signing Key Registry).
#
#   signing-key-rotation.sh stage    <kid> <operator> <witness> <reason> <correlation>
#   signing-key-rotation.sh approve  <kid> <activate|retire|abandon|revoke> <operator> <approver> <reason> <correlation> [--emergency]
#   signing-key-rotation.sh activate <kid> <operator>
#   signing-key-rotation.sh retire   <kid> <operator>
#   signing-key-rotation.sh abandon  <kid> <operator>
#   signing-key-rotation.sh revoke   <kid> <operator>
#   signing-key-rotation.sh state
#
#   stage     registers the key the ceremony made, checks its keystore, and creates its provider enabled
#             and passive: published, signing nothing. The first key, which realm-apply activated, is
#             registered and left as it is.
#   approve   records an approval, by a holder of the ceremony role who is not the step's operator, and
#             for an activation not the key's generator either. --emergency: an activation after a
#             compromise, which does not wait (ADR-IAM-002 §5.5 Q7).
#   activate  after the consumer cache window: the key active above every other, then the previous
#             active key demoted to retiring. The first key's activation is recorded as it stands.
#   retire    after the retirement window: the provider removed, then the keystore, password and
#             certificate destroyed, then the evidence recorded (ADR-IAM-002 §5.5 Q8).
#   abandon   a staged key that never signed, the same way, recorded as retired, abandoned (Q6).
#   revoke    a staged or retiring key, at once (Q7). A compromised active key is first demoted by a
#             replacement's emergency activation.
#   state     the registry's keys and the realm's providers.
#
# On the development server, from the kernel's checkout:
#
#   IDENTITY_CONTROL_DEPLOY_DIR=/srv/identity-control/deploy/dev scripts/signing-key-rotation.sh state
#
# The commands it runs, each replaceable for a test run:
#
#   SIGNING_KEY_REGISTRY  identity-control's command; default: its signing-key service, in
#                         IDENTITY_CONTROL_DEPLOY_DIR
#   SIGNING_KEY_TOOL      cmd/signing-key with Admin API credentials and the keys; default: the kernel's
#                         signing-key service, in KERNEL_DEPLOY_DIR (default deploy/dev)
#   SIGNING_KEY_CHECK     the image's keystore check; default: the kernel's service with check-keystores
#   REALM_ENVIRONMENT     the environment, for the windows (default development)
#
# Exit status: 0 done, 1 error, 2 refused.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
realm=scnehaux
kernel_dir="${KERNEL_DEPLOY_DIR:-$root/deploy/dev}"
environment="${REALM_ENVIRONMENT:-development}"

refuse() {
	echo "signing-key-rotation: refusing: $*" >&2
	exit 2
}
fail() {
	echo "signing-key-rotation: $*" >&2
	exit 1
}

if [ -z "${SIGNING_KEY_REGISTRY:-}" ]; then
	[ -n "${IDENTITY_CONTROL_DEPLOY_DIR:-}" ] ||
		fail "set IDENTITY_CONTROL_DEPLOY_DIR to identity-control's deploy/dev, or SIGNING_KEY_REGISTRY"
	SIGNING_KEY_REGISTRY="docker compose --project-directory $IDENTITY_CONTROL_DEPLOY_DIR run --rm --no-deps -T signing-key"
fi
SIGNING_KEY_TOOL="${SIGNING_KEY_TOOL:-docker compose --project-directory $kernel_dir run --rm --no-deps -T signing-key}"
SIGNING_KEY_CHECK="${SIGNING_KEY_CHECK:-docker compose --project-directory $kernel_dir run --rm --no-deps -T keycloak check-keystores}"

# The commands are word-split on purpose: each is a command and its leading arguments.
registry() { $SIGNING_KEY_REGISTRY "$@"; }
tool() { $SIGNING_KEY_TOOL "$@"; }

# field reads one string member of a JSON line.
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }

registry_state() { registry state -realm "$realm" -kid "$1" | field state; }
provider_state() {
	tool providers | grep -F "\"kid\":\"$1\"" | field state || true
}

# agree refuses a key whose registry state and provider disagree, as after a restore of either
# (TDD-identity-control-001 §The Signing Key Registry, restore to an earlier point).
agree() {
	local kid="$1" registered provider
	registered="$(registry_state "$kid")"
	provider="$(provider_state "$kid")"
	case "$registered:$provider" in
	staged:passive | active:active | retiring:passive | retired: | revoked: | staged:active) ;;
	*) refuse "$kid is '${registered:-not registered}' in the registry and '${provider:-absent}' in the realm; record the missing transitions first (docs/runbooks/signing-key-rotation.md)" ;;
	esac
	printf '%s' "$registered"
}

windows() { tool windows -environment "$environment"; }
window() { windows | sed -n "s/.*$1=\([^ ]*\).*/\1/p"; }

# check asks the registry for the step's approval and prints its identifier; a refusal stops the step.
check() {
	local kid="$1" transition="$2" operator="$3" min_age="${4:-0s}" approval status=0
	approval="$(registry check -realm "$realm" -kid "$kid" -transition "$transition" -operator "$operator" \
		-min-age "$min_age")" || status=$?
	[ "$status" -eq 0 ] || exit "$status"
	printf '%s' "$approval"
}

# act runs the kernel's half of a step; on failure it records the failure, which changes no state.
act() {
	local approval="$1" output status=0
	shift
	output="$("$@" 2>&1)" || status=$?
	if [ "$status" -ne 0 ]; then
		registry record -realm "$realm" -approval "$approval" -outcome failed -evidence "$output" >&2 || true
		fail "the step failed and its failure is recorded: $output"
	fi
	printf '%s' "$output"
}

command="${1:-}"
[ -n "$command" ] || fail "usage: signing-key-rotation.sh stage|approve|activate|retire|abandon|revoke|state ..."
shift

case "$command" in
stage)
	kid="${1:?kid}" operator="${2:?operator}" witness="${3:?witness}" reason="${4:?reason}" correlation="${5:?correlation}"
	name="realm-signing-$kid"
	if [ -z "$(registry_state "$kid")" ]; then
		tool jwk -certificate "/keys/$name.crt" |
			registry stage -realm "$realm" -kid "$kid" -jwk - -operator "$operator" -witness "$witness" \
				-reason "$reason" -correlation "$correlation" \
				-custody-ref "deploy/dev/keys: signing/$name.p12, vault/scnehaux_${name//_/__}"
	fi
	[ "$(registry_state "$kid")" = staged ] || [ "$(provider_state "$kid")" = active ] ||
		refuse "$kid is $(registry_state "$kid") in the registry; only a new key is staged"
	$SIGNING_KEY_CHECK
	tool stage -kid "$kid"
	echo "staged $kid: published, signing nothing"
	;;
approve)
	kid="${1:?kid}" transition="${2:?transition}" operator="${3:?operator}" approver="${4:?approver}"
	reason="${5:?reason}" correlation="${6:?correlation}"
	emergency=()
	[ "${7:-}" = "--emergency" ] && emergency=(-emergency)
	registry approve -realm "$realm" -kid "$kid" -transition "$transition" -operator "$operator" \
		-approver "$approver" -reason "$reason" -correlation "$correlation" "${emergency[@]}"
	;;
activate)
	kid="${1:?kid}" operator="${2:?operator}"
	agree "$kid" >/dev/null
	# The first key is active already: realm-apply made it so on the empty realm, before any consumer
	# could cache a key set (ADR-IAM-002 §5.5 Q4). Its activation is recorded as it stands, with no wait.
	min_age="$(window cache)"
	[ "$(provider_state "$kid")" = active ] && min_age=0s
	approval="$(check "$kid" activate "$operator" "$min_age")"
	act "$approval" tool activate -kid "$kid"
	echo
	registry record -realm "$realm" -approval "$approval" -outcome completed
	;;
retire | abandon | revoke)
	kid="${1:?kid}" operator="${2:?operator}"
	state="$(agree "$kid")"
	case "$command:$state" in
	retire:retiring | abandon:staged | revoke:staged | revoke:retiring) ;;
	revoke:active) refuse "$kid is active; stage a replacement and activate it with an emergency approval first (ADR-IAM-002 §5.5 Q7)" ;;
	*) refuse "$kid is $state; $command does not apply" ;;
	esac
	min_age=0s
	[ "$command" = retire ] && min_age="$(window retirement)"
	approval="$(check "$kid" "$command" "$operator" "$min_age")"
	# ADR-IAM-002 §5.5 Q8, in order: the provider removed, which takes the key out of the key set; the
	# key's files destroyed and read back absent; then the registry, with that evidence, and not before.
	act "$approval" tool remove -kid "$kid" >/dev/null
	evidence="$(act "$approval" tool destroy -kid "$kid")"
	registry record -realm "$realm" -approval "$approval" -outcome completed \
		-evidence "provider removed from the realm; $evidence"
	;;
state)
	echo "registry:"
	registry state -realm "$realm"
	echo "realm:"
	tool providers
	;;
*)
	fail "unknown step $command"
	;;
esac
