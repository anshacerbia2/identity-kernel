#!/bin/bash
# The kernel image's entrypoint (TDD-identity-kernel-002 1.5.0 §Startup as Built, TDD-identity-kernel-005
# 1.10.0 §Build Inputs). Before Keycloak starts a server, it checks every realm signing keystore and its
# password, and refuses to start otherwise. `check-keystores` runs the same checks and exits, so a
# rotation step can check a new keystore without starting a kernel. Any other command, such as
# kc.sh show-config, runs unchecked.
#
# The check is the design, not a convenience. STD-IAM-001 §3.5 prohibits per-process key generation
# "including as a fallback when protected custody is unreachable", and Keycloak 26.7.5 does exactly
# that when no PS256 key loads: the next token makes it generate fallback-PS256 in the database
# (DefaultKeyManager.getActiveKey). A kernel that cannot open its keystores therefore never starts.
#
# The layout is the one realm/signing-key.json names, one keystore per key (ADR-IAM-002 §5.5 Q3): the
# java-keystore provider of key <kid> reads realm-signing-<kid>.p12 from the realm's keystore directory,
# /opt/keycloak/data/scnehaux, and both its passwords are ${vault.realm-signing-<kid>}, which the file
# vault reads from $KC_VAULT_DIR/scnehaux_realm-signing-<kid>, underscores doubled. Each keystore holds
# exactly one entry, realm-signing. deploy/dev/compose.yaml mounts both directories read-only; in
# production the AWS Secrets and Configuration Provider mounts them
# (docs/production/realm-signing-secret-provider-class.yaml).
set -euo pipefail

check_keystores() {
	local directory=/opt/keycloak/data/scnehaux found=0 keystore name password listing
	refuse() {
		echo "identity-kernel: refusing to start: $*. See docs/runbooks/custody-outage.md" >&2
		exit 1
	}
	[ -n "${KC_VAULT_DIR:-}" ] || refuse "KC_VAULT_DIR is empty, so the realm's \${vault...} passwords resolve to nothing"
	for keystore in "$directory"/*; do
		[ -e "$keystore" ] || continue
		name="${keystore##*/}"
		case "$name" in
		realm-signing-*.p12) ;;
		*) refuse "$keystore is not a realm signing keystore, realm-signing-<kid>.p12" ;;
		esac
		name="${name%.p12}"
		password="$KC_VAULT_DIR/scnehaux_${name//_/__}"
		[ -r "$keystore" ] || refuse "the realm signing keystore $keystore is not readable"
		[ -r "$password" ] || refuse "the password of $keystore, $password, is not mounted or not readable"
		listing="$(keytool -list -storetype PKCS12 -keystore "$keystore" -storepass:file "$password" 2>&1)" ||
			refuse "$keystore does not open with the password in $password"
		[[ "$listing" == *"Your keystore contains 1 entry"* ]] ||
			refuse "$keystore holds more or fewer than one entry; each key is a keystore of its own"
		keytool -list -alias realm-signing -storetype PKCS12 -keystore "$keystore" -storepass:file "$password" \
			>/dev/null 2>&1 || refuse "$keystore holds no entry realm-signing"
		found=$((found + 1))
	done
	[ "$found" -gt 0 ] || refuse "no realm signing keystore is mounted in $directory"
	echo "identity-kernel: $found realm signing keystore(s), each one entry, each opening with its password"
}

case "${1:-}" in
check-keystores)
	check_keystores
	exit 0
	;;
start | start-dev)
	check_keystores
	;;
esac

exec /opt/keycloak/bin/kc.sh "$@"
