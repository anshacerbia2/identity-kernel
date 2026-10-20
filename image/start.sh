#!/bin/bash
# The kernel image's entrypoint (TDD-identity-kernel-002 1.2.0 §Startup as Built, TDD-identity-kernel-005
# 1.10.0 §Build Inputs). Before Keycloak starts a server, it checks that the realm signing keystore and
# its password are mounted and open together, and refuses to start otherwise. Any other command, such as
# kc.sh show-config, runs unchecked.
#
# The check is the design, not a convenience. STD-IAM-001 §3.5 prohibits per-process key generation
# "including as a fallback when protected custody is unreachable", and Keycloak 26.7.5 does exactly
# that when no PS256 key loads: the next token makes it generate fallback-PS256 in the database
# (DefaultKeyManager.getActiveKey). A kernel that cannot open its keystore therefore never starts.
#
# The paths are the ones realm/signing-key.json names: the java-keystore provider reads realm-signing.p12
# from the realm's keystore directory, /opt/keycloak/data/scnehaux, and both its passwords are
# ${vault.realm-signing-password}, which the file vault reads from $KC_VAULT_DIR/scnehaux_realm-signing-password.
# deploy/dev/compose.yaml mounts both read-only; in production the AWS Secrets and Configuration
# Provider mounts them (docs/production/realm-signing-secret-provider-class.yaml).
set -euo pipefail

case "${1:-}" in
start | start-dev)
	keystore=/opt/keycloak/data/scnehaux/realm-signing.p12
	refuse() {
		echo "identity-kernel: refusing to start: $*. See docs/runbooks/custody-outage.md" >&2
		exit 1
	}
	[ -n "${KC_VAULT_DIR:-}" ] || refuse "KC_VAULT_DIR is empty, so the realm's \${vault...} passwords resolve to nothing"
	password="$KC_VAULT_DIR/scnehaux_realm-signing-password"
	[ -r "$keystore" ] || refuse "the realm signing keystore $keystore is not mounted or not readable"
	[ -r "$password" ] || refuse "its password $password is not mounted or not readable"
	keytool -list -alias realm-signing -storetype PKCS12 -keystore "$keystore" -storepass:file "$password" \
		>/dev/null 2>&1 || refuse "$keystore does not open with the password in $password, or holds no entry realm-signing"
	;;
esac

exec /opt/keycloak/bin/kc.sh "$@"
