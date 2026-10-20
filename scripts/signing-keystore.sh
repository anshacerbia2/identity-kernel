#!/bin/bash
# Makes the realm signing keystore (TDD-identity-kernel-002 1.2.0 §Custody as Built, ADR-IAM-002 §5.3).
# It runs inside the kernel's own image, as root, with no network: the keystore is written by the JDK
# that will read it, and nothing leaves the container but the files below.
#
#   signing-keystore.sh <keys directory> [--throwaway-if-absent]
#
# Writes, under <keys directory>:
#
#   signing/realm-signing.p12              the PKCS#12 keystore: one RSA-3072 key pair, alias realm-signing,
#                                          and its self-signed certificate. Owned by the kernel's user
#                                          (1000:0), mode 0400, in a directory of mode 0500
#   vault/scnehaux_realm-signing-password  its password, for Keycloak's file vault: the realm scnehaux's
#                                          secret realm-signing-password, ${vault.realm-signing-password}
#                                          in realm/signing-key.json. Same owner and modes
#   realm-signing.crt                      the certificate, PEM, mode 0644: the public half. realm-apply
#                                          reads its kid from it, the RFC 7638 thumbprint of the key
#
# One password protects both the keystore and the key. keytool sets "the key password ... to the same
# password as the keystore password" when none is given, and PKCS#12 tools expect them equal; the
# realm's two password fields name the same vault entry.
#
# The private key never leaves the keystore, and the keystore and the vault file are never copied to
# a backup (STD-GLB-009 rule 9). A lost keystore is replaced by a new ceremony and a new kid.
#
# It refuses when either file exists: a second key in a realm is a rotation, which is not built
# (TDD-identity-kernel-002 §Rotation). --throwaway-if-absent leaves existing files alone and exits 0
# instead; only deploy/dev/compose.ci.yaml passes it, for a test run's kernel (ADR-IAM-002 §5.3: "A
# throwaway kernel, such as a test run's, may sign with a key it generated itself").
#
# A person never runs this directly on a server: scripts/signing-key-ceremony.sh runs it, with the
# operator and the witness it records (STD-IAM-001 §3.10).
set -euo pipefail

keys="${1:?usage: signing-keystore.sh <keys directory> [--throwaway-if-absent]}"
mode="${2:-}"
owner=1000:0
alias=realm-signing

signing="$keys/signing"
vault="$keys/vault"
keystore="$signing/realm-signing.p12"
password="$vault/scnehaux_realm-signing-password"
certificate="$keys/realm-signing.crt"

if [ -e "$keystore" ] || [ -e "$password" ]; then
	if [ "$mode" = "--throwaway-if-absent" ]; then
		echo "signing-keystore: $keystore exists; leaving it"
		exit 0
	fi
	echo "signing-keystore: refusing: $keystore or its password exists. A second key is a rotation, which is" \
		"not built (TDD-identity-kernel-002 §Rotation); a server starts from zero instead (deploy/dev/README.md)" >&2
	exit 1
fi

umask 077
mkdir -p "$signing" "$vault"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 32 random bytes, hex, with no newline: the vault serves the file's bytes as the password.
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$work/password"
keytool -genkeypair -alias "$alias" -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -validity 365 \
	-dname "CN=scnehaux realm signing key" -storetype PKCS12 -keystore "$work/keystore.p12" \
	-storepass:file "$work/password" >/dev/null 2>&1
keytool -exportcert -rfc -alias "$alias" -storetype PKCS12 -keystore "$work/keystore.p12" \
	-storepass:file "$work/password" -file "$work/certificate.pem" >/dev/null 2>&1
# The keystore opens with the password, as the kernel's start check opens it (image/start.sh).
keytool -list -alias "$alias" -storetype PKCS12 -keystore "$work/keystore.p12" \
	-storepass:file "$work/password" >/dev/null

install -m 0400 -o "${owner%:*}" -g "${owner#*:}" "$work/keystore.p12" "$keystore"
install -m 0400 -o "${owner%:*}" -g "${owner#*:}" "$work/password" "$password"
install -m 0644 "$work/certificate.pem" "$certificate"
chown "$owner" "$signing" "$vault"
chmod 0500 "$signing" "$vault"

echo "signing-keystore: wrote $keystore, its password in $vault, and its certificate $certificate"
