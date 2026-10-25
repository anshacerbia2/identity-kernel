#!/bin/bash
# Makes one realm signing keystore (TDD-identity-kernel-002 1.5.0 §Custody as Built and §Rotation as
# Built, ADR-IAM-002 §5.3 and §5.5 Q3). It runs inside the kernel's own image, as root, with no network:
# the keystore is written by the JDK that will read it, and nothing leaves the container but the files
# below.
#
#   signing-keystore.sh <keys directory> [--throwaway-if-absent]
#
# Writes, under <keys directory>/new, for `signing-key place` (cmd/signing-key) to name by the key's
# kid, which this image cannot compute:
#
#   keystore.p12     the PKCS#12 keystore: exactly one RSA-3072 key pair, alias realm-signing, and its
#                    self-signed certificate. Placed as signing/realm-signing-<kid>.p12
#   password         its password, for Keycloak's file vault. Placed as vault/scnehaux_realm-signing-<kid>
#                    (underscores doubled), ${vault.realm-signing-<kid>} in the key's provider
#   certificate.pem  the certificate, PEM: the public half. Placed as realm-signing-<kid>.crt; realm-apply
#                    and the rotation steps read the kid from it, the RFC 7638 thumbprint of the key
#
# One password protects both the keystore and the key. keytool sets "the key password ... to the same
# password as the keystore password" when none is given, and PKCS#12 tools expect them equal; the
# provider's two password fields name the same vault entry.
#
# The private key never leaves the keystore, and the keystore and the vault file are never copied to
# a backup (STD-GLB-009 rule 9). A lost keystore is replaced by a new ceremony and a new kid.
#
# It refuses when <keys>/new exists: an earlier run was not placed. --throwaway-if-absent writes nothing
# and exits 0 when a keystore is already in place; only deploy/dev/compose.ci.yaml passes it, for a test
# run's kernel (ADR-IAM-002 §5.3: "A throwaway kernel, such as a test run's, may sign with a key it
# generated itself").
#
# A person never runs this directly on a server: scripts/signing-key-ceremony.sh runs it, with the
# operator and the witness it records (STD-IAM-001 §3.10).
set -euo pipefail

keys="${1:?usage: signing-keystore.sh <keys directory> [--throwaway-if-absent]}"
mode="${2:-}"
alias=realm-signing
staging="$keys/new"

if [ "$mode" = "--throwaway-if-absent" ]; then
	for existing in "$keys"/signing/realm-signing-*.p12; do
		if [ -e "$existing" ]; then
			echo "signing-keystore: $existing exists; leaving it"
			exit 0
		fi
	done
fi
if [ -e "$staging" ]; then
	echo "signing-keystore: refusing: $staging exists, an earlier key that was never placed. Place it" \
		"(signing-key place) or remove it, then run the ceremony again" >&2
	exit 1
fi

umask 077
mkdir -p "$staging"
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

install -m 0400 "$work/keystore.p12" "$staging/keystore.p12"
install -m 0400 "$work/password" "$staging/password"
install -m 0644 "$work/certificate.pem" "$staging/certificate.pem"
echo "signing-keystore: wrote a keystore, its password and its certificate in $staging"
