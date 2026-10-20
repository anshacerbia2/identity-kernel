package realmdef

// The realm signing key, loaded from a keystore the kernel never generates (TDD-identity-kernel-002
// 1.2.0 §Custody as Built, ADR-IAM-002 §5.3).
//
// The definition declares the provider: Keycloak's java-keystore, reading a PKCS#12 keystore from the
// realm's keystore directory, with both passwords as file-vault references. Two facts about the pinned
// release shape what happens around it:
//
//   - Its kid is a configuration value the provider is created with. JavaKeystoreKeyProviderFactory
//     .validateConfiguration puts a random identifier in the configuration when none is given, so a
//     provider created without one would sign under an identifier unrelated to its key. The kid is
//     therefore rendered at creation from the keystore's certificate: its RFC 7638 thumbprint, the
//     rule TDD-identity-kernel-002 §Key Identity fixes. Keycloak leaves the value out of every
//     representation it returns and ignores it on an update, so it is never part of the comparison,
//     and an update cannot rebind it.
//   - When no active PS256 key loads -- a missing keystore, a wrong password -- the next token makes
//     Keycloak generate one, fallback-PS256 (DefaultKeyManager.getActiveKey). That is the in-process
//     generation STD-IAM-001 §3.5 prohibits, so VerifySigningKey refuses a realm that holds one.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
)

// SigningAlgorithm is the one algorithm the realm signs with (ADR-IAM-002 §5.1).
const SigningAlgorithm = "PS256"

// minimumModulus is ADR-IAM-002 §5.1's floor, which foundation-platform's verifier also holds.
const minimumModulus = 3072

// SigningKeyID returns the kid of the key a certificate carries: the RFC 7638 thumbprint of its RSA
// public key. The certificate is the public half of the keystore the ceremony made
// (scripts/signing-key-ceremony.sh); nothing secret is read.
func SigningKeyID(certificatePEM []byte) (string, error) {
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("the signing certificate is not a PEM CERTIFICATE")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing the signing certificate: %w", err)
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("the signing certificate does not carry an RSA key")
	}
	if public.N.BitLen() < minimumModulus {
		return "", fmt.Errorf("the signing certificate carries a %d-bit key; ADR-IAM-002 §5.1 requires at least %d",
			public.N.BitLen(), minimumModulus)
	}
	return admin.Thumbprint(public), nil
}

// realmKey is one entry of GET /admin/realms/{realm}/keys.
type realmKey struct {
	Kid        string `json:"kid"`
	ProviderID string `json:"providerId"`
	Algorithm  string `json:"algorithm"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	PublicKey  string `json:"publicKey"`
}

// VerifySigningKey asserts what TDD-identity-kernel-002 §Startup asserts of a replica, against the
// live realm: the declared provider loaded its key, that key is the realm's one active PS256 key, its
// kid is the RFC 7638 thumbprint of its own public key, and no other PS256 key exists, a
// fallback-PS256 above all. want, when set, is the kid the keystore's certificate gives, so the key
// loaded is the one the ceremony made. It returns the kid.
func VerifySigningKey(ctx context.Context, c *admin.Client, d Definition, want string) (string, error) {
	base := "/admin/realms/" + url.PathEscape(d.Name())
	var components []map[string]any
	if err := c.GetJSON(ctx, base+"/components?type="+url.QueryEscape("org.keycloak.keys.KeyProvider"),
		&components); err != nil {
		return "", fmt.Errorf("reading the key providers: %w", err)
	}
	providerID := ""
	for _, component := range components {
		if name(component) == name(d.Key) {
			providerID, _ = component["id"].(string)
		}
	}
	if providerID == "" {
		return "", fmt.Errorf("the realm has no key provider %s", name(d.Key))
	}
	var keys struct {
		Active map[string]string `json:"active"`
		Keys   []realmKey        `json:"keys"`
	}
	if err := c.GetJSON(ctx, base+"/keys", &keys); err != nil {
		return "", fmt.Errorf("reading the realm's keys: %w", err)
	}
	return checkSigningKey(providerID, name(d.Key), keys.Active, keys.Keys, want)
}

func checkSigningKey(providerID, providerName string, active map[string]string, keys []realmKey,
	want string) (string, error) {
	var ours []realmKey
	var others []string
	for _, key := range keys {
		switch {
		case key.ProviderID == providerID:
			ours = append(ours, key)
		case key.Algorithm == SigningAlgorithm:
			others = append(others, fmt.Sprintf("kid %s from provider %s (%s)", key.Kid, key.ProviderID, key.Status))
		}
	}
	sort.Strings(others)
	if len(ours) != 1 {
		return "", fmt.Errorf("the key provider %s serves %d keys, want 1: its keystore did not load. The kernel "+
			"logs why; see docs/runbooks/custody-outage.md", providerName, len(ours))
	}
	key := ours[0]
	if key.Algorithm != SigningAlgorithm || key.Type != "RSA" || key.Status != "ACTIVE" {
		return "", fmt.Errorf("the key provider %s serves a %s %s key in state %s, want an ACTIVE RSA %s key",
			providerName, key.Type, key.Algorithm, key.Status, SigningAlgorithm)
	}
	der, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("the realm's key %s has a public key that is not base64: %w", key.Kid, err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", fmt.Errorf("parsing the realm's public key %s: %w", key.Kid, err)
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok || public.N.BitLen() < minimumModulus {
		return "", fmt.Errorf("the realm's key %s is not an RSA key of at least %d bits", key.Kid, minimumModulus)
	}
	if thumbprint := admin.Thumbprint(public); key.Kid != thumbprint {
		return "", fmt.Errorf("the realm signs under kid %s, and its key's RFC 7638 thumbprint is %s; "+
			"TDD-identity-kernel-002 §Key Identity requires them equal. The provider was created without its kid", key.Kid,
			thumbprint)
	}
	if want != "" && key.Kid != want {
		return "", fmt.Errorf("the realm's signing key is %s, and the keystore's certificate gives %s: the kernel "+
			"loaded another keystore than the ceremony made", key.Kid, want)
	}
	if active[SigningAlgorithm] != key.Kid {
		return "", fmt.Errorf("the realm's active %s key is %q, not the keystore's %s", SigningAlgorithm,
			active[SigningAlgorithm], key.Kid)
	}
	if len(others) > 0 {
		return "", fmt.Errorf("the realm holds %s keys other than the keystore's: %s. A fallback-PS256 is a key "+
			"Keycloak generated in-process because the keystore did not load; see docs/runbooks/custody-outage.md",
			SigningAlgorithm, strings.Join(others, "; "))
	}
	return key.Kid, nil
}

// validateSigningKey holds the declared provider to ADR-IAM-002 §5.3: the java-keystore provider,
// signing PS256, both passwords vault references and never literal configuration, and no kid of its
// own, because the kid is the certificate's thumbprint, rendered at creation.
func (d Definition) validateSigningKey() error {
	if providerID, _ := d.Key["providerId"].(string); providerID != "java-keystore" {
		return fmt.Errorf("signing-key.json declares provider %q; the realm signs with a key loaded from a keystore, "+
			"java-keystore, never one Keycloak generates (ADR-IAM-002 §5.3)", providerID)
	}
	config, _ := d.Key["config"].(map[string]any)
	if _, declared := config["kid"]; declared {
		return errors.New("signing-key.json declares a kid; the kid is the RFC 7638 thumbprint of the keystore's " +
			"certificate, rendered when the provider is created")
	}
	if got := single(config["algorithm"]); got != SigningAlgorithm {
		return fmt.Errorf("signing-key.json signs %q; ADR-IAM-002 §5.1 requires %s", got, SigningAlgorithm)
	}
	for _, field := range []string{"keystorePassword", "keyPassword"} {
		value := single(config[field])
		if !strings.HasPrefix(value, "${vault.") || !strings.HasSuffix(value, "}") {
			return fmt.Errorf("signing-key.json sets %s to a literal value; it must be a vault reference, "+
				"${vault.<name>} (ADR-IAM-002 §5.3)", field)
		}
	}
	return nil
}

// single reads a component configuration value, which Keycloak keeps as a list of strings.
func single(value any) string {
	switch v := value.(type) {
	case []any:
		if len(v) == 1 {
			s, _ := v[0].(string)
			return s
		}
	case []string:
		if len(v) == 1 {
			return v[0]
		}
	}
	return ""
}
