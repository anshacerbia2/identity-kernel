package realmdef

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
)

// certificateFor is a self-signed certificate over the key, as keytool -genkeypair writes one.
func certificateFor(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestTheKidIsTheCertificateKeysThumbprint(t *testing.T) {
	key := rsaKey(t, 3072)
	kid, err := SigningKeyID(certificateFor(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if want := admin.Thumbprint(&key.PublicKey); kid != want {
		t.Fatalf("kid %s, want the RFC 7638 thumbprint %s", kid, want)
	}
	if _, err := SigningKeyID(certificateFor(t, rsaKey(t, 2048))); err == nil {
		t.Error("a 2048-bit certificate gave a kid; ADR-IAM-002 §5.1 requires 3072")
	}
	if _, err := SigningKeyID([]byte("not a certificate")); err == nil {
		t.Error("text that is not a PEM certificate gave a kid")
	}
}

func publicKeyB64(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestTheRealmMustSignWithTheKeystoreKeyAlone(t *testing.T) {
	key := rsaKey(t, 3072)
	kid := admin.Thumbprint(&key.PublicKey)
	ours := realmKey{Kid: kid, ProviderID: "provider", Algorithm: "PS256", Type: "RSA", Status: "ACTIVE",
		PublicKey: publicKeyB64(t, key)}
	rs256 := realmKey{Kid: "rs", ProviderID: "rsa-default", Algorithm: "RS256", Type: "RSA", Status: "DISABLED",
		PublicKey: "MIIB"}
	hs512 := realmKey{Kid: "hs", ProviderID: "hmac", Algorithm: "HS512", Type: "OCT", Status: "ACTIVE"}
	active := map[string]string{"PS256": kid, "RS256": "rs"}

	if got, err := checkSigningKey("provider", "realm-signing-ps256", active, []realmKey{ours, rs256, hs512}, kid); err != nil ||
		got != kid {
		t.Fatalf("the keystore's key alone: %q, %v", got, err)
	}

	cases := map[string]struct {
		keys   []realmKey
		active map[string]string
		want   string
		says   string
	}{
		"the keystore did not load": {keys: []realmKey{rs256}, active: active, says: "did not load"},
		"a fallback key beside it": {keys: []realmKey{ours, {Kid: "fb", ProviderID: "fallback", Algorithm: "PS256",
			Type: "RSA", Status: "ACTIVE"}}, active: active, says: "fallback-PS256"},
		"a kid that is not the thumbprint": {keys: []realmKey{func() realmKey { k := ours; k.Kid = "uuid"; return k }()},
			active: map[string]string{"PS256": "uuid"}, says: "thumbprint"},
		"another keystore than the ceremony's": {keys: []realmKey{ours}, active: active, want: "other", says: "another keystore"},
		"not the active key":                   {keys: []realmKey{ours}, active: map[string]string{"PS256": "x"}, says: "active"},
		"an RS256 key still published": {keys: []realmKey{ours, func() realmKey { k := rs256; k.Status = "ACTIVE"; return k }()},
			active: active, says: "publishes keys other than"},
		"a disabled key": {keys: []realmKey{func() realmKey { k := ours; k.Status = "DISABLED"; return k }()},
			active: active, says: "ACTIVE"},
	}
	for name, c := range cases {
		_, err := checkSigningKey("provider", "realm-signing-ps256", c.active, c.keys, c.want)
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: got %v, want an error saying %q", name, err, c.says)
		}
	}
}

func TestTheDefinedKeyIsAKeystoreWithVaultPasswords(t *testing.T) {
	d := definition(t)
	if err := d.validateSigningKey(); err != nil {
		t.Fatalf("the committed definition: %v", err)
	}
	for name, edit := range map[string]func(config map[string]any){
		"a literal password": func(c map[string]any) { c["keystorePassword"] = []any{"changeit"} },
		"a kid of its own":   func(c map[string]any) { c["kid"] = []any{"chosen"} },
		"RS256":              func(c map[string]any) { c["algorithm"] = []any{"RS256"} },
	} {
		changed := d.Clone()
		edit(changed.Key["config"].(map[string]any))
		if err := changed.validateSigningKey(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	generated := d.Clone()
	generated.Key["providerId"] = "rsa-generated"
	if err := generated.validateSigningKey(); err == nil {
		t.Error("a key Keycloak generates was accepted")
	}
}

func TestEveryOtherKeyProviderIsDeclaredDisabled(t *testing.T) {
	d := definition(t)
	if len(d.KeyProviders) == 0 {
		t.Fatal("the definition declares no key provider besides the signing key")
	}
	if err := d.validateKeyProviders(); err != nil {
		t.Fatalf("the committed definition: %v", err)
	}
	enabled := d.Clone()
	enabled.KeyProviders[0]["config"].(map[string]any)["enabled"] = []any{"true"}
	if err := enabled.validateKeyProviders(); err == nil {
		t.Error("a key provider declared enabled was accepted")
	}
}

func TestAKeyProviderEnabledAgainIsAChangeAndAbsentIsInSync(t *testing.T) {
	d := definition(t)
	l := liveFrom(d)
	for _, change := range compare(d, l) {
		if change.Kind == KindKeyProvider && change.Action != InSync {
			t.Fatalf("a disabled provider reads as %s: %v", change.Action, change.Diffs)
		}
	}
	providerName := name(d.KeyProviders[0])
	l.keys[providerName]["config"].(map[string]any)["enabled"] = []any{"true"}
	found := false
	for _, change := range compare(d, l) {
		if change.Kind == KindKeyProvider && change.Name == providerName {
			found = change.Action == Update
		}
	}
	if !found {
		t.Errorf("%s enabled again is not a change", providerName)
	}
	delete(l.keys, providerName)
	for _, change := range compare(d, l) {
		if change.Kind == KindKeyProvider && change.Name == providerName && change.Action != InSync {
			t.Errorf("%s absent reads as %s; absent is as good as disabled", providerName, change.Action)
		}
	}
}
