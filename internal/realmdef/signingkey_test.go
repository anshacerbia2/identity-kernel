package realmdef

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
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

func provider(id, kid string, active bool) map[string]any {
	return map[string]any{"id": id, "name": SigningKeyName(kid), "providerId": "java-keystore",
		"config": map[string]any{"active": []any{strconv.FormatBool(active)}, "enabled": []any{"true"}}}
}

func TestTheRealmPublishesCustodyKeysAloneOneActive(t *testing.T) {
	oldKey, newKey := rsaKey(t, 3072), rsaKey(t, 3072)
	oldKid, newKid := admin.Thumbprint(&oldKey.PublicKey), admin.Thumbprint(&newKey.PublicKey)
	active := realmKey{Kid: newKid, ProviderID: "p-new", Algorithm: "PS256", Type: "RSA", Status: "ACTIVE",
		PublicKey: publicKeyB64(t, newKey)}
	retiring := realmKey{Kid: oldKid, ProviderID: "p-old", Algorithm: "PS256", Type: "RSA", Status: "PASSIVE",
		PublicKey: publicKeyB64(t, oldKey)}
	rs256 := realmKey{Kid: "rs", ProviderID: "rsa-default", Algorithm: "RS256", Type: "RSA", Status: "DISABLED",
		PublicKey: "MIIB"}
	hs512 := realmKey{Kid: "hs", ProviderID: "hmac", Algorithm: "HS512", Type: "OCT", Status: "ACTIVE"}
	components := []map[string]any{provider("p-new", newKid, true), provider("p-old", oldKid, false)}
	custody := map[string]string{oldKid: "old.crt", newKid: "new.crt"}
	actives := map[string]string{"PS256": newKid, "RS256": "rs"}

	if got, err := checkSigningKey(components, actives, []realmKey{active, retiring, rs256, hs512}, custody); err != nil ||
		got != newKid {
		t.Fatalf("an active key and a retiring one: %q, %v", got, err)
	}
	if got, err := checkSigningKey(components[:1], actives, []realmKey{active}, nil); err != nil || got != newKid {
		t.Fatalf("one key, no custody given: %q, %v", got, err)
	}

	with := func(k realmKey, edit func(*realmKey)) realmKey { edit(&k); return k }
	cases := map[string]struct {
		components []map[string]any
		keys       []realmKey
		active     map[string]string
		custody    map[string]string
		says       string
	}{
		"no signing provider":          {nil, []realmKey{rs256}, actives, custody, "no signing key provider"},
		"a keystore that did not load": {components, []realmKey{active}, actives, custody, "did not load"},
		"two active keys": {components, []realmKey{active, with(retiring, func(k *realmKey) { k.Status = "ACTIVE" })},
			actives, custody, "2 active"},
		"no active key": {components, []realmKey{with(active, func(k *realmKey) { k.Status = "PASSIVE" }), retiring},
			actives, custody, "0 active"},
		"a fallback key beside them": {components, []realmKey{active, retiring, {Kid: "fb", ProviderID: "fallback",
			Algorithm: "PS256", Type: "RSA", Status: "ACTIVE"}}, actives, custody, "fallback-PS256"},
		"an RS256 key still published": {components, []realmKey{active, retiring,
			with(rs256, func(k *realmKey) { k.Status = "ACTIVE" })}, actives, custody, "publishes keys other than"},
		"a key not in custody": {components, []realmKey{active, retiring}, actives,
			map[string]string{newKid: "new.crt"}, "not in custody"},
		"a kid that is not the thumbprint": {components, []realmKey{with(active, func(k *realmKey) { k.Kid = "uuid" }),
			retiring}, map[string]string{"PS256": "uuid"}, custody, "thumbprint"},
		"a provider not named by its key": {[]map[string]any{provider("p-new", oldKid, true), provider("p-old", newKid, false)},
			[]realmKey{active, retiring}, actives, custody, "name is not its kid"},
		"a disabled signing key": {components, []realmKey{active, with(retiring, func(k *realmKey) { k.Status = "DISABLED" })},
			actives, custody, "DISABLED"},
		"the realm's active key is another": {components, []realmKey{active, retiring},
			map[string]string{"PS256": oldKid}, custody, "not its one active"},
	}
	for name, c := range cases {
		_, err := checkSigningKey(c.components, c.active, c.keys, c.custody)
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: got %v, want an error saying %q", name, err, c.says)
		}
	}
}

func TestEachKeysProviderIsRenderedFromTheTemplate(t *testing.T) {
	d := definition(t)
	rendered := RenderSigningKey(d.Key, "KID_x-1")
	config := rendered["config"].(map[string]any)
	for field, want := range map[string]string{"keystore": "realm-signing-KID_x-1.p12",
		"keystorePassword": "${vault.realm-signing-KID_x-1}", "keyPassword": "${vault.realm-signing-KID_x-1}",
		"keyAlias": "realm-signing", "kid": "KID_x-1"} {
		if got := single(config[field]); got != want {
			t.Errorf("%s is %q, want %q", field, got, want)
		}
	}
	if name(rendered) != "realm-signing-KID_x-1" {
		t.Errorf("the provider is named %q", name(rendered))
	}
	if single(d.Key["config"].(map[string]any)["keystore"]) != "realm-signing-{kid}.p12" {
		t.Error("rendering changed the template")
	}
}

func TestCustodyIsTheCertificatesNamedByTheirKids(t *testing.T) {
	dir := t.TempDir()
	key := rsaKey(t, 3072)
	kid := admin.Thumbprint(&key.PublicKey)
	if err := os.WriteFile(filepath.Join(dir, SigningKeyName(kid)+".crt"), certificateFor(t, key), 0o644); err != nil {
		t.Fatal(err)
	}
	custody, err := ReadCustody(dir)
	if err != nil || len(custody) != 1 || custody[kid] == "" {
		t.Fatalf("custody %v, %v", custody, err)
	}
	if err := os.WriteFile(filepath.Join(dir, SigningKeyName("another")+".crt"), certificateFor(t, rsaKey(t, 3072)),
		0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCustody(dir); err == nil || !strings.Contains(err.Error(), "not its kid") {
		t.Errorf("a certificate named by another kid: %v", err)
	}
}

func TestOnlyAThrowawayEnvironmentShortensTheWindows(t *testing.T) {
	none := func(string) string { return "" }
	set := func(name string) string {
		return map[string]string{CacheWindowVariable: "5s", RetirementWindowVariable: "7s"}[name]
	}
	if w, err := StepWindows(Development, none); err != nil || w.Cache != ConsumerKeySetCache || w.Retirement != RetirementWindow {
		t.Errorf("development: %+v, %v", w, err)
	}
	if w, err := StepWindows(CI, set); err != nil || w.Cache != 5*time.Second || w.Retirement != 7*time.Second {
		t.Errorf("ci with both set: %+v, %v", w, err)
	}
	if _, err := StepWindows(Development, set); err == nil {
		t.Error("development accepted a shortened window")
	}
	if _, err := StepWindows(Local, func(string) string { return "soon" }); err == nil {
		t.Error("a window that is not a duration was accepted")
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
