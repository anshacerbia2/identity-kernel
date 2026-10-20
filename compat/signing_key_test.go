package compat

// The realm signs with the key in the keystore the kernel loads, under the kid TDD-identity-kernel-002
// §Key Identity fixes (TDD-identity-kernel-002 1.2.0 §Custody as Built, ADR-IAM-002 §5.3). CI makes a
// throwaway keystore with scripts/signing-keystore.sh, the generator the ceremony runs, mounts it and
// its vault file read-only, and names its certificate in KERNEL_SIGNING_CERTIFICATE. This asserts:
//
//   - the realm's one PS256 key comes from the declared java-keystore provider, whose passwords are
//     vault references, and is the certificate's key;
//   - its kid is the RFC 7638 thumbprint of that key, in the Admin API and in the published key set;
//   - an access token and an ID token carry that kid, and verify with the certificate's key alone;
//   - no other PS256 key exists, so nothing was generated in-process as a fallback;
//   - the published key set holds the keystore's key and nothing else: Keycloak's RS256 and RSA-OAEP
//     providers are disabled by realm/key-providers.json (ADR-IAM-002 §5.1, TDD-identity-kernel-002
//     §The Published Key Set).
//
// TestTheLegacyRealmEndpointAsksForAnRS256Key records what the pinned image does when a request reaches
// GET /realms/{realm} with no RS256 key active, which is why the proxy closes that endpoint.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	kcadmin "github.com/anshacerbia2/identity-kernel/internal/admin"
	"github.com/anshacerbia2/identity-kernel/internal/realmdef"
)

const signingProvider = "realm-signing-ps256"

func TestTokensAreSignedByTheKeystoreKeyUnderItsThumbprint(t *testing.T) {
	a := requireKeycloak(t)
	path := strings.TrimSpace(os.Getenv("KERNEL_SIGNING_CERTIFICATE"))
	if path == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("KERNEL_SIGNING_CERTIFICATE is unset: the suite cannot tell the keystore's key from another")
		}
		t.Skip("KERNEL_SIGNING_CERTIFICATE is unset")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	public := certificate.PublicKey.(*rsa.PublicKey)
	kid := kcadmin.Thumbprint(public)
	if fromTool, err := realmdef.SigningKeyID(content); err != nil || fromTool != kid {
		t.Fatalf("realmdef.SigningKeyID gives %q (%v), the thumbprint is %s", fromTool, err, kid)
	}

	// The provider, as configured.
	var components []struct {
		ID         string              `json:"id"`
		Name       string              `json:"name"`
		ProviderID string              `json:"providerId"`
		Config     map[string][]string `json:"config"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/components?type=org.keycloak.keys.KeyProvider", &components); err != nil {
		t.Fatalf("listing the key providers: %v", err)
	}
	providerID := ""
	for _, component := range components {
		if component.Name != signingProvider {
			continue
		}
		providerID = component.ID
		if component.ProviderID != "java-keystore" {
			t.Errorf("%s is a %s provider, not java-keystore", signingProvider, component.ProviderID)
		}
		for _, field := range []string{"keystorePassword", "keyPassword"} {
			if got := component.Config[field]; len(got) != 1 || !strings.HasPrefix(got[0], "${vault.") {
				t.Errorf("%s's %s is %v, not a vault reference", signingProvider, field, got)
			}
		}
	}
	if providerID == "" {
		t.Fatalf("the realm has no key provider %s", signingProvider)
	}

	// The key, as loaded.
	var keys struct {
		Active map[string]string `json:"active"`
		Keys   []struct {
			Kid         string `json:"kid"`
			ProviderID  string `json:"providerId"`
			Algorithm   string `json:"algorithm"`
			Status      string `json:"status"`
			PublicKey   string `json:"publicKey"`
			Certificate string `json:"certificate"`
		} `json:"keys"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/keys", &keys); err != nil {
		t.Fatalf("reading the realm's keys: %v", err)
	}
	if keys.Active["PS256"] != kid {
		t.Errorf("the realm's active PS256 key is %q, want the keystore's %s", keys.Active["PS256"], kid)
	}
	spki, _ := x509.MarshalPKIXPublicKey(public)
	found := false
	for _, key := range keys.Keys {
		switch {
		case key.ProviderID == providerID:
			found = true
			if key.Kid != kid || key.Algorithm != "PS256" || key.Status != "ACTIVE" {
				t.Errorf("the provider serves kid %s, %s, %s; want %s, PS256, ACTIVE", key.Kid, key.Algorithm, key.Status, kid)
			}
			if key.PublicKey != base64.StdEncoding.EncodeToString(spki) {
				t.Error("the provider's public key is not the certificate's")
			}
			if key.Certificate != base64.StdEncoding.EncodeToString(certificate.Raw) {
				t.Error("the provider's certificate is not the keystore's")
			}
		case key.Algorithm == "PS256":
			t.Errorf("the realm holds another PS256 key, kid %s from provider %s: a fallback generated in-process",
				key.Kid, key.ProviderID)
		case key.PublicKey != "" && key.Status != "DISABLED":
			t.Errorf("the realm publishes a %s key, kid %s from provider %s (%s); ADR-IAM-002 §5.1 allows PS256 alone",
				key.Algorithm, key.Kid, key.ProviderID, key.Status)
		}
	}
	if !found {
		t.Fatal("the java-keystore provider serves no key: the keystore did not load")
	}

	// The key set, as published: the keystore's key and nothing else.
	response, err := a.http.Get(a.realmURL("/certs"))
	if err != nil {
		t.Fatalf("GET certs: %v", err)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	err = json.NewDecoder(response.Body).Decode(&set)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("decoding certs: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != kid || set.Keys[0].Alg != "PS256" || set.Keys[0].Use != "sig" {
		t.Errorf("the key set publishes %+v; want the keystore's PS256 signing key %s alone", set.Keys, kid)
	}

	// The key, as published.
	published, err := realmKey(a, kid)
	if err != nil {
		t.Fatalf("the key set: %v", err)
	}
	if published.N.Cmp(public.N) != 0 || published.E != public.E {
		t.Error("the key set publishes another key under the keystore's kid")
	}
	if got := kcadmin.Thumbprint(published); got != kid {
		t.Errorf("the published key's thumbprint is %s, its kid %s", got, kid)
	}

	// The tokens.
	c := internalClient(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil, http.StatusNoContent)
	})
	p := createPrincipal(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil, http.StatusNoContent)
	})
	tokens := passwordGrant(t, a, c, p)
	for name, token := range map[string]string{"access token": tokens.AccessToken, "ID token": tokens.IDToken} {
		if token == "" {
			t.Errorf("no %s was issued", name)
			continue
		}
		header := jwtHeader(t, token)
		if header["kid"] != kid || header["alg"] != "PS256" {
			t.Errorf("the %s's header is %v; want kid %s, alg PS256", name, header, kid)
		}
		if err := verifyWith(public, token); err != nil {
			t.Errorf("the %s does not verify with the certificate's key: %v", name, err)
		}
	}
	summary, _ := json.Marshal(map[string]string{"kid": kid, "provider": "java-keystore"})
	t.Logf("the realm signs with the keystore's key: %s", summary)
}

// verifyWith checks a PS256 compact JWS against one public key.
func verifyWith(public *rsa.PublicKey, token string) error {
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
}

// TestTheLegacyRealmEndpointAsksForAnRS256Key asks the pinned image what GET /realms/{realm} does when no
// RS256 key is active, as with the realm's RS256 provider disabled. 26.7.5's PublicRealmResource returns
// the realm's public key through getActiveRsaKey, and DefaultKeyManager.getActiveKey generates a
// fallback key when none is active. A fallback-RS256 made so is a key generated in-process and
// published, which is why the proxy closes the endpoint and realm-apply refuses such a key
// (TDD-identity-kernel-002 §The Published Key Set). The answer is recorded, not required, and any
// fallback key the request made is removed again.
func TestTheLegacyRealmEndpointAsksForAnRS256Key(t *testing.T) {
	a := requireKeycloak(t)
	fallbacks := func() []string {
		var components []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := a.getJSON("/admin/realms/"+realmName+"/components?type=org.keycloak.keys.KeyProvider", &components); err != nil {
			t.Fatalf("listing the key providers: %v", err)
		}
		var ids []string
		for _, component := range components {
			if strings.HasPrefix(component.Name, "fallback-") {
				ids = append(ids, component.ID)
			}
		}
		return ids
	}
	if before := fallbacks(); len(before) != 0 {
		t.Fatalf("the realm already holds %d fallback key providers", len(before))
	}
	t.Cleanup(func() {
		for _, id := range fallbacks() {
			_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/components/"+id, nil, http.StatusNoContent)
		}
	})
	response, err := a.http.Get(a.base + "/realms/" + realmName)
	if err != nil {
		t.Fatalf("GET the legacy realm endpoint: %v", err)
	}
	_ = response.Body.Close()
	made := len(fallbacks())
	t.Logf("GET /realms/%s with no active RS256 key answered %d and made %d fallback key providers", realmName,
		response.StatusCode, made)
	publish(t, fmt.Sprintf("### The legacy realm endpoint, with RS256 disabled\n\n`GET /realms/%s` answered %d "+
		"and made **%d** fallback key provider(s) in-process. The proxy closes the endpoint "+
		"(TDD-identity-kernel-002 §The Published Key Set).\n", realmName, response.StatusCode, made))
}
