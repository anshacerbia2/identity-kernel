package compat

// The Keycloak mechanism the five key states of TDD-identity-kernel-002 1.4.0 §Rotation State Machine
// are built on, asked of the pinned image (ADR-IAM-002 §5.2: "A retiring key verifies and no longer
// signs, as the kernel's passive key does").
//
// A state is a java-keystore provider's two flags: staged and retiring are enabled and passive,
// active is enabled and active, and retired and revoked are a provider removed. The ceremony and
// script steps that move a key between states are not built: TDD-identity-kernel-002 1.4.0 §Rotation
// as Built names the open questions they wait on. This test proves what those steps will rely on.
//
// CI makes a second throwaway keystore for it beside the realm's, rotation-fixture.p12 under the alias
// rotation-fixture, with the realm keystore's password, and names its certificate in
// KERNEL_ROTATION_FIXTURE_CERTIFICATE. The fixture is a test's key, never a custody layout. The test
// asserts, at every step:
//
//   - a staged key is published and signs nothing;
//   - once it is active, new tokens carry its kid, and a token the previous key signed still verifies
//     against the published key set while that key is retiring;
//   - a key leaves the key set when its provider is removed, and not before, and a token it signed then
//     no longer verifies against the key set;
//   - the key set holds RSA PS256 keys alone, and no step makes a fallback or an RS256 key.
//
// To leave the realm as the definition describes it, the test rotates back to the realm's key and
// removes the fixture's provider, which takes the fixture key through retiring and out.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-kernel/internal/realmdef"
)

const rotationFixtureProvider = "rotation-fixture-ps256"

func TestTheKeyStatesOnThePinnedImage(t *testing.T) {
	a := requireKeycloak(t)
	oldKid := certificateKid(t, "KERNEL_SIGNING_CERTIFICATE")
	newKid := certificateKid(t, "KERNEL_ROTATION_FIXTURE_CERTIFICATE")
	if oldKid == newKid {
		t.Fatal("the fixture keystore carries the realm's key")
	}
	providers := "/admin/realms/" + realmName + "/components"

	listProviders := func() []map[string]any {
		var components []map[string]any
		if err := a.getJSON(providers+"?type=org.keycloak.keys.KeyProvider", &components); err != nil {
			t.Fatalf("listing the key providers: %v", err)
		}
		return components
	}
	named := func(providerName string) map[string]any {
		for _, component := range listProviders() {
			if component["name"] == providerName {
				return component
			}
		}
		return nil
	}
	original := named(signingProvider)
	if original == nil {
		t.Fatalf("the realm has no key provider %s", signingProvider)
	}
	if named(rotationFixtureProvider) != nil {
		t.Fatalf("the realm already holds %s", rotationFixtureProvider)
	}
	setActive := func(component map[string]any, active bool) {
		t.Helper()
		update := map[string]any{}
		for k, v := range component {
			update[k] = v
		}
		config := map[string]any{}
		for k, v := range component["config"].(map[string]any) {
			config[k] = v
		}
		config["active"] = []string{fmt.Sprint(active)}
		update["config"] = config
		if _, err := a.call(http.MethodPut, providers+"/"+component["id"].(string), update,
			http.StatusNoContent); err != nil {
			t.Fatalf("setting %s active=%v: %v", component["name"], active, err)
		}
	}
	t.Cleanup(func() {
		if _, err := a.call(http.MethodPut, providers+"/"+original["id"].(string), original,
			http.StatusNoContent); err != nil {
			t.Errorf("restoring %s: %v", signingProvider, err)
		}
		for _, component := range listProviders() {
			name, _ := component["name"].(string)
			if name == rotationFixtureProvider || strings.HasPrefix(name, "fallback-") {
				_, _ = a.call(http.MethodDelete, providers+"/"+component["id"].(string), nil, http.StatusNoContent)
			}
		}
	})

	c := internalClient(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil, http.StatusNoContent)
	})
	p := createPrincipal(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil, http.StatusNoContent)
	})
	signedBy := func(step string) string {
		t.Helper()
		token := passwordGrant(t, a, c, p).AccessToken
		if kid, _ := jwtHeader(t, token)["kid"].(string); kid == "" {
			t.Fatalf("%s: the access token carries no kid", step)
		}
		return token
	}
	kidOf := func(token string) string { kid, _ := jwtHeader(t, token)["kid"].(string); return kid }
	verifies := func(token string) error {
		public, err := realmKey(a, kidOf(token))
		if err != nil {
			return err
		}
		if public == nil {
			return fmt.Errorf("the key set holds no key %s", kidOf(token))
		}
		return verifyWith(public, token)
	}
	// state checks the published key set, the realm's active key, and that nothing was generated.
	state := func(step string, wantPublished []string, wantActive string) {
		t.Helper()
		published := publishedKeySet(t, a)
		var kids []string
		for _, key := range published {
			kids = append(kids, key.Kid)
			if key.Kty != "RSA" || key.Alg != "PS256" || key.Use != "sig" {
				t.Errorf("%s: the key set publishes %+v; ADR-IAM-002 §5.1 allows RSA PS256 signing keys alone",
					step, key)
			}
		}
		sort.Strings(kids)
		sort.Strings(wantPublished)
		if strings.Join(kids, " ") != strings.Join(wantPublished, " ") {
			t.Errorf("%s: the key set publishes %v, want %v", step, kids, wantPublished)
		}
		var keys struct {
			Active map[string]string `json:"active"`
			Keys   []struct {
				Kid       string `json:"kid"`
				Algorithm string `json:"algorithm"`
				Status    string `json:"status"`
			} `json:"keys"`
		}
		if err := a.getJSON("/admin/realms/"+realmName+"/keys", &keys); err != nil {
			t.Fatalf("%s: reading the realm's keys: %v", step, err)
		}
		if keys.Active[realmdef.SigningAlgorithm] != wantActive {
			t.Errorf("%s: the realm's active PS256 key is %q, want %s", step, keys.Active["PS256"], wantActive)
		}
		for _, key := range keys.Keys {
			if key.Algorithm == "RS256" && key.Status != "DISABLED" {
				t.Errorf("%s: the realm holds an RS256 key %s in state %s", step, key.Kid, key.Status)
			}
		}
		for _, component := range listProviders() {
			if name, _ := component["name"].(string); strings.HasPrefix(name, "fallback-") {
				t.Errorf("%s: the realm generated %s in-process", step, name)
			}
		}
	}

	state("before", []string{oldKid}, oldKid)

	// staged: the fixture key, enabled and passive.
	realmID := original["parentId"]
	fixture := map[string]any{
		"name": rotationFixtureProvider, "providerId": "java-keystore", "providerType": "org.keycloak.keys.KeyProvider",
		"parentId": realmID,
		"config": map[string][]string{
			"priority": {"300"}, "algorithm": {"PS256"}, "active": {"false"}, "enabled": {"true"},
			"keystore": {"rotation-fixture.p12"}, "keystoreType": {"PKCS12"}, "keyAlias": {"rotation-fixture"},
			"keystorePassword": {"${vault.realm-signing-password}"}, "keyPassword": {"${vault.realm-signing-password}"},
			"kid": {newKid},
		},
	}
	if _, err := a.call(http.MethodPost, providers, fixture, http.StatusCreated); err != nil {
		t.Fatalf("creating the staged provider: %v", err)
	}
	staged := named(rotationFixtureProvider)
	if staged == nil {
		t.Fatal("the staged provider is missing after its creation")
	}
	state("staged", []string{oldKid, newKid}, oldKid)
	beforeRotation := signedBy("staged")
	if kidOf(beforeRotation) != oldKid {
		t.Errorf("staged: a token carries kid %s; a staged key signs nothing, want %s", kidOf(beforeRotation), oldKid)
	}

	// active: the staged key activated first, at the higher priority, and the previous key demoted
	// after, so no moment has no active key, which would make Keycloak generate fallback-PS256.
	setActive(staged, true)
	setActive(original, false)
	state("active, previous retiring", []string{oldKid, newKid}, newKid)
	afterRotation := signedBy("active")
	if kidOf(afterRotation) != newKid {
		t.Errorf("active: a new token carries kid %s, want the new key's %s", kidOf(afterRotation), newKid)
	}
	if err := verifies(beforeRotation); err != nil {
		t.Errorf("overlap: a token the retiring key signed does not verify against the key set: %v", err)
	}
	if err := verifies(afterRotation); err != nil {
		t.Errorf("overlap: a token the active key signed does not verify against the key set: %v", err)
	}

	// Back to the realm's key, which leaves the fixture key retiring: still published, signing nothing.
	setActive(named(signingProvider), true)
	setActive(named(rotationFixtureProvider), false)
	state("fixture retiring", []string{oldKid, newKid}, oldKid)
	if kidOf(signedBy("fixture retiring")) != oldKid {
		t.Error("fixture retiring: a new token is not signed by the active key")
	}
	if err := verifies(afterRotation); err != nil {
		t.Errorf("fixture retiring: a token it signed does not verify against the key set: %v", err)
	}

	// retired or revoked: the provider removed, and the key leaves the key set with it.
	if _, err := a.call(http.MethodDelete, providers+"/"+staged["id"].(string), nil, http.StatusNoContent); err != nil {
		t.Fatalf("removing the fixture's provider: %v", err)
	}
	state("fixture removed", []string{oldKid}, oldKid)
	if err := verifies(afterRotation); err == nil {
		t.Error("removed: a token the removed key signed still verifies against the key set")
	}
	if err := verifies(beforeRotation); err != nil {
		t.Errorf("removed: a token the active key signed does not verify: %v", err)
	}

	summary, _ := json.Marshal(map[string]string{"realm key": oldKid, "fixture key": newKid})
	t.Logf("the key states hold on the pinned image: %s", summary)
	publish(t, "### The key states, on the pinned image\n\nA passive `java-keystore` key is published and "+
		"signs nothing; once active, new tokens carry its `kid` and the passive previous key still verifies "+
		"them; a removed provider's key leaves the key set at once; no step publishes RS256 or makes a "+
		"fallback key (TDD-identity-kernel-002 §Rotation State Machine).\n")
}

// certificateKid reads a certificate named by an environment variable and returns its RFC 7638 kid.
func certificateKid(t *testing.T, variable string) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(variable))
	if path == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatalf("%s is unset", variable)
		}
		t.Skipf("%s is unset", variable)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := realmdef.SigningKeyID(content)
	if err != nil {
		t.Fatalf("%s: %v", variable, err)
	}
	return kid
}

type publishedKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// publishedKeySet reads the realm's key set as a consumer does.
func publishedKeySet(t *testing.T, a *admin) []publishedKey {
	t.Helper()
	response, err := a.http.Get(a.realmURL("/certs"))
	if err != nil {
		t.Fatalf("GET certs: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var set struct {
		Keys []publishedKey `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&set); err != nil {
		t.Fatalf("decoding certs: %v", err)
	}
	return set.Keys
}
