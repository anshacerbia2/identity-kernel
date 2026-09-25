package compat

// The Admin API client and the apply step.
//
// The realm is applied through the supported Admin API rather than a realm import, and that is a
// correctness choice rather than a style one. A realm import that declares client scopes or key
// providers REPLACES Keycloak's defaults instead of adding to them: the built-in `basic` scope is
// what puts `sub` in a token, and the generated HMAC key is what signs refresh tokens. An import
// declaring only ours would produce tokens without `sub` and a realm that cannot refresh -- and a
// coverage probe against that realm would report a missing claim as a Keycloak limitation.
//
// So realm/scnehaux.json carries the realm's own settings, and everything that must sit beside the
// defaults is added to them here, the way TDD-identity-kernel-001 says configuration is applied.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const realmName = "scnehaux"

// keycloak is the connection the suite runs against. Nil when KEYCLOAK_URL is unset.
var keycloak *admin

type admin struct {
	base     string
	http     *http.Client
	user     string
	password string
}

func TestMain(m *testing.M) {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
	if base != "" {
		keycloak = &admin{
			base:     base,
			http:     &http.Client{Timeout: 20 * time.Second},
			user:     envOr("KEYCLOAK_ADMIN_USER", "admin"),
			password: envOr("KEYCLOAK_ADMIN_PASSWORD", "admin"),
		}
		if err := keycloak.apply(); err != nil {
			fmt.Fprintf(os.Stderr, "applying the realm definition: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// requireKeycloak skips without a Keycloak, unless integration is required.
func requireKeycloak(t *testing.T) *admin {
	t.Helper()
	if keycloak == nil {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and KEYCLOAK_URL is empty: the Keycloak this suite " +
				"asserts against never came up")
		}
		t.Skip("KEYCLOAK_URL is unset")
	}
	return keycloak
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

// ---------------------------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------------------------

func (a *admin) apply() error {
	realm, err := readFile("scnehaux.json")
	if err != nil {
		return err
	}
	if _, err := a.call(http.MethodPost, "/admin/realms", realm, http.StatusCreated); err != nil {
		return fmt.Errorf("creating the realm: %w", err)
	}

	var rep struct {
		ID string `json:"id"`
	}
	if err := a.getJSON("/admin/realms/"+realmName, &rep); err != nil {
		return fmt.Errorf("reading the realm: %w", err)
	}

	// PS256 at 3072 bits. The realm's defaultSignatureAlgorithm selects PS256, and only a key of that
	// algorithm can satisfy it. 3072 because foundation-platform's verifier discards any smaller
	// modulus while parsing the key set -- silently, so a 2048-bit realm would have every token in
	// the estate refused with a message about key distribution.
	//
	// Generated in-process, which TDD-identity-kernel-002 prohibits in production. Acceptable for a
	// throwaway proof-of-concept instance and named here so it is not copied into one that is not.
	key := map[string]any{
		"name":         "rsa-ps256-3072",
		"providerId":   "rsa-generated",
		"providerType": "org.keycloak.keys.KeyProvider",
		"parentId":     rep.ID,
		"config": map[string][]string{
			"priority":  {"200"},
			"keySize":   {"3072"},
			"algorithm": {"PS256"},
			"active":    {"true"},
			"enabled":   {"true"},
		},
	}
	if _, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/components", key, http.StatusCreated); err != nil {
		return fmt.Errorf("adding the PS256 key provider: %w", err)
	}

	scopesRaw, err := readFile("client-scopes.json")
	if err != nil {
		return err
	}
	var scopes []json.RawMessage
	if err := json.Unmarshal(scopesRaw, &scopes); err != nil {
		return fmt.Errorf("parsing client-scopes.json: %w", err)
	}
	for _, scope := range scopes {
		if _, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/client-scopes", scope,
			http.StatusCreated); err != nil {
			return fmt.Errorf("creating a client scope: %w", err)
		}
	}

	return a.mergeUserProfile()
}

// mergeUserProfile adds our attributes to the live profile rather than replacing it.
//
// PUT replaces the whole configuration, and the default one declares username, email, firstName
// and lastName. Replacing it with ours alone would remove username from the profile -- a realm in
// which no user can be created. So the live configuration is read, ours appended, and the result
// written back.
//
// It has to happen before any user is created. Since Keycloak 24 an attribute the profile does not
// declare is unmanaged and dropped on write, so a user created first would silently lose
// scnehaux_principal_id -- and the mapper probe would then report "not covered" for a claim whose
// source was never stored.
func (a *admin) mergeUserProfile() error {
	oursRaw, err := readFile("user-profile.json")
	if err != nil {
		return err
	}
	var ours struct {
		Attributes []map[string]any `json:"attributes"`
	}
	if err := json.Unmarshal(oursRaw, &ours); err != nil {
		return fmt.Errorf("parsing user-profile.json: %w", err)
	}

	return a.editProfile(func(existing []any) []any {
		present := map[string]bool{}
		for _, attribute := range existing {
			if m, ok := attribute.(map[string]any); ok {
				if name, ok := m["name"].(string); ok {
					present[name] = true
				}
			}
		}
		for _, attribute := range ours.Attributes {
			if name, _ := attribute["name"].(string); !present[name] {
				existing = append(existing, attribute)
			}
		}
		return existing
	})
}

// editProfile reads the live user profile, lets edit change its attribute list, and writes the
// whole configuration back -- the only way the Admin API updates it.
func (a *admin) editProfile(edit func(attributes []any) []any) error {
	path := "/admin/realms/" + realmName + "/users/profile"
	var live map[string]any
	if err := a.getJSON(path, &live); err != nil {
		return fmt.Errorf("reading the user profile: %w", err)
	}
	existing, _ := live["attributes"].([]any)
	live["attributes"] = edit(existing)
	if _, err := a.call(http.MethodPut, path, live, http.StatusOK); err != nil {
		return fmt.Errorf("writing the user profile: %w", err)
	}
	return nil
}

func readFile(name string) ([]byte, error) {
	content, err := os.ReadFile(filepath.Join("..", "realm", name))
	if err != nil {
		return nil, fmt.Errorf("reading realm/%s: %w", name, err)
	}
	return content, nil
}

// ---------------------------------------------------------------------------------------------
// Admin API
// ---------------------------------------------------------------------------------------------

// token is fetched per call. Admin tokens live for a minute by default, and the suite is short
// enough that caching one would be an optimisation with a failure mode.
func (a *admin) token() (string, error) {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {a.user},
		"password":   {a.password},
	}
	response, err := a.http.PostForm(a.base+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		return "", fmt.Errorf("reaching Keycloak: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("admin login answered %d: %s", response.StatusCode, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("admin login returned no access token")
	}
	return out.AccessToken, nil
}

// call sends one Admin API request and returns the response with its body read.
func (a *admin) call(method, path string, body any, want int) (*http.Response, error) {
	token, err := a.token()
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	case json.RawMessage:
		reader = bytes.NewReader(b)
	default:
		encoded, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, a.base+path, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if reader != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := a.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, _ := io.ReadAll(response.Body)
	response.Body = io.NopCloser(bytes.NewReader(raw))
	if response.StatusCode != want {
		return response, fmt.Errorf("%s %s answered %d, want %d: %s", method, path, response.StatusCode, want, raw)
	}
	return response, nil
}

func (a *admin) getJSON(path string, into any) error {
	response, err := a.call(http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return err
	}
	return json.NewDecoder(response.Body).Decode(into)
}

// created returns the identifier Keycloak put in the Location header of a 201.
func created(response *http.Response) string {
	location := response.Header.Get("Location")
	return location[strings.LastIndex(location, "/")+1:]
}
