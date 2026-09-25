package compat

// The connection the suite runs against, and the realm it asserts.
//
// The realm is applied by internal/realmdef -- the same code cmd/realm-apply runs against a server
// -- so the suite asserts the realm the tool produces rather than one a test helper assembled. In
// CI the tool itself applies it first (see .github/workflows/compat.yml); run by hand against a
// fresh Keycloak, TestMain applies it.
//
// It is applied through the supported Admin API rather than a realm import, and that is a
// correctness choice rather than a style one. A realm import that declares client scopes or key
// providers REPLACES Keycloak's defaults instead of adding to them: the built-in `basic` scope is
// what puts `sub` in a token, and the generated HMAC key is what signs refresh tokens.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kcadmin "github.com/anshacerbia2/identity-kernel/internal/admin"
	"github.com/anshacerbia2/identity-kernel/internal/realmdef"
)

const realmName = "scnehaux"

// keycloak is the connection the suite runs against. Nil when KEYCLOAK_URL is unset.
var keycloak *admin

// admin adapts the shared Admin API client to the suite's helpers.
type admin struct {
	client *kcadmin.Client
	base   string
	http   *http.Client
}

func TestMain(m *testing.M) {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
	if base != "" {
		client, err := kcadmin.New(base, &http.Client{Timeout: 20 * time.Second}, kcadmin.Credentials{
			Username: envOr("KEYCLOAK_ADMIN_USER", "admin"),
			Password: envOr("KEYCLOAK_ADMIN_PASSWORD", "admin"),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "configuring the Admin API client: %v\n", err)
			os.Exit(1)
		}
		keycloak = &admin{client: client, base: client.Base(), http: client.HTTP()}
		if err := ensureApplied(client); err != nil {
			fmt.Fprintf(os.Stderr, "applying the realm definition: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// ensureApplied applies the definition to a Keycloak that does not have the realm yet, and leaves
// one that does alone: the suite asserts the realm, it does not repair it.
func ensureApplied(client *kcadmin.Client) error {
	ctx := context.Background()
	definition, err := realmdef.Load(filepath.Join("..", "realm"))
	if err != nil {
		return err
	}
	record, err := realmdef.ReadRecord(ctx, client, definition.Name())
	if err != nil || record.RealmExists {
		return err
	}
	plan, err := realmdef.NewPlan(ctx, client, definition, nil)
	if err != nil {
		return err
	}
	return realmdef.Apply(ctx, client, plan, realmdef.Options{Environment: realmdef.Local, Revision: "compat"})
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

func readFile(name string) ([]byte, error) {
	content, err := os.ReadFile(filepath.Join("..", "realm", name))
	if err != nil {
		return nil, fmt.Errorf("reading realm/%s: %w", name, err)
	}
	return content, nil
}

// ---------------------------------------------------------------------------------------------
// Admin API, in the shape the suite's helpers use
// ---------------------------------------------------------------------------------------------

// call sends one Admin API request and returns the response with its body readable.
func (a *admin) call(method, path string, body any, want int) (*http.Response, error) {
	response, err := a.client.Call(context.Background(), method, path, body, want)
	if response == nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: response.Status,
		Header:     response.Header,
		Body:       io.NopCloser(bytes.NewReader(response.Body)),
	}, err
}

func (a *admin) getJSON(path string, into any) error {
	return a.client.GetJSON(context.Background(), path, into)
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

// created returns the identifier Keycloak put in the Location header of a 201.
func created(response *http.Response) string {
	location := response.Header.Get("Location")
	return location[strings.LastIndex(location, "/")+1:]
}
