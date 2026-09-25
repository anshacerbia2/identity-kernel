package compat

// Proof-of-concept question 4: the issuer URI form.
//
// Keycloak derives iss as {frontend URL}/realms/{realm name}. TDD-identity-kernel-001 asks whether
// the /realms/{name} segment can be removed while staying on supported configuration, and records
// the answer before the first token either way, because iss is irreversible once tokens carrying it
// have been accepted and downstream domains have stored it beside principal_id in evidence:
//
//	a vendor-neutral issuer is supported   iss carries no vendor or realm name
//	the path form is retained              a realm rename or kernel change becomes an issuer migration
//
// Keycloak offers two supported inputs to the issuer: the server's hostname (which may carry a
// path) and a realm's frontendUrl attribute, which overrides it per realm. They are the same knob at
// two scopes, so the probe turns the per-realm one -- on a throwaway realm, because the realm the
// rest of the suite asserts must keep its issuer -- and watches what moves. A hostname path cannot
// be changed on a running server, and it composes the same way frontendUrl does.
//
// The probe also renames the throwaway realm, because the realm name is the other half of the path
// form: if a rename moves iss, the name is as irreversible as the hostname.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestQuestion4IssuerURIForm(t *testing.T) {
	a := requireKeycloak(t)
	realm := "compat-issuer-" + suffix()
	if _, err := a.call(http.MethodPost, "/admin/realms", map[string]any{"realm": realm, "enabled": true},
		http.StatusCreated); err != nil {
		t.Fatalf("creating the throwaway realm: %v", err)
	}
	current := realm
	defer func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+current, nil, http.StatusNoContent); err != nil {
			t.Errorf("deleting the throwaway realm %s: %v", current, err)
		}
	}()

	type probe struct{ input, issuer string }
	var probes []probe
	segmentRemoved := false
	observe := func(input, name string) string {
		t.Helper()
		issuer := discoveredIssuer(t, a, name)
		probes = append(probes, probe{input, issuer})
		if !strings.HasSuffix(issuer, "/realms/"+name) {
			segmentRemoved = true
		}
		return issuer
	}

	if got, want := observe("defaults", current), a.base+"/realms/"+current; got != want {
		t.Errorf("the default issuer is %q, want %q", got, want)
	}

	for _, frontend := range []string{"https://issuer.compat.invalid", "https://issuer.compat.invalid/identity"} {
		if _, err := a.call(http.MethodPut, "/admin/realms/"+current, map[string]any{
			"realm": current, "attributes": map[string]string{"frontendUrl": frontend},
		}, http.StatusNoContent); err != nil {
			t.Fatalf("setting frontendUrl %s: %v", frontend, err)
		}
		if got, want := observe("frontendUrl "+frontend, current), frontend+"/realms/"+current; got != want {
			t.Errorf("with frontendUrl %s the issuer is %q, want %q", frontend, got, want)
		}
	}

	renamed := current + "-renamed"
	if _, err := a.call(http.MethodPut, "/admin/realms/"+current, map[string]any{"realm": renamed},
		http.StatusNoContent); err != nil {
		t.Fatalf("renaming the throwaway realm: %v", err)
	}
	current = renamed
	renamedIssuer := observe("realm renamed to "+renamed, current)
	renameMovesIssuer := strings.HasSuffix(renamedIssuer, "/realms/"+renamed)

	answer := "**path form retained** -- every supported input changes only the prefix; the issuer always " +
		"ends in /realms/{realm name}"
	if segmentRemoved {
		answer = "**a vendor-neutral issuer is supported** -- a supported input produced an issuer without " +
			"/realms/{realm name}"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## Proof-of-concept question 4: issuer URI form\n\n")
	fmt.Fprintf(&b, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Input | Issuer |\n| :-- | :-- |\n")
	for _, p := range probes {
		fmt.Fprintf(&b, "| %s | `%s` |\n", p.input, p.issuer)
	}
	fmt.Fprintf(&b, "\n**Answer:** %s\n", answer)
	if renameMovesIssuer {
		fmt.Fprintf(&b, "\nRenaming a realm moves its issuer: the realm name is as irreversible as the hostname.\n")
	}
	publish(t, b.String())

	// The issuer form is now the contract. Answered as the path form against the pinned release; a
	// release that changes how iss is composed changes what every consumer and evidence record holds.
	if segmentRemoved && loadContract(t).Question4.PathFormRetained {
		t.Error("REGRESSION: realm/contract.json records the issuer as {frontend}/realms/{realm}, and this " +
			"release composes it differently -- an issuer change for every stored iss")
	}
}

func discoveredIssuer(t *testing.T, a *admin, realm string) string {
	t.Helper()
	response, err := a.http.Get(a.base + "/realms/" + realm + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("reading discovery for %s: %v", realm, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("discovery for %s answered %d: %s", realm, response.StatusCode, body)
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &discovery); err != nil || discovery.Issuer == "" {
		t.Fatalf("discovery for %s carries no issuer: %s", realm, body)
	}
	return discovery.Issuer
}
