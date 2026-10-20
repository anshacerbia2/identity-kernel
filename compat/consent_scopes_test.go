package compat

// Consent follows the audience class (STD-IAM-002 1.9.0 §3.6, ADR-IAM-003 §5.11,
// TDD-identity-kernel-001 1.21.0 §Consent). An external registration requires consent, and every
// scope it releases is shown on the consent screen; an internal, privileged or workload registration
// never asks. identity-control sets the client's consent from its class; the realm marks the scopes an
// external client releases: the realm defaults basic and acr, and scnehaux-external.
//
// This signs a person in to two clients registered the way identity-control registers them, one
// external and one first-party, and asserts that only the external one shows the consent page, that
// the page lists each released scope by its text, and that the consent records those scopes.

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// externalScopes are the scopes an external registration holds: the realm's default client scopes
// and its audience scope (TDD-identity-control-003, realm/default-client-scopes.json).
var externalScopes = []string{"basic", "acr", "scnehaux-external"}

// consentText is each scope's line on the consent page in the reference bundle
// (themes/scnehaux/login/messages/messages_en.properties).
var consentText = map[string]string{
	"basic":             "An identifier for your account, and when you signed in",
	"acr":               "How you signed in: with a password alone, or with a second factor",
	"scnehaux-external": "Sign you in with your Scnehaux account",
}

// registeredClient creates a confidential, authorization-code client holding the audience scope, with
// consent set as identity-control derives it from the class.
func registeredClient(t *testing.T, a *admin, scope string, consent bool) client {
	t.Helper()
	clientID := "compat-" + strings.TrimPrefix(scope, "scnehaux-") + "-" + suffix()
	secret := "compat-" + suffix()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/clients", map[string]any{
		"clientId": clientID, "protocol": "openid-connect", "publicClient": false, "secret": secret,
		"standardFlowEnabled": true, "directAccessGrantsEnabled": false, "serviceAccountsEnabled": false,
		"consentRequired": consent, "redirectUris": []string{providerRedirect},
		"attributes": map[string]string{"pkce.code.challenge.method": "S256",
			"access.token.signed.response.alg": "PS256"},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating %s: %v", clientID, err)
	}
	c := client{uuid: created(response), id: clientID, secret: secret}
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil, http.StatusNoContent)
	})
	if _, err := a.call(http.MethodPut,
		"/admin/realms/"+realmName+"/clients/"+c.uuid+"/default-client-scopes/"+scopeIDByName(t, a, scope),
		nil, http.StatusNoContent); err != nil {
		t.Fatalf("attaching %s: %v", scope, err)
	}
	return c
}

func TestAnExternalClientAsksConsentForWhatItReleasesAndAFirstPartyOneDoesNot(t *testing.T) {
	a := requireKeycloak(t)

	// The realm marks exactly the scopes an external client releases, each with its text.
	var scopes []struct {
		Name       string            `json:"name"`
		Attributes map[string]string `json:"attributes"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/client-scopes", &scopes); err != nil {
		t.Fatalf("listing the client scopes: %v", err)
	}
	for _, scope := range scopes {
		if !slices.Contains(externalScopes, scope.Name) {
			continue
		}
		if scope.Attributes["display.on.consent.screen"] != "true" || scope.Attributes["consent.screen.text"] == "" {
			t.Errorf("%s is released to an external client and is not shown on the consent screen: %v", scope.Name,
				scope.Attributes)
		}
	}

	external := registeredClient(t, a, "scnehaux-external", true)
	firstParty := registeredClient(t, a, "scnehaux-internal", false)
	p := createPrincipal(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil, http.StatusNoContent)
	})

	own := newBrowser(t, a, firstParty, p)
	own.signIn(nil)
	if slices.Contains(own.pages, "consent") {
		t.Errorf("a first-party client asked for consent; pages %v", own.pages)
	}

	b := newBrowser(t, a, external, p)
	b.signIn(nil)
	if !slices.Contains(b.pages, "consent") || len(b.consentPages) != 1 {
		t.Fatalf("an external client's first sign-in showed pages %v, with no consent page", b.pages)
	}
	for _, scope := range externalScopes {
		if !strings.Contains(b.consentPages[0], consentText[scope]) {
			t.Errorf("the consent page does not list %s as %q", scope, consentText[scope])
		}
	}

	var consents []recordedConsent
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+p.userID+"/consents", &consents); err != nil {
		t.Fatalf("listing the consents: %v", err)
	}
	if len(consents) != 1 || consents[0].ClientID != external.id {
		t.Fatalf("the person's consents read %+v; want one, for %s alone", consents, external.id)
	}
	for _, scope := range externalScopes {
		if !slices.Contains(consents[0].GrantedClientScopes, scope) {
			t.Errorf("the consent records %v, without %s", consents[0].GrantedClientScopes, scope)
		}
	}
}
