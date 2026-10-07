package compat

// Consents, asked by identity-control (TDD-identity-control-005 §Self-Service as Built, slice 3b).
// A person's consents are to be listed and withdrawn through the Admin API, as identity-control does
// everything else. This asks the pinned image what a client that requires consent does: whether the
// sign-in shows the consent page once, whether GET users/{id}/consents lists the grant with its
// scopes, and whether DELETE users/{id}/consents/{clientId} withdraws it, ends what was issued on
// it, and brings the consent page back.
//
// The consent page lists only client scopes marked "display on consent screen", and with none to
// list, 26.7.5 shows no page and records no consent (AuthenticationManager
// .getClientScopesToApproveOnConsentScreen). Every scope this realm declares is marked false, so the
// test adds one of its own.

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
)

type recordedConsent struct {
	ClientID            string   `json:"clientId"`
	GrantedClientScopes []string `json:"grantedClientScopes"`
	CreatedDate         int64    `json:"createdDate"`
}

func TestAConsentIsListedAndWithdrawnThroughTheAdminAPI(t *testing.T) {
	a := requireKeycloak(t)
	clientID := "compat-consent-" + suffix()
	secret := "compat-" + suffix()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/clients", map[string]any{
		"clientId": clientID, "protocol": "openid-connect", "publicClient": false, "secret": secret,
		"standardFlowEnabled": true, "directAccessGrantsEnabled": false, "consentRequired": true,
		"redirectUris": []string{providerRedirect},
		"attributes":   map[string]string{"pkce.code.challenge.method": "S256"},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating a client that requires consent: %v", err)
	}
	c := client{uuid: created(response), id: clientID, secret: secret}
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil, http.StatusNoContent)
	})
	scopeName := "compat-consent-" + suffix()
	response, err = a.call(http.MethodPost, "/admin/realms/"+realmName+"/client-scopes", map[string]any{
		"name": scopeName, "protocol": "openid-connect",
		"attributes": map[string]string{"display.on.consent.screen": "true", "consent.screen.text": "Compat consent",
			"include.in.token.scope": "true"},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating a scope shown on the consent screen: %v", err)
	}
	scopeID := created(response)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/client-scopes/"+scopeID, nil, http.StatusNoContent)
	})
	if _, err := a.call(http.MethodPut, "/admin/realms/"+realmName+"/clients/"+c.uuid+"/default-client-scopes/"+scopeID,
		nil, http.StatusNoContent); err != nil {
		t.Fatalf("attaching the scope: %v", err)
	}
	p := createPrincipal(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil, http.StatusNoContent)
	})
	consentsPath := "/admin/realms/" + realmName + "/users/" + p.userID + "/consents"
	consents := func() []recordedConsent {
		t.Helper()
		var out []recordedConsent
		if err := a.getJSON(consentsPath, &out); err != nil {
			t.Fatalf("listing the consents: %v", err)
		}
		return out
	}
	refreshes := func(token string) bool {
		status, _ := tokenRequest(t, a, url.Values{"grant_type": {"refresh_token"}, "client_id": {c.id},
			"client_secret": {c.secret}, "refresh_token": {token}})
		return status == http.StatusOK
	}
	b := newBrowser(t, a, c, p)

	if listed := consents(); len(listed) != 0 {
		t.Fatalf("before any sign-in the person holds consents %+v", listed)
	}
	b.signIn(nil)
	if !slices.Contains(b.pages, "consent") {
		t.Errorf("the first sign-in to a client that requires consent showed pages %v, with no consent page", b.pages)
	}
	listed := consents()
	if len(listed) != 1 || listed[0].ClientID != c.id || !slices.Contains(listed[0].GrantedClientScopes, scopeName) ||
		listed[0].CreatedDate == 0 {
		t.Fatalf("after consenting the person's consents read %+v; want one for %s, naming %s, with its date", listed, c.id,
			scopeName)
	}
	t.Logf("the granted scopes as listed: %v", listed[0].GrantedClientScopes)
	granted := b.refresh

	// The consent is remembered: a second sign-in, in a new browser, does not ask again.
	again := newBrowser(t, a, c, p)
	again.signIn(nil)
	if slices.Contains(again.pages, "consent") {
		t.Errorf("a second sign-in asked for consent again; pages %v", again.pages)
	}
	if !refreshes(granted) {
		t.Fatal("the refresh token issued on the consent does not refresh before the withdrawal")
	}

	// The withdrawal: the consent goes, what was issued on it stops refreshing, and the next sign-in
	// asks again.
	if _, err := a.call(http.MethodDelete, consentsPath+"/"+url.PathEscape(c.id), nil, http.StatusNoContent); err != nil {
		t.Fatalf("withdrawing the consent: %v", err)
	}
	if listed := consents(); len(listed) != 0 {
		t.Errorf("after the withdrawal the person's consents read %+v", listed)
	}
	if refreshes(granted) || refreshes(again.refresh) {
		t.Error("a refresh token issued on the withdrawn consent still refreshes")
	}
	after := newBrowser(t, a, c, p)
	after.signIn(nil)
	if !slices.Contains(after.pages, "consent") {
		t.Errorf("the sign-in after the withdrawal showed pages %v, with no consent page", after.pages)
	}

	// A second withdrawal answers 404 ("Consent nor offline token not found"): recorded, not required.
	// identity-control treats a consent already gone as withdrawn either way.
	if _, err := a.call(http.MethodDelete, consentsPath+"/"+url.PathEscape(c.id), nil, http.StatusNotFound); err != nil {
		t.Logf("a second withdrawal did not answer 404: %v", err)
	}
}
