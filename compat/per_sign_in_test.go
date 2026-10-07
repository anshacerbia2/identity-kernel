package compat

// The per-sign-in privileged form (ADR-IAM-008, STD-IAM-002 1.7.0 §3.1.1).
//
// One confidential client holds both privileged form scopes and the kernel's organization scope, all
// optional, so a token carries a form only when the authorization request names one. A Tenant
// sign-in asks for scnehaux-privileged organization:<tenant_id> and gets that Tenant in the access
// token and the ID token, where the client checks it on the callback. A provider sign-in asks for
// scnehaux-provider and gets no Tenant in either. A refresh keeps each form, in the ID token too,
// which the BFF holds to the Tenant its session was issued for. A sign-in naming neither form gets
// no principal_id, which every resource refuses.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestOneClientObtainsEachPrivilegedFormPerSignIn(t *testing.T) {
	a := requireKeycloak(t)

	tenant := uuidV7()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/organizations", map[string]any{
		"name": "compat " + tenant, "alias": tenant, "enabled": true,
		"domains": []map[string]any{{"name": strings.ToLower(tenant[len(tenant)-8:]) + ".compat.invalid"}}},
		http.StatusCreated)
	if err != nil {
		t.Fatalf("creating the organization: %v", err)
	}
	org := created(response)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/organizations/"+org, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting organization %s: %v", tenant, err)
		}
	})

	caller := perSignInCaller(t, a)
	who := providerPrincipal(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+who.userID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting user %s: %v", who.username, err)
		}
	})
	if _, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/organizations/"+org+"/members", who.userID,
		http.StatusCreated); err != nil {
		t.Fatalf("adding the member: %v", err)
	}

	// The Tenant form: the Tenant asked for, in both tokens.
	inTenant := authorizationCodeWithScope(t, a, caller, who, "openid scnehaux-privileged organization:"+tenant)
	access, id := jwtClaims(t, inTenant.AccessToken), jwtClaims(t, inTenant.IDToken)
	for name, token := range map[string]map[string]any{"access": access, "ID": id} {
		if got, _ := token["tenant_id"].(string); got != tenant {
			t.Errorf("the Tenant sign-in's %s token carries tenant_id=%v, want %s", name, token["tenant_id"], tenant)
		}
		if got, _ := token["principal_id"].(string); got != who.principalID {
			t.Errorf("the Tenant sign-in's %s token carries principal_id=%v, want %s", name, token["principal_id"],
				who.principalID)
		}
	}
	if scopes := scopeNames(access); !slices.Contains(scopes, "scnehaux-privileged") || slices.Contains(scopes, "scnehaux-provider") {
		t.Errorf("the Tenant sign-in's access token has scope %v, want scnehaux-privileged and not scnehaux-provider", scopes)
	}

	// A refresh keeps the Tenant, in the ID token as well as the access token (ADR-IAM-006 §5.2).
	refreshed := secretRefresh(t, a, caller, inTenant)
	for name, token := range map[string]string{"access": refreshed.AccessToken, "ID": refreshed.IDToken} {
		if token == "" {
			t.Errorf("the Tenant refresh returned no %s token", name)
			continue
		}
		if got, _ := jwtClaims(t, token)["tenant_id"].(string); got != tenant {
			t.Errorf("the Tenant refresh's %s token carries tenant_id=%v, want %s", name, jwtClaims(t, token)["tenant_id"],
				tenant)
		}
	}

	// The provider form: no Tenant in either token.
	provider := authorizationCodeWithScope(t, a, caller, who, "openid scnehaux-provider")
	access, id = jwtClaims(t, provider.AccessToken), jwtClaims(t, provider.IDToken)
	for name, token := range map[string]map[string]any{"access": access, "ID": id} {
		if value, present := token["tenant_id"]; present {
			t.Errorf("the provider sign-in's %s token carries tenant_id=%v; the provider form prohibits it", name, value)
		}
		if got, _ := token["principal_id"].(string); got != who.principalID {
			t.Errorf("the provider sign-in's %s token carries principal_id=%v, want %s", name, token["principal_id"],
				who.principalID)
		}
		if acr, _ := token["acr"].(string); acr == "" {
			t.Errorf("the provider sign-in's %s token carries no acr (got %v)", name, token["acr"])
		}
	}
	if scopes := scopeNames(access); !slices.Contains(scopes, "scnehaux-provider") || slices.Contains(scopes, "scnehaux-privileged") {
		t.Errorf("the provider sign-in's access token has scope %v, want scnehaux-provider and not scnehaux-privileged", scopes)
	}
	refreshed = secretRefresh(t, a, caller, provider)
	for name, token := range map[string]string{"access": refreshed.AccessToken, "ID": refreshed.IDToken} {
		if token == "" {
			continue
		}
		if value, present := jwtClaims(t, token)["tenant_id"]; present {
			t.Errorf("the provider refresh's %s token carries tenant_id=%v", name, value)
		}
	}

	// Neither form: no principal_id, so no resource accepts the token.
	none := jwtClaims(t, authorizationCode(t, a, caller, who).AccessToken)
	for _, name := range []string{"principal_id", "subject_type", "tenant_id"} {
		if value, present := none[name]; present {
			t.Errorf("a sign-in naming no form got %s=%v", name, value)
		}
	}
}

// perSignInCaller registers a client the way identity-control registers the per-sign-in form
// (ADR-IAM-008 §5.1): confidential, Authorization Code with PKCE S256, no form scope among the
// defaults, and scnehaux-provider, scnehaux-privileged and organization as optional scopes.
func perSignInCaller(t *testing.T, a *admin) client {
	t.Helper()
	clientID := "compat-per-sign-in-" + suffix()
	secret := "compat-" + suffix()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/clients", map[string]any{
		"clientId":                  clientID,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"secret":                    secret,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    false,
		"redirectUris":              []string{providerRedirect},
		"attributes": map[string]string{
			"pkce.code.challenge.method":       "S256",
			"access.token.signed.response.alg": "PS256",
		},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating the per-sign-in caller: %v", err)
	}
	c := client{uuid: created(response), id: clientID, secret: secret}
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", clientID, err)
		}
	})
	for _, scope := range []string{"scnehaux-provider", "scnehaux-privileged", "organization"} {
		attachOptionalScope(t, a, c.uuid, scope)
	}
	return c
}

// secretRefresh redeems a sign-in's refresh token as the confidential client, asking for no scope,
// as the BFF does.
func secretRefresh(t *testing.T, a *admin, c client, from issuedTokens) issuedTokens {
	t.Helper()
	var tokens issuedTokens
	body := postForm(t, a, a.realmURL("/token"), url.Values{
		"grant_type": {"refresh_token"}, "client_id": {c.id}, "client_secret": {c.secret},
		"refresh_token": {from.RefreshToken}})
	if err := json.Unmarshal(body, &tokens); err != nil {
		t.Fatalf("reading the refresh response: %v", err)
	}
	return tokens
}

// scopeNames splits an access token's scope claim.
func scopeNames(claims map[string]any) []string {
	scope, _ := claims["scope"].(string)
	return strings.Fields(scope)
}
