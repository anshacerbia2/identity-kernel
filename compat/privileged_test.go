package compat

// The tenant-scoped form of the privileged profile (STD-IAM-002 §3.1.1, §3.2.1, ADR-IAM-006 §5.3).
//
// A privileged operation inside one Tenant, such as administering it at Organization Control
// (ADR-ORG-003 §5.3), needs a token carrying principal_id, subject_type, acr and auth_time, and the
// tenant_id of the Tenant asked for at sign-in. The kernel realizes the form through the
// scnehaux-privileged client scope, beside the kernel's organization scope held as optional. Without
// organization:<tenant_id> in the request the token carries no Tenant, and it never carries
// provider_scope.
//
// Obtained by Authorization Code with PKCE S256, as the provider form is: auth_time is the instant
// of an authentication ceremony, which a direct grant does not have.

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestATenantScopedPrivilegedTokenMeetsItsProfile(t *testing.T) {
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

	caller := privilegedCaller(t, a)
	resource := resourceServerFor(t, a, caller)
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

	before := time.Now().Add(-time.Minute).Unix()
	claims := jwtClaims(t, authorizationCodeWithScope(t, a, caller, who, "openid organization:"+tenant).AccessToken)
	for name, want := range map[string]string{
		"principal_id": who.principalID,
		"subject_type": "human",
		"tenant_id":    tenant,
	} {
		if got, _ := claims[name].(string); got != want {
			t.Errorf("the tenant-scoped privileged token carries %s=%v, want %q", name, claims[name], want)
		}
	}
	if acr, _ := claims["acr"].(string); acr == "" {
		t.Errorf("the tenant-scoped privileged token carries no acr (got %v); STD-IAM-002 §3.2 makes it mandatory", claims["acr"])
	}
	authTime, ok := claims["auth_time"].(float64)
	if !ok || int64(authTime) < before || int64(authTime) > time.Now().Add(time.Minute).Unix() {
		t.Errorf("the tenant-scoped privileged token carries auth_time %v, want the instant of the login just performed",
			claims["auth_time"])
	}
	for _, name := range []string{"provider_scope", "organization", "workspace_id", "membership_version",
		"tenant_security_version", "workload_owner"} {
		if value, present := claims[name]; present {
			t.Errorf("the tenant-scoped privileged token carries %s=%v, which the profile prohibits", name, value)
		}
	}
	if !audienceNames(claims["aud"], resource.id) {
		t.Errorf("the token's aud %v does not name the resource it was issued for (%s)", claims["aud"], resource.id)
	}

	// Without a Tenant asked for, the same client's token carries none (ADR-IAM-006 §5.2).
	plain := jwtClaims(t, authorizationCode(t, a, caller, who).AccessToken)
	if value, present := plain["tenant_id"]; present {
		t.Errorf("a sign-in asking for no Tenant got tenant_id=%v", value)
	}
	if acr, _ := plain["acr"].(string); acr == "" {
		t.Errorf("a sign-in asking for no Tenant got no acr (got %v)", plain["acr"])
	}
}

// privilegedCaller registers a client the way a tenant-scoped privileged caller is registered:
// Authorization Code with PKCE S256, no password grant, scnehaux-privileged attached as a default
// scope and the kernel's organization scope as an optional one.
func privilegedCaller(t *testing.T, a *admin) client {
	t.Helper()
	clientID := "compat-privileged-" + suffix()
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
		t.Fatalf("creating the privileged caller: %v", err)
	}
	c := client{uuid: created(response), id: clientID, secret: secret}
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", clientID, err)
		}
	})
	if _, err := a.call(http.MethodPut,
		"/admin/realms/"+realmName+"/clients/"+c.uuid+"/default-client-scopes/"+scopeIDByName(t, a, "scnehaux-privileged"),
		nil, http.StatusNoContent); err != nil {
		t.Fatalf("attaching scnehaux-privileged: %v", err)
	}
	attachOptionalScope(t, a, c.uuid, "organization")
	return c
}
