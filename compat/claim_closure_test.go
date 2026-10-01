package compat

// The claim closure, asked by STD-IAM-002 §3.2: an access token carries the claims the standard
// defines, the ones RFC 9068 §2.2 requires, and the three the kernel writes itself (azp, sid and a
// payload typ), and nothing else: no personal data and no role. A first-party BFF reads the name it
// shows from its ID token, through scnehaux-profile.
//
// The realm's default client scopes are what makes this hold for a new client, so the test first
// asserts the realm's sets, then builds a client the way identity-control registers one and reads
// its tokens.

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// closure is every claim an access token may carry (STD-IAM-002 §3.2, RFC 9068 §2.2).
var closure = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "jti": true, "client_id": true, "scope": true,
	"principal_id": true, "subject_type": true, "tenant_id": true, "workspace_id": true,
	"membership_version": true, "tenant_security_version": true, "provider_scope": true,
	"acr": true, "auth_time": true, "workload_owner": true,
	// Written by the kernel's token code, not by a mapper.
	"azp": true, "sid": true, "typ": true,
}

func TestTheRealmDefaultScopesAreBasicAndAcr(t *testing.T) {
	a := requireKeycloak(t)
	for kind, want := range map[string][]string{
		"default-default-client-scopes":  {"acr", "basic"},
		"default-optional-client-scopes": {},
	} {
		var scopes []struct {
			Name string `json:"name"`
		}
		if err := a.getJSON("/admin/realms/"+realmName+"/"+kind, &scopes); err != nil {
			t.Fatalf("reading %s: %v", kind, err)
		}
		got := []string{}
		for _, scope := range scopes {
			got = append(got, scope.Name)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("the realm's %s are %v, want %v", kind, got, want)
		}
	}
}

func TestAnAccessTokenCarriesOnlyTheClaimsTheStandardAdmits(t *testing.T) {
	a := requireKeycloak(t)
	var steps []lifecycleStep
	require := func(name string, observed bool, detail string) {
		steps = append(steps, lifecycleStep{name: name, observed: observed, required: "yes"})
		if !observed {
			t.Errorf("%s: %s", name, detail)
		}
	}
	outside := func(token string) []string {
		var extra []string
		for _, name := range claimNames(t, token) {
			if !closure[name] {
				extra = append(extra, name)
			}
		}
		return extra
	}

	// A BFF: a confidential client, registered with the internal profile, at+jwt, its client_id
	// mapper, and scnehaux-profile as an optional scope it requests at sign-in.
	key := newClientKey(t, "compat-closure-bff")
	bffID := "compat-closure-bff-" + suffix()
	bff := registeredLikeIdentityControl(t, a, bffID, key, "scnehaux-internal")
	updateClient(t, a, bff, func(c map[string]any) { c["directAccessGrantsEnabled"] = true })
	attachOptionalScope(t, a, bff, "scnehaux-profile")
	user := createPrincipal(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+user.userID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting user %s: %v", user.username, err)
		}
	})
	signIn := passwordGrantWithScope(t, a, bffID, key, user, "openid scnehaux-profile")
	extra := outside(signIn.AccessToken)
	require("user token: no claim outside the closure", len(extra) == 0, fmt.Sprintf("carries %v", extra))
	idClaims := jwtClaims(t, signIn.IDToken)
	require("user sign-in: the ID token carries name and preferred_username",
		idClaims["name"] != nil && idClaims["preferred_username"] == user.username,
		fmt.Sprintf("name %v, preferred_username %v", idClaims["name"], idClaims["preferred_username"]))
	require("user token: principal_id present", jwtClaims(t, signIn.AccessToken)["principal_id"] == user.principalID,
		"the internal profile's claim is missing")

	// A workload: service accounts on, service_account and acr detached, the workload profile.
	workloadKey := newClientKey(t, "compat-closure-job")
	jobID := "compat-closure-job-" + suffix()
	job := registeredLikeIdentityControl(t, a, jobID, workloadKey, "scnehaux-workload")
	detachDefaultScope(t, a, job, "service_account")
	detachDefaultScope(t, a, job, "acr")
	writeWorkloadIdentity(t, a, job, uuidV7(), uuidV7())
	status, body := clientCredentials(t, a, jobID, signAssertion(t, a, jobID, workloadKey))
	if status != http.StatusOK {
		t.Fatalf("the workload's grant answered %d: %s", status, snippet(string(body)))
	}
	workload := accessToken(t, body)
	extra = outside(workload)
	require("workload token: no claim outside the closure", len(extra) == 0, fmt.Sprintf("carries %v", extra))
	require("workload token: client_id from its own mapper", jwtClaims(t, workload)["client_id"] == jobID,
		fmt.Sprintf("client_id is %v", jwtClaims(t, workload)["client_id"]))

	var b strings.Builder
	fmt.Fprintf(&b, "## The claim closure\n\nImage: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Step | Observed | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", s.name, yesNo(s.observed), orDash(s.required))
	}
	fmt.Fprintf(&b, "\nClaims in a user token: `%s`\n\nClaims in a workload token: `%s`\n",
		strings.Join(claimNames(t, signIn.AccessToken), "`, `"), strings.Join(claimNames(t, workload), "`, `"))
	publish(t, b.String())
}

// registeredLikeIdentityControl creates a key-authenticated client as identity-control registers one:
// the at+jwt header, a client_id mapper, and the one audience profile scope as a default scope.
func registeredLikeIdentityControl(t *testing.T, a *admin, clientID string, key clientKey, profile string) string {
	t.Helper()
	clientUUID := keyClient(t, a, clientID, key)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+clientUUID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", clientID, err)
		}
	})
	updateClient(t, a, clientUUID, func(c map[string]any) {
		attributes, _ := c["attributes"].(map[string]any)
		if attributes == nil {
			attributes = map[string]any{}
		}
		attributes["access.token.header.type.rfc9068"] = "true"
		c["attributes"] = attributes
	})
	addClientMapper(t, a, clientUUID, map[string]any{
		"name": "client_id", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
		"config": map[string]string{"claim.name": "client_id", "claim.value": clientID, "jsonType.label": "String",
			"access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true"},
	})
	if _, err := a.call(http.MethodPut, "/admin/realms/"+realmName+"/clients/"+clientUUID+"/default-client-scopes/"+
		scopeIDByName(t, a, profile), nil, http.StatusNoContent); err != nil {
		t.Fatalf("attaching %s: %v", profile, err)
	}
	return clientUUID
}

func attachOptionalScope(t *testing.T, a *admin, clientUUID, scope string) {
	t.Helper()
	if _, err := a.call(http.MethodPut, "/admin/realms/"+realmName+"/clients/"+clientUUID+"/optional-client-scopes/"+
		scopeIDByName(t, a, scope), nil, http.StatusNoContent); err != nil {
		t.Fatalf("attaching %s as optional: %v", scope, err)
	}
}
