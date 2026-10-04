package compat

// Proof of concept for identity-control's open questions 5 and 7 (TDD-identity-control-002): can
// a Keycloak Organization stand for a Tenant, with the active Tenant chosen per token request and
// carried as a flat tenant_id claim, and what does the kernel do with a token whose Tenant
// membership or Tenant is gone? Asked on a throwaway realm, so the declared realm is untouched.
// Every observation is recorded, none is required yet: the answers feed an ADR.
//
// The realm's token requests here use the password grant of throwaway clients, as the lockout
// proof does: they exercise the kernel's token and refresh logic, which a browser sign-in shares.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestOrganizationsAsTenantContext(t *testing.T) {
	a := requireKeycloak(t)
	realm := "compat-org-" + strings.ToLower(randomToken(t)[:8])
	if _, err := a.call(http.MethodPost, "/admin/realms", map[string]any{
		"realm": realm, "enabled": true, "organizationsEnabled": true,
	}, http.StatusCreated); err != nil {
		t.Fatalf("creating realm %s: %v", realm, err)
	}
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realm, nil, http.StatusNoContent); err != nil {
			t.Errorf("deleting realm %s: %v", realm, err)
		}
	})
	base := "/admin/realms/" + realm

	var steps []lifecycleStep
	record := func(name string, observed bool, detail string) {
		steps = append(steps, lifecycleStep{name: fmt.Sprintf("%s (%s)", name, detail), observed: observed})
	}

	// The organization scope Keycloak creates with the realm, its mapper made single-valued and named
	// tenant_id, so the claim is the selected organization's alias: the Tenant's identifier.
	var scopes []map[string]any
	if err := a.getJSON(base+"/client-scopes", &scopes); err != nil {
		t.Fatal(err)
	}
	scopeID := ""
	for _, s := range scopes {
		if s["name"] == "organization" {
			scopeID, _ = s["id"].(string)
		}
	}
	if scopeID == "" {
		t.Fatal("the realm has no organization client scope")
	}
	var mappers []map[string]any
	if err := a.getJSON(base+"/client-scopes/"+scopeID+"/protocol-mappers/models", &mappers); err != nil {
		t.Fatal(err)
	}
	for _, m := range mappers {
		if m["protocolMapper"] != "oidc-organization-membership-mapper" {
			continue
		}
		config, _ := m["config"].(map[string]any)
		config["multivalued"], config["claim.name"] = "false", "tenant_id"
		config["access.token.claim"], config["id.token.claim"] = "true", "true"
		if _, err := a.call(http.MethodPut, base+"/client-scopes/"+scopeID+"/protocol-mappers/models/"+m["id"].(string),
			m, http.StatusNoContent); err != nil {
			t.Fatalf("configuring the organization mapper: %v", err)
		}
	}

	client := func(body map[string]any) string {
		t.Helper()
		response, err := a.call(http.MethodPost, base+"/clients", body, http.StatusCreated)
		if err != nil {
			t.Fatalf("creating client %v: %v", body["clientId"], err)
		}
		id := created(response)
		// The realm may already give new clients the scope as optional; then attaching it again is
		// refused, and the listing shows it is there.
		if _, err := a.call(http.MethodPut, base+"/clients/"+id+"/optional-client-scopes/"+scopeID, nil,
			http.StatusNoContent); err != nil {
			var optional []map[string]any
			if lerr := a.getJSON(base+"/clients/"+id+"/optional-client-scopes", &optional); lerr != nil ||
				!strings.Contains(fmt.Sprint(optional), scopeID) {
				t.Fatalf("attaching the organization scope: %v", err)
			}
		}
		return id
	}
	client(map[string]any{"clientId": "person-app", "publicClient": true, "directAccessGrantsEnabled": true,
		"standardFlowEnabled": false})
	secret := randomToken(t)
	workloadClient := client(map[string]any{"clientId": "tenant-workload", "publicClient": false, "secret": secret,
		"serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false})

	tenantA, tenantB := "019235f2-4d11-7a03-b8c7-1e9f7a2c4b60", "019235f2-4d11-7a03-b8c7-1e9f7a2c4b61"
	organization := func(alias string) string {
		t.Helper()
		response, err := a.call(http.MethodPost, base+"/organizations", map[string]any{"name": "tenant " + alias,
			"alias": alias, "enabled": true, "domains": []map[string]any{{"name": alias[len(alias)-4:] + ".compat.invalid"}}},
			http.StatusCreated)
		if err != nil {
			t.Fatalf("creating organization %s: %v", alias, err)
		}
		return created(response)
	}
	orgA, orgB := organization(tenantA), organization(tenantB)

	password := randomToken(t)
	response, err := a.call(http.MethodPost, base+"/users", map[string]any{"username": "member", "enabled": true,
		"email": "member@compat.invalid", "emailVerified": true, "firstName": "Member", "lastName": "Person",
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}}}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating the user: %v", err)
	}
	userID := created(response)
	member := func(org, user string) {
		t.Helper()
		if _, err := a.call(http.MethodPost, base+"/organizations/"+org+"/members", user, http.StatusCreated); err != nil {
			t.Fatalf("adding %s to %s: %v", user, org, err)
		}
	}
	member(orgA, userID)
	member(orgB, userID)

	type answer struct {
		status int
		body   map[string]any
	}
	token := func(form url.Values) answer {
		t.Helper()
		r, err := a.http.Post(a.base+"/realms/"+realm+"/protocol/openid-connect/token",
			"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("the token request: %v", err)
		}
		defer func() { _ = r.Body.Close() }()
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		return answer{r.StatusCode, body}
	}
	signIn := func(scope string) answer {
		return token(url.Values{"grant_type": {"password"}, "client_id": {"person-app"}, "username": {"member"},
			"password": {password}, "scope": {scope}})
	}
	refresh := func(from answer, scope string) answer {
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"person-app"},
			"refresh_token": {fmt.Sprint(from.body["refresh_token"])}}
		if scope != "" {
			form.Set("scope", scope)
		}
		return token(form)
	}
	claim := func(an answer) string {
		if an.status != http.StatusOK {
			return fmt.Sprintf("HTTP %d %v", an.status, an.body["error"])
		}
		raw, _ := json.Marshal(jwtClaims(t, fmt.Sprint(an.body["access_token"]))["tenant_id"])
		return string(raw)
	}

	// 5: the active Tenant chosen per token request, as a flat claim.
	inA := signIn("openid organization:" + tenantA)
	record("organization:<A> gives a flat tenant_id of A", claim(inA) == `"`+tenantA+`"`, claim(inA))
	inB := signIn("openid organization:" + tenantB)
	record("a second sign-in with organization:<B> gives B", claim(inB) == `"`+tenantB+`"`, claim(inB))
	plain := signIn("openid organization")
	record("plain organization for a member of two, by password grant", plain.status == http.StatusOK, claim(plain))
	none := signIn("openid")
	record("without the scope the token carries no tenant_id", claim(none) == "null", claim(none))

	// 7: switching within a session.
	again := refresh(inA, "")
	record("a refresh keeps A", claim(again) == `"`+tenantA+`"`, claim(again))
	switched := refresh(inA, "openid organization:"+tenantB)
	record("a refresh asking for B", claim(switched) == `"`+tenantB+`"`, claim(switched))

	// Revocation: the membership removed, then the Tenant suspended (its organization disabled).
	if _, err := a.call(http.MethodDelete, base+"/organizations/"+orgA+"/members/"+userID, nil,
		http.StatusNoContent); err != nil {
		t.Fatalf("removing the member: %v", err)
	}
	afterRemoval := refresh(inA, "")
	record("after the membership is removed, a refresh for A is refused", afterRemoval.status != http.StatusOK,
		claim(afterRemoval))
	refused := signIn("openid organization:" + tenantA)
	record("and a new token for A is refused", refused.status != http.StatusOK, claim(refused))
	stillB := refresh(inB, "")
	record("a session for B is unaffected", claim(stillB) == `"`+tenantB+`"`, claim(stillB))

	var org map[string]any
	if err := a.getJSON(base+"/organizations/"+orgB, &org); err != nil {
		t.Fatal(err)
	}
	org["enabled"] = false
	if _, err := a.call(http.MethodPut, base+"/organizations/"+orgB, org, http.StatusNoContent); err != nil {
		t.Fatalf("disabling organization B: %v", err)
	}
	afterSuspend := refresh(inB, "")
	record("after B is disabled, a refresh for B is refused", afterSuspend.status != http.StatusOK, claim(afterSuspend))

	// A tenant-scoped workload: its service-account user a member, the organization asked for in
	// the client-credentials request.
	var serviceAccount map[string]any
	if err := a.getJSON(base+"/clients/"+workloadClient+"/service-account-user", &serviceAccount); err != nil {
		t.Fatal(err)
	}
	orgC := organization("019235f2-4d11-7a03-b8c7-1e9f7a2c4b62")
	member(orgC, serviceAccount["id"].(string))
	workload := token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"tenant-workload"},
		"client_secret": {secret}, "scope": {"openid organization:019235f2-4d11-7a03-b8c7-1e9f7a2c4b62"}})
	record("a workload's client-credentials token with organization:<C>",
		claim(workload) == `"019235f2-4d11-7a03-b8c7-1e9f7a2c4b62"`, claim(workload))

	var out strings.Builder
	fmt.Fprintf(&out, "## Organizations as Tenant context (proof of concept)\n\n")
	fmt.Fprintf(&out, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&out, "| Observation | Held |\n| :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&out, "| %s | %s |\n", s.name, yesNo(s.observed))
	}
	publish(t, out.String())
}
