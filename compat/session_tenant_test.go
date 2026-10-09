package compat

// A Tenant sign-in on a session a provider sign-in made (ADR-IAM-008, TDD-identity-kernel-001
// §Authentication Levels). One BFF signs its operator in to either privileged form, chosen per
// sign-in. Organization Experience's stack proof signs an operator in as a provider, at aal2 with
// max_age=0, and then asks the same kernel session for organization:<tenant_id> at aal2 -- and the
// kernel answered its own error page ("invalid_user_credentials", no user) where a sign-in in a new
// browser succeeds (organization-experience ROADMAP, production gate).
//
// The test asks the same of the pinned image, the way a browser does, and narrows the cause: a
// session made without max_age and at aal1, and the same session's sign-in without the organization
// scope. A Tenant sign-in that asks for max_age=0 must still ask for the password and the code, and a
// Tenant the person is not a member of must still be refused.

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestATenantSignInOnAProviderSignInsSession(t *testing.T) {
	a := requireKeycloak(t)

	tenant, org := compatOrganization(t, a)
	stranger, _ := compatOrganization(t, a)
	caller := perSignInCaller(t, a)
	// The BFF also asks for scnehaux-profile, the name its application shows (STD-IAM-002 §3.2).
	attachOptionalScope(t, a, caller.uuid, "scnehaux-profile")
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

	// The scopes Organization Experience's BFF asks for (its bff/src/auth/oidc.ts).
	providerScope := "openid scnehaux-provider scnehaux-profile"
	tenantScope := func(alias string) string {
		return "openid scnehaux-privileged organization:" + alias + " scnehaux-profile"
	}

	var steps []lifecycleStep
	require := func(name string, observed, want bool, detail string) {
		steps = append(steps, lifecycleStep{name: name, observed: observed, required: yesNo(want)})
		if observed != want {
			t.Errorf("%s: observed %v, want %v: %s", name, observed, want, detail)
		}
	}
	tenantOf := func(claims map[string]any) string {
		value, _ := claims["tenant_id"].(string)
		return value
	}

	b := newBrowser(t, a, caller, who)
	pages := func() string { return strings.Join(b.pages, ",") }

	// The provider sign-in, as the Admin Portal makes it.
	claims := b.signIn(url.Values{"scope": {providerScope}, "acr_values": {"aal2"}, "max_age": {"0"}})
	require("a provider sign-in at aal2 with max_age 0 carries aal2 and no Tenant",
		claims["acr"] == "aal2" && tenantOf(claims) == "", true, fmt.Sprint(claims["acr"], " ", claims["tenant_id"], " ", pages()))

	// The defect: the Tenant sign-in on that session, within level 2's 300 seconds.
	claims, outcome := b.silentSignIn(url.Values{"scope": {tenantScope(tenant)}, "acr_values": {"aal2"}})
	require("on that session, a Tenant sign-in at aal2 is answered without a page", claims != nil, true, outcome)
	require("and carries that Tenant, the Principal and aal2",
		tenantOf(claims) == tenant && claims["principal_id"] == who.principalID && claims["acr"] == "aal2", true,
		fmt.Sprint(claims["tenant_id"], " ", claims["principal_id"], " ", claims["acr"]))
	steps = append(steps, lifecycleStep{name: "the Tenant sign-in on the provider sign-in's session: " + outcome, observed: true})

	// Back to the provider form on the same session.
	claims, outcome = b.silentSignIn(url.Values{"scope": {providerScope}, "acr_values": {"aal2"}})
	require("then a provider sign-in on the session is answered without a page, and carries no Tenant",
		claims != nil && tenantOf(claims) == "", true, fmt.Sprint(outcome, " ", claims["tenant_id"]))

	// The cause, narrowed: a session made at aal1 without max_age, which the organization scope alone
	// separates from a sign-in that works.
	c := newBrowser(t, a, caller, who)
	claims = c.signIn(url.Values{"scope": {providerScope}})
	require("a provider sign-in asking no level shows the password page alone and carries aal1",
		claims["acr"] == "aal1" && strings.Join(c.pages, ",") == "password", true,
		fmt.Sprint(claims["acr"], " ", strings.Join(c.pages, ",")))
	claims, outcome = c.silentSignIn(url.Values{"scope": {"openid scnehaux-privileged scnehaux-profile"}})
	require("on that session, a sign-in without the organization scope is answered without a page",
		claims != nil && tenantOf(claims) == "", true, outcome)
	claims, outcome = c.silentSignIn(url.Values{"scope": {tenantScope(tenant)}})
	require("on that session, a Tenant sign-in asking no level is answered without a page and carries the Tenant",
		claims != nil && tenantOf(claims) == tenant && claims["acr"] == "aal1", true,
		fmt.Sprint(outcome, " ", claims["tenant_id"], " ", claims["acr"]))
	steps = append(steps, lifecycleStep{name: "the Tenant sign-in on an aal1 session made without max_age: " + outcome,
		observed: true})

	// A Tenant sign-in may still ask for a fresh authentication. A new TOTP step, so the code differs
	// from the one the provider sign-in used.
	time.Sleep(time.Until(time.Unix((time.Now().Unix()/30+1)*30, 0)) + time.Second)
	claims = b.signIn(url.Values{"scope": {tenantScope(tenant)}, "acr_values": {"aal2"}, "max_age": {"0"}})
	require("a Tenant sign-in with max_age 0 asks for the password and the code, and carries the Tenant at aal2",
		pages() == "password,otp" && tenantOf(claims) == tenant && claims["acr"] == "aal2", true,
		fmt.Sprint(pages(), " ", claims["tenant_id"], " ", claims["acr"]))

	// A Tenant the person is not a member of is refused on a session as in a new browser (R13).
	claims, outcome = b.silentSignIn(url.Values{"scope": {tenantScope(stranger)}, "acr_values": {"aal2"}})
	require("on the session, a Tenant the person is not a member of gets no token", claims == nil, true, outcome)
	steps = append(steps, lifecycleStep{name: "a Tenant the person is not a member of: " + outcome, observed: true})

	var out strings.Builder
	fmt.Fprintf(&out, "## A Tenant sign-in on a provider sign-in's session\n\n")
	fmt.Fprintf(&out, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&out, "| Step | Observed | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&out, "| %s | %s | %s |\n", s.name, yesNo(s.observed), orDash(s.required))
	}
	if t.Failed() {
		fmt.Fprintf(&out, "\n**Outcome:** the kernel does not let one session move between the privileged forms.\n")
	} else {
		fmt.Fprintf(&out, "\n**Outcome:** one kernel session serves a provider sign-in and a Tenant sign-in in turn, "+
			"without a page while its level holds; max_age 0 still asks again, and a non-member is refused.\n")
	}
	publish(t, out.String())
}

// compatOrganization creates an enabled Organization, a Tenant, with a uuidv7 alias, and deletes it
// when the test ends. It returns the alias and the Organization's id.
func compatOrganization(t *testing.T, a *admin) (string, string) {
	t.Helper()
	alias := uuidV7()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/organizations", map[string]any{
		"name": "compat " + alias, "alias": alias, "enabled": true,
		"domains": []map[string]any{{"name": strings.ToLower(alias[len(alias)-8:]) + ".compat.invalid"}}},
		http.StatusCreated)
	if err != nil {
		t.Fatalf("creating the organization: %v", err)
	}
	id := created(response)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/organizations/"+id, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting organization %s: %v", alias, err)
		}
	})
	return alias, id
}
