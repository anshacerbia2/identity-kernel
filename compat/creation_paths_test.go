package compat

// The closed creation paths of TDD-identity-kernel-001 §Closing Unauthorized Creation Paths, the ones
// TDD-identity-kernel-005's declared realm contract names beside self-registration and the
// user-editable attribute (contract_test.go, immutability_test.go): federated auto-creation, and user
// creation through the Admin Console. A candidate release that reopens either fails here.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const firstBrokerLoginFlow = "scnehaux-first-broker-login-v1"

// The kernel's own first login flow runs Create User If Unique, which "creates a new local {project_name}
// account and links it with the identity provider" (Server Administration Guide, First login flow), an
// account no Principal maps. The realm binds a flow that denies it instead, so an identity provider
// added without a flow of its own creates no user.
func TestFederatedFirstLoginCreatesNoUser(t *testing.T) {
	a := requireKeycloak(t)
	var realm struct {
		FirstBrokerLoginFlow string `json:"firstBrokerLoginFlow"`
	}
	if err := a.getJSON("/admin/realms/"+realmName, &realm); err != nil {
		t.Fatalf("reading the realm: %v", err)
	}
	if realm.FirstBrokerLoginFlow != firstBrokerLoginFlow {
		t.Fatalf("the realm's first login flow is %q, want %q, which denies", realm.FirstBrokerLoginFlow, firstBrokerLoginFlow)
	}

	var executions []struct {
		ProviderID  string `json:"providerId"`
		Requirement string `json:"requirement"`
		Level       int    `json:"level"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/authentication/flows/"+url.PathEscape(firstBrokerLoginFlow)+
		"/executions", &executions); err != nil {
		t.Fatalf("reading the flow's executions: %v", err)
	}
	if len(executions) != 1 || executions[0].ProviderID != "deny-access-authenticator" || executions[0].Requirement != "REQUIRED" {
		t.Errorf("the first login flow runs %+v, want deny-access-authenticator REQUIRED and nothing else", executions)
	}

	// What a provider added without naming a flow inherits. Recorded: whether the kernel copies the
	// realm's binding onto the provider, or leaves it empty and resolves it at sign-in, both close the path.
	alias := "compat-idp-" + suffix()
	if _, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/identity-provider/instances", map[string]any{
		"alias": alias, "providerId": "oidc", "enabled": false,
		"config": map[string]string{"clientId": "compat", "clientSecret": "compat-" + suffix(),
			"authorizationUrl": "https://idp.compat.invalid/auth", "tokenUrl": "https://idp.compat.invalid/token",
			"clientAuthMethod": "client_secret_post"},
	}, http.StatusCreated); err != nil {
		t.Fatalf("adding an identity provider: %v", err)
	}
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/identity-provider/instances/"+alias, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting the identity provider: %v", err)
		}
	})
	var provider struct {
		FirstBrokerLoginFlowAlias string `json:"firstBrokerLoginFlowAlias"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/identity-provider/instances/"+alias, &provider); err != nil {
		t.Fatalf("reading the identity provider: %v", err)
	}
	switch provider.FirstBrokerLoginFlowAlias {
	case "", firstBrokerLoginFlow:
		publish(t, "## Federated first login\n\nA provider added without a flow of its own takes `"+
			provider.FirstBrokerLoginFlowAlias+"` (empty: the realm's binding, resolved at sign-in).\n")
	default:
		t.Errorf("a provider added without a flow of its own takes %q: the realm's binding does not reach it, "+
			"and its first login creates a user", provider.FirstBrokerLoginFlowAlias)
	}
}

// Admin Console user creation is restricted (TDD-identity-kernel-001): in the realm, only a service
// account holds manage-users or realm-admin, directly or through a group, so no person signs in to the
// console and creates a user beside identity-control's path.
func TestOnlyServiceAccountsManageUsers(t *testing.T) {
	a := requireKeycloak(t)
	var clients []struct {
		ID string `json:"id"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/clients?clientId=realm-management", &clients); err != nil || len(clients) != 1 {
		t.Fatalf("finding realm-management: %v, %d found", err, len(clients))
	}
	for _, role := range []string{"manage-users", "realm-admin"} {
		base := "/admin/realms/" + realmName + "/clients/" + clients[0].ID + "/roles/" + role
		var users []struct {
			Username string `json:"username"`
		}
		if err := a.getJSON(base+"/users?max=1000", &users); err != nil {
			t.Fatalf("reading who holds %s: %v", role, err)
		}
		for _, user := range users {
			if !strings.HasPrefix(user.Username, "service-account-") {
				t.Errorf("%s holds %s: a person could create a user in the console", user.Username, role)
			}
		}
		var groups []struct {
			Name string `json:"name"`
		}
		if err := a.getJSON(base+"/groups", &groups); err != nil {
			t.Fatalf("reading which groups hold %s: %v", role, err)
		}
		for _, group := range groups {
			t.Errorf("the group %s holds %s: every member could create a user in the console", group.Name, role)
		}
	}
}
