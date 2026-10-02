package compat

// The workload profile, asked by identity-control: TDD-identity-control-004 creates a workload as a
// Principal that authenticates as its own client, with a registered key and the client credentials
// grant (ADR-IAM-001 §5.12). STD-IAM-002 §3.2 requires its access token to carry principal_id,
// subject_type=workload and workload_owner, and never acr, auth_time or any Tenant claim.
//
// Two things about the kernel decide how a workload is registered, and this test pins both:
//
//   - A token from the client credentials grant is issued for the client's service-account user, not
//     for any other user.
//   - The realm's built-in acr scope is a realm default, so every new client holds it, and it puts
//     acr=1 in a client credentials token. A workload client therefore does not hold it:
//     identity-control detaches it at registration, and this test detaches it the same way.
//
// Because of the first, a workload's claim-source attributes are those of its service-account user,
// and this test writes them there, as identity-control must. It is the question 1 evidence for the workload profile, which TDD-identity-kernel-001 left open until
// the workload path was built.

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAWorkloadTokenMeetsTheContract(t *testing.T) {
	a := requireKeycloak(t)
	key := newClientKey(t, "compat-workload")
	clientID := "compat-workload-" + suffix()
	clientUUID := keyClient(t, a, clientID, key)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+clientUUID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", clientID, err)
		}
	})
	if _, err := a.call(http.MethodPut,
		"/admin/realms/"+realmName+"/clients/"+clientUUID+"/default-client-scopes/"+scopeIDByName(t, a, "scnehaux-workload"),
		nil, http.StatusNoContent); err != nil {
		t.Fatalf("attaching scnehaux-workload: %v", err)
	}
	detachDefaultScope(t, a, clientUUID, "acr")

	principalID, owner := uuidV7(), uuidV7()
	serviceAccount := writeWorkloadIdentity(t, a, clientUUID, principalID, owner)

	status, body := clientCredentials(t, a, clientID, signAssertion(t, a, clientID, key))
	if status != http.StatusOK {
		t.Fatalf("the workload's client credentials grant answered %d: %s", status, snippet(string(body)))
	}
	var issued struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decoding the token response: %v", err)
	}
	// A workload re-authenticates with its own key rather than continuing a session.
	if issued.RefreshToken != "" {
		t.Error("the workload was issued a refresh token")
	}

	if alg := jwtHeader(t, issued.AccessToken)["alg"]; alg != "PS256" {
		t.Errorf("the workload's access token is signed with %v, want PS256", alg)
	}
	claims := jwtClaims(t, issued.AccessToken)
	for name, want := range map[string]string{
		"principal_id":   principalID,
		"subject_type":   "workload",
		"workload_owner": owner,
	} {
		if claims[name] != want {
			t.Errorf("the workload's access token carries %s=%v, want %s", name, claims[name], want)
		}
	}
	// sub is the service-account user, the protocol subject; principal_id is the enterprise one.
	if claims["sub"] != serviceAccount || claims["sub"] == principalID {
		t.Errorf("sub is %v, want the service-account user %s and never the principal_id", claims["sub"], serviceAccount)
	}
	for _, name := range []string{"acr", "auth_time", "provider_scope",
		"tenant_id", "workspace_id", "membership_version", "tenant_security_version"} {
		if value, present := claims[name]; present {
			t.Errorf("the workload's access token carries %s=%v, which STD-IAM-002 §3.2 prohibits for a workload", name, value)
		}
	}
}

// The workload_owner mapper lives in scnehaux-workload only. A human holding the attribute, through
// a defect or a console edit, still gets no workload_owner in an internal token, so the claim can
// never make a human token look like a workload's.
func TestOnlyTheWorkloadProfileCarriesAWorkloadOwner(t *testing.T) {
	a := requireKeycloak(t)
	client := internalClient(t, a)
	who := createPrincipal(t, a)

	var user map[string]any
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+who.userID, &user); err != nil {
		t.Fatalf("reading the user: %v", err)
	}
	attributes, _ := user["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	attributes["scnehaux_workload_owner"] = []string{uuidV7()}
	user["attributes"] = attributes
	if _, err := a.call(http.MethodPut, "/admin/realms/"+realmName+"/users/"+who.userID, user, http.StatusNoContent); err != nil {
		t.Fatalf("writing workload_owner on a human: %v", err)
	}

	claims := jwtClaims(t, passwordGrant(t, a, client, who).AccessToken)
	if value, present := claims["workload_owner"]; present {
		t.Errorf("an internal token carries workload_owner=%v", value)
	}
}

// writeWorkloadIdentity writes the workload's claim-source attributes on the client's service-account
// user, the one user a client credentials token is issued for, and returns that user's id.
func writeWorkloadIdentity(t *testing.T, a *admin, clientUUID, principalID, owner string) string {
	t.Helper()
	var serviceAccount map[string]any
	if err := a.getJSON("/admin/realms/"+realmName+"/clients/"+clientUUID+"/service-account-user", &serviceAccount); err != nil {
		t.Fatalf("reading the service-account user: %v", err)
	}
	userID, _ := serviceAccount["id"].(string)
	if userID == "" {
		t.Fatal("the workload client has no service-account user")
	}
	var user map[string]any
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+userID, &user); err != nil {
		t.Fatalf("reading the service-account user: %v", err)
	}
	attributes, _ := user["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	attributes["scnehaux_principal_id"] = []string{principalID}
	attributes["scnehaux_subject_type"] = []string{"workload"}
	attributes["scnehaux_workload_owner"] = []string{owner}
	user["attributes"] = attributes
	if _, err := a.call(http.MethodPut, "/admin/realms/"+realmName+"/users/"+userID, user, http.StatusNoContent); err != nil {
		t.Fatalf("writing the workload's identity on its service-account user: %v", err)
	}

	var written struct {
		Attributes map[string][]string `json:"attributes"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+userID, &written); err != nil {
		t.Fatalf("reading the service-account user back: %v", err)
	}
	for name, want := range map[string]string{
		"scnehaux_principal_id": principalID, "scnehaux_subject_type": "workload", "scnehaux_workload_owner": owner,
	} {
		if got := written.Attributes[name]; len(got) != 1 || got[0] != want {
			t.Fatalf("the service-account user holds %s=%v after the write, want [%s]; the declared profile dropped it",
				name, got, want)
		}
	}
	return userID
}

// detachDefaultScope removes a default client scope from a client, as identity-control does for the
// built-in scopes a profile must not carry. A scope the client does not hold is not an error: a
// release that stopped attaching it by default has nothing to detach.
func detachDefaultScope(t *testing.T, a *admin, clientUUID, name string) {
	t.Helper()
	var attached []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	path := "/admin/realms/" + realmName + "/clients/" + clientUUID + "/default-client-scopes"
	if err := a.getJSON(path, &attached); err != nil {
		t.Fatalf("reading the client's default scopes: %v", err)
	}
	for _, scope := range attached {
		if scope.Name != name {
			continue
		}
		t.Logf("the realm attached its %s scope to a new client by default; detaching it", name)
		if _, err := a.call(http.MethodDelete, path+"/"+scope.ID, nil, http.StatusNoContent); err != nil {
			t.Fatalf("detaching %s: %v", name, err)
		}
	}
}
