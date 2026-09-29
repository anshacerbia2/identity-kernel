package compat

// The administration client authenticates with a key, end to end (ADR-IAM-001 §5.12). client_keys_
// test.go proves the kernel's mechanism with a hand-built assertion. This proves this repository's
// own signer: internal/admin mints the assertion, finds the audience through discovery, and obtains
// an administrator token that the Admin API honours. realm-apply and client-key both depend on that
// path.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	kcadmin "github.com/anshacerbia2/identity-kernel/internal/admin"
)

func TestTheAdminClientAuthenticatesWithItsKey(t *testing.T) {
	a := requireKeycloak(t)
	key, err := kcadmin.NewClientKey()
	if err != nil {
		t.Fatal(err)
	}
	clientID := "compat-admin-key-" + suffix()
	uuid := masterKeyClient(t, a, clientID, key)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/master/clients/"+uuid, nil, http.StatusNoContent); err != nil {
			t.Errorf("deleting master client %s: %v", clientID, err)
		}
	})

	client, err := kcadmin.New(a.base, &http.Client{Timeout: 20 * time.Second},
		kcadmin.Credentials{ClientID: clientID, ClientKey: &key})
	if err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Realm string `json:"realm"`
	}
	if err := client.GetJSON(context.Background(), "/admin/realms/"+realmName, &realm); err != nil || realm.Realm != realmName {
		t.Fatalf("a service account with a registered key could not read the realm: %v", err)
	}

	// A replaced key stops working at once: the same client, a fresh Client so no token is cached.
	other, err := kcadmin.NewClientKey()
	if err != nil {
		t.Fatal(err)
	}
	setMasterClientKeys(t, a, uuid, other)
	stale, err := kcadmin.New(a.base, &http.Client{Timeout: 20 * time.Second},
		kcadmin.Credentials{ClientID: clientID, ClientKey: &key})
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.GetJSON(context.Background(), "/admin/realms/"+realmName, &realm); err == nil {
		t.Error("a key removed from the client still obtained an administrator token")
	}
}

// masterKeyClient creates a master-realm service account that authenticates with key and holds the
// admin role, the shape create-apply-client.sh gives realm-apply's account.
func masterKeyClient(t *testing.T, a *admin, clientID string, key kcadmin.ClientKey) string {
	t.Helper()
	response, err := a.call(http.MethodPost, "/admin/realms/master/clients", map[string]any{
		"clientId":                  clientID,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"clientAuthenticatorType":   "client-jwt",
		"standardFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    true,
		"attributes": map[string]string{
			"token.endpoint.auth.signing.alg": "PS256",
			"use.jwks.url":                    "false",
			"use.jwks.string":                 "true",
			"jwks.string":                     masterJWKS(t, key),
		},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating master client %s: %v", clientID, err)
	}
	uuid := created(response)

	var user struct {
		ID string `json:"id"`
	}
	if err := a.getJSON("/admin/realms/master/clients/"+uuid+"/service-account-user", &user); err != nil {
		t.Fatalf("reading the service account user: %v", err)
	}
	var role map[string]any
	if err := a.getJSON("/admin/realms/master/roles/admin", &role); err != nil {
		t.Fatalf("reading the master admin role: %v", err)
	}
	if _, err := a.call(http.MethodPost, "/admin/realms/master/users/"+user.ID+"/role-mappings/realm",
		[]map[string]any{role}, http.StatusNoContent); err != nil {
		t.Fatalf("granting the admin role: %v", err)
	}
	return uuid
}

func setMasterClientKeys(t *testing.T, a *admin, uuid string, keys ...kcadmin.ClientKey) {
	t.Helper()
	path := "/admin/realms/master/clients/" + uuid
	var representation map[string]any
	if err := a.getJSON(path, &representation); err != nil {
		t.Fatalf("reading the master client: %v", err)
	}
	attributes, _ := representation["attributes"].(map[string]any)
	attributes["jwks.string"] = masterJWKS(t, keys...)
	representation["attributes"] = attributes
	if _, err := a.call(http.MethodPut, path, representation, http.StatusNoContent); err != nil {
		t.Fatalf("replacing the master client's keys: %v", err)
	}
}

func masterJWKS(t *testing.T, keys ...kcadmin.ClientKey) string {
	t.Helper()
	set := struct {
		Keys []kcadmin.JWK `json:"keys"`
	}{}
	for _, key := range keys {
		set.Keys = append(set.Keys, key.PublicJWK())
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
