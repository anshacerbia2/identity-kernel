package compat

// Names are optional. PAD-PLT-001 minimizes personal data by purpose and lists no name among a
// Principal's PII; identity-control's API accepts none; and a required family name shuts out every
// person who has a single name. Keycloak's default profile requires both firstName and lastName, so
// the realm definition declares them optional -- and a person identity-control created, who has
// neither, must be able to log in without the kernel interrupting the flow to collect them.

import (
	"net/http"
	"testing"
)

func TestAPrincipalWithoutANameCanLogIn(t *testing.T) {
	a := requireKeycloak(t)
	caller := providerCaller(t, a)
	resourceServerFor(t, a, caller)

	p := principal{username: "compat-" + suffix(), password: "Compat-" + suffix() + "!", principalID: uuidV7()}
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/users", map[string]any{
		"username":      p.username,
		"enabled":       true,
		"email":         p.username + "@compat.invalid",
		"emailVerified": true,
		"attributes": map[string][]string{
			"scnehaux_principal_id":   {p.principalID},
			"scnehaux_subject_type":   {"human"},
			"scnehaux_provider_scope": {providerScopeValue},
		},
		"credentials":     []map[string]any{{"type": "password", "value": p.password, "temporary": false}},
		"requiredActions": []string{},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating a Principal without a name: %v", err)
	}
	p.userID = created(response)

	// authorizationCode fails the test if the login is answered with anything but a redirect carrying
	// a code, which is what a profile-completion page would be.
	issued := authorizationCode(t, a, caller, p)
	if got, _ := jwtClaims(t, issued.AccessToken)["principal_id"].(string); got != p.principalID {
		t.Errorf("the nameless Principal's token carries principal_id %q, want %q", got, p.principalID)
	}
}

// Optional, and otherwise Keycloak's own. The definition governs one field of each built-in name
// attribute; the validations Keycloak ships them with stay in force, because a name that is given is
// still held to them.
func TestNameAttributesAreOptionalAndKeepTheirValidations(t *testing.T) {
	a := requireKeycloak(t)
	var profile struct {
		Attributes []map[string]any `json:"attributes"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/users/profile", &profile); err != nil {
		t.Fatalf("reading the user profile: %v", err)
	}
	for _, want := range []string{"firstName", "lastName"} {
		var attribute map[string]any
		for _, candidate := range profile.Attributes {
			if candidate["name"] == want {
				attribute = candidate
			}
		}
		if attribute == nil {
			t.Errorf("the user profile has no %s attribute", want)
			continue
		}
		if required, present := attribute["required"]; present && required != nil {
			t.Errorf("%s is still required: %v", want, required)
		}
		validations, _ := attribute["validations"].(map[string]any)
		if _, ok := validations["length"]; !ok {
			t.Errorf("%s lost Keycloak's length validation: %v", want, attribute["validations"])
		}
	}
}
