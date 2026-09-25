package compat

// Proof-of-concept question 3: attribute immutability.
//
// TDD-identity-kernel-001 leaves one thing open: whether the declarative user profile stops an
// ADMINISTRATOR from changing scnehaux_principal_id, or only the user. The answer decides whether
// immutability is enforced by Keycloak, or rests on identity-control's narrow Admin API role set plus
// reconciler detection -- a reduced guarantee the design says is recorded rather than assumed away.
//
// Asked of the declared profile alone, the question has a known answer: edit=["admin"] grants
// administrators edit by construction, and it has to, because identity-control writes the attribute
// at creation. The question worth running is whether ANY declarative configuration gives write-once
// -- settable through the Admin API at creation, refused afterwards. So a probe attribute nobody may
// edit is added to the profile and tried both ways.
//
// Immutability also fails without anyone editing: an unrelated write that drops the attribute
// erases the identifier as surely as a change does. Quarantine is exactly such a write in
// TDD-identity-control-001 -- a PUT that disables the user -- so the partial update is probed too.
//
// The self-service half is not a question. The declared profile excludes the user from edit, and a
// realm where a user can rewrite their own identifier fails the suite.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTheUserCannotChangeTheirOwnIdentifier(t *testing.T) {
	a := requireKeycloak(t)
	client := internalClient(t, a)
	who := createPrincipal(t, a)
	token := passwordGrant(t, a, client, who).AccessToken

	status, body := asUser(t, a, http.MethodGet, token, nil)
	if status != http.StatusOK {
		t.Fatalf("the account API answered %d to the user's own token: %s", status, body)
	}
	var self struct {
		Attributes map[string]any `json:"attributes"`
	}
	if err := json.Unmarshal(body, &self); err != nil {
		t.Fatalf("the account API returned something other than JSON: %s", body)
	}
	if value, present := self.Attributes["scnehaux_principal_id"]; present {
		t.Errorf("account self-service shows scnehaux_principal_id=%v to its user; the profile grants "+
			"view to admin only", value)
	}

	update := func(firstName string, attributes map[string][]string) (int, []byte) {
		return asUser(t, a, http.MethodPost, token, map[string]any{
			"username":   who.username,
			"email":      who.username + "@compat.invalid",
			"firstName":  firstName,
			"lastName":   "Principal",
			"attributes": attributes,
		})
	}

	// The positive control. Every verdict below is "the identifier did not change", and an account
	// API that refused this user everything would produce that verdict for the wrong reason.
	if status, body := update("Renamed", nil); status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("the account API refused an ordinary self-service edit with %d: %s -- the probe below "+
			"would prove nothing", status, body)
	}
	after := adminUser(t, a, who.userID)
	if after.FirstName != "Renamed" {
		t.Fatalf("the account API accepted an ordinary edit and did not apply it (firstName %q): the "+
			"probe below would prove nothing", after.FirstName)
	}
	if got := after.Attributes["scnehaux_principal_id"]; len(got) != 1 || got[0] != who.principalID {
		t.Errorf("an ordinary self-service edit left scnehaux_principal_id %v, want [%s]: the user erased "+
			"their identifier without touching it", got, who.principalID)
	}

	status, body = update("Renamed", map[string][]string{
		"scnehaux_principal_id": {uuidV7()},
		"scnehaux_subject_type": {"workload"},
	})
	t.Logf("the account API answered %d to a self-service change of the identifier: %s", status, body)
	after = adminUser(t, a, who.userID)
	if got := after.Attributes["scnehaux_principal_id"]; len(got) != 1 || got[0] != who.principalID {
		t.Errorf("a user changed their own scnehaux_principal_id to %v (was %s): the self-service "+
			"mutation path is open", got, who.principalID)
	}
	if got := after.Attributes["scnehaux_subject_type"]; len(got) != 1 || got[0] != "human" {
		t.Errorf("a user changed their own scnehaux_subject_type to %v", got)
	}
}

func TestQuestion3AdministratorImmutability(t *testing.T) {
	a := requireKeycloak(t)
	var rows [][3]string

	// The declared profile.
	who := createPrincipal(t, a)
	status, body := adminSetAttribute(t, a, who.userID, "scnehaux_principal_id", uuidV7())
	t.Logf("an administrator's change of scnehaux_principal_id answered %d: %s", status, body)
	if got := adminUser(t, a, who.userID).Attributes["scnehaux_principal_id"]; len(got) == 1 && got[0] == who.principalID {
		rows = append(rows, [3]string{"declared profile, admin change", "refused", "enforced by Keycloak"})
	} else {
		rows = append(rows, [3]string{"declared profile, admin change", fmt.Sprintf("**applied** (%d)", status),
			"any holder of manage-users can rewrite an identifier"})
	}

	// Write-once: an attribute nobody may edit, written at creation and then changed.
	probe := "compat_write_once_" + strings.ReplaceAll(suffix(), "-", "_")
	if err := a.editProfile(func(attributes []any) []any {
		return append(attributes, map[string]any{
			"name":        probe,
			"displayName": "compat write-once probe",
			"permissions": map[string][]string{"view": {"admin"}, "edit": {}},
			"multivalued": false,
		})
	}); err != nil {
		t.Fatalf("adding the write-once probe attribute: %v", err)
	}
	defer func() {
		if err := a.editProfile(func(attributes []any) []any {
			kept := attributes[:0]
			for _, attribute := range attributes {
				if m, ok := attribute.(map[string]any); !ok || m["name"] != probe {
					kept = append(kept, attribute)
				}
			}
			return kept
		}); err != nil {
			t.Errorf("removing the write-once probe attribute: %v", err)
		}
	}()

	original := uuidV7()
	holder, createErr := newPrincipalWith(a, map[string][]string{probe: {original}})
	var storedAtCreate, changedAfter bool
	switch {
	case createErr != nil:
		t.Logf("creating a user with the edit-for-nobody attribute was refused: %v", createErr)
		rows = append(rows, [3]string{"edit-for-nobody attribute, set at creation", "**refused**", "—"})
	default:
		got := adminUser(t, a, holder.userID).Attributes[probe]
		storedAtCreate = len(got) == 1 && got[0] == original
		if storedAtCreate {
			rows = append(rows, [3]string{"edit-for-nobody attribute, set at creation", "stored", "—"})
		} else {
			rows = append(rows, [3]string{"edit-for-nobody attribute, set at creation",
				fmt.Sprintf("**dropped** (holds %v)", got), "—"})
		}
	}
	if storedAtCreate {
		status, body := adminSetAttribute(t, a, holder.userID, probe, uuidV7())
		t.Logf("an administrator's change of the edit-for-nobody attribute answered %d: %s", status, body)
		got := adminUser(t, a, holder.userID).Attributes[probe]
		changedAfter = !(len(got) == 1 && got[0] == original)
		if changedAfter {
			rows = append(rows, [3]string{"edit-for-nobody attribute, admin change", "**applied**", "—"})
		} else {
			rows = append(rows, [3]string{"edit-for-nobody attribute, admin change",
				fmt.Sprintf("refused (%d)", status), "—"})
		}
	}

	// Incidental erasure: a disable sent as a partial representation, the way a quarantine would.
	target := createPrincipal(t, a)
	if _, err := a.call(http.MethodPut, "/admin/realms/"+realmName+"/users/"+target.userID,
		map[string]any{"enabled": false}, http.StatusNoContent); err != nil {
		t.Fatalf("disabling a user with a partial representation: %v", err)
	}
	disabled := adminUser(t, a, target.userID)
	if disabled.Enabled {
		t.Errorf("a PUT of {\"enabled\": false} left the user enabled: quarantine by partial update does nothing")
	}
	if got := disabled.Attributes["scnehaux_principal_id"]; len(got) == 1 && got[0] == target.principalID {
		rows = append(rows, [3]string{"disable by partial PUT", "identifier kept", "quarantine may send {enabled:false}"})
	} else {
		rows = append(rows, [3]string{"disable by partial PUT", fmt.Sprintf("**identifier erased** (holds %v)", got),
			"quarantine must PUT the full representation it just read, never a partial one"})
	}
	if disabled.Email == "" || disabled.FirstName == "" {
		rows = append(rows, [3]string{"disable by partial PUT", fmt.Sprintf("**profile fields erased** "+
			"(email %q, firstName %q)", disabled.Email, disabled.FirstName), "as above"})
	}

	verdict := "**detected, not enforced** -- no declarative configuration gives write-once; immutability " +
		"rests on identity-control's narrow Admin API role set plus reconciler detection"
	if storedAtCreate && !changedAfter {
		verdict = "**enforceable** -- an attribute nobody may edit is still written at creation through the " +
			"Admin API and refused afterwards; declaring scnehaux_principal_id that way makes Keycloak enforce it"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Proof-of-concept question 3: attribute immutability for administrators\n\n")
	fmt.Fprintf(&b, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Probe | Answer | Consequence |\n| :-- | :-- | :-- |\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", row[0], row[1], row[2])
	}
	fmt.Fprintf(&b, "\n**Answer:** %s\n", verdict)
	publish(t, b.String())
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

type userRepresentation struct {
	Enabled    bool                `json:"enabled"`
	Email      string              `json:"email"`
	FirstName  string              `json:"firstName"`
	Attributes map[string][]string `json:"attributes"`
}

func adminUser(t *testing.T, a *admin, userID string) userRepresentation {
	t.Helper()
	var user userRepresentation
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+userID, &user); err != nil {
		t.Fatalf("reading user %s: %v", userID, err)
	}
	return user
}

// adminSetAttribute changes one attribute the way a careful administrator would: read the whole
// representation, change the one value, write the whole thing back. It returns the answer rather
// than judging it, because whether Keycloak accepts the write is what is being asked.
func adminSetAttribute(t *testing.T, a *admin, userID, name, value string) (int, string) {
	t.Helper()
	path := "/admin/realms/" + realmName + "/users/" + userID
	var user map[string]any
	if err := a.getJSON(path, &user); err != nil {
		t.Fatalf("reading user %s: %v", userID, err)
	}
	attributes, _ := user["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	attributes[name] = []string{value}
	user["attributes"] = attributes

	response, err := a.call(http.MethodPut, path, user, http.StatusNoContent)
	if response == nil {
		t.Fatalf("writing user %s: %v", userID, err)
	}
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(raw)
}

// newPrincipalWith creates a Principal carrying extra attributes beside the canonical ones.
func newPrincipalWith(a *admin, extra map[string][]string) (principal, error) {
	p := principal{username: "compat-" + suffix(), principalID: uuidV7()}
	attributes := map[string][]string{
		"scnehaux_principal_id": {p.principalID},
		"scnehaux_subject_type": {"human"},
	}
	for name, values := range extra {
		attributes[name] = values
	}
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/users", map[string]any{
		"username":      p.username,
		"enabled":       true,
		"email":         p.username + "@compat.invalid",
		"emailVerified": true,
		"firstName":     "Compat",
		"lastName":      "Principal",
		"attributes":    attributes,
	}, http.StatusCreated)
	if err != nil {
		return p, err
	}
	p.userID = created(response)
	return p, nil
}

// asUser calls the account REST API with the user's own token -- the self-service path.
func asUser(t *testing.T, a *admin, method, token string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequest(method, a.base+"/realms/"+realmName+"/account", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	// Without it the account endpoint serves the console application instead of the REST API.
	request.Header.Set("Accept", "application/json")
	if reader != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := a.http.Do(request)
	if err != nil {
		t.Fatalf("%s account API: %v", method, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, raw
}
