package compat

// User containment, asked by identity-control: TDD-identity-control-005 suspends a Principal by
// disabling its user and ending its sessions, restores it by enabling the user, ends every session on
// its own, and revokes one authenticator by deleting the credential. Each is an Admin API call the
// executor makes idempotently and confirms by reading back, so this test asserts both the effect on
// the user's tokens and what each read-back shows, on every upgrade.
//
// identity-control writes `enabled` with a partial PUT of the user. The test asserts that the
// partial update leaves the user's attributes as they were, because scnehaux_principal_id is one.
//
// One answer is recorded and not required: whether a disable alone, without the logout, pauses the
// user's sessions or ends them. A client's disable only pauses them (client_lifecycle_test.go), and
// the answer decides whether a suspension could rest on the disable alone. identity-control's
// suspension logs the user out either way.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAUserIsContainedAndRestoredThroughTheAdminAPI(t *testing.T) {
	a := requireKeycloak(t)
	c := internalClient(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", c.id, err)
		}
	})
	p := createPrincipal(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting user %s: %v", p.username, err)
		}
	})
	userPath := "/admin/realms/" + realmName + "/users/" + p.userID

	var steps []lifecycleStep
	record := func(name string, observed bool) {
		steps = append(steps, lifecycleStep{name: name, observed: observed})
	}
	require := func(name string, observed, want bool, detail string) {
		steps = append(steps, lifecycleStep{name: name, observed: observed, required: yesNo(want)})
		if observed != want {
			t.Errorf("%s: observed %v, want %v: %s", name, observed, want, snippet(detail))
		}
	}
	signIn := func() (string, bool, string) {
		status, body := tokenRequest(t, a, url.Values{
			"grant_type": {"password"}, "client_id": {c.id}, "client_secret": {c.secret},
			"username": {p.username}, "password": {p.password}, "scope": {"openid"},
		})
		var out struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.Unmarshal(body, &out)
		return out.RefreshToken, status == http.StatusOK && out.RefreshToken != "", string(body)
	}
	refresh := func(refreshToken string) (bool, string) {
		status, body := tokenRequest(t, a, url.Values{
			"grant_type": {"refresh_token"}, "client_id": {c.id}, "client_secret": {c.secret},
			"refresh_token": {refreshToken},
		})
		return status == http.StatusOK, string(body)
	}
	setEnabled := func(enabled bool) {
		t.Helper()
		if _, err := a.call(http.MethodPut, userPath, map[string]any{"enabled": enabled}, http.StatusNoContent); err != nil {
			t.Fatalf("setting enabled=%v: %v", enabled, err)
		}
	}
	logout := func() {
		t.Helper()
		if _, err := a.call(http.MethodPost, userPath+"/logout", nil, http.StatusNoContent); err != nil {
			t.Fatalf("logging the user out: %v", err)
		}
	}
	readUser := func() (bool, string) {
		t.Helper()
		var user struct {
			Enabled    bool                `json:"enabled"`
			Attributes map[string][]string `json:"attributes"`
		}
		if err := a.getJSON(userPath, &user); err != nil {
			t.Fatalf("reading the user: %v", err)
		}
		id := ""
		if values := user.Attributes["scnehaux_principal_id"]; len(values) == 1 {
			id = values[0]
		}
		return user.Enabled, id
	}
	sessions := func() int {
		t.Helper()
		var list []map[string]any
		if err := a.getJSON(userPath+"/sessions", &list); err != nil {
			t.Fatalf("listing the sessions: %v", err)
		}
		return len(list)
	}

	session, ok, body := signIn()
	require("active: a sign-in", ok, true, body)
	require("active: the session is listed", sessions() == 1, true, "")

	// Disable alone first: whether it pauses or ends the session is recorded.
	setEnabled(false)
	enabled, principalID := readUser()
	require("disabled: the user reads back disabled", !enabled, true, "")
	require("disabled by a partial update: scnehaux_principal_id is kept", principalID == p.principalID, true, principalID)
	_, ok, body = signIn()
	require("disabled: a sign-in", ok, false, body)
	ok, body = refresh(session)
	require("disabled: the refresh token issued before", ok, false, body)
	setEnabled(true)
	ok, _ = refresh(session)
	record("enabled again without a logout: the refresh token issued before", ok)

	// The suspension identity-control performs: disable, then log out.
	session, ok, body = signIn()
	require("before suspension: a sign-in", ok, true, body)
	setEnabled(false)
	logout()
	require("suspended: the session list is empty", sessions() == 0, true, "")
	ok, body = refresh(session)
	require("suspended: the refresh token issued before", ok, false, body)
	logout()
	record("suspended: a second logout is accepted", true)

	// Restore: enable, and no session comes back.
	setEnabled(true)
	enabled, principalID = readUser()
	require("restored: the user reads back enabled", enabled, true, "")
	require("restored by a partial update: scnehaux_principal_id is kept", principalID == p.principalID, true, principalID)
	ok, body = refresh(session)
	require("restored: the refresh token from before the suspension", ok, false, body)
	session, ok, body = signIn()
	require("restored: a new sign-in", ok, true, body)

	// Terminate every session, without a suspension.
	logout()
	require("logged out: the session list is empty", sessions() == 0, true, "")
	ok, body = refresh(session)
	require("logged out: the refresh token issued before", ok, false, body)

	// Revoke the one authenticator.
	var credentials []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := a.getJSON(userPath+"/credentials", &credentials); err != nil {
		t.Fatalf("listing the credentials: %v", err)
	}
	require("the credential list holds the password", len(credentials) == 1 && credentials[0].Type == "password", true,
		fmt.Sprint(credentials))
	if len(credentials) == 1 {
		if _, err := a.call(http.MethodDelete, userPath+"/credentials/"+credentials[0].ID, nil, http.StatusNoContent); err != nil {
			t.Fatalf("deleting the credential: %v", err)
		}
		credentials = nil
		if err := a.getJSON(userPath+"/credentials", &credentials); err != nil {
			t.Fatalf("listing the credentials again: %v", err)
		}
		require("revoked: the credential reads back absent", len(credentials) == 0, true, fmt.Sprint(credentials))
		_, ok, body = signIn()
		require("revoked: a sign-in with the password", ok, false, body)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## User containment\n\n")
	fmt.Fprintf(&b, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Step | Observed | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", s.name, yesNo(s.observed), orDash(s.required))
	}
	if t.Failed() {
		fmt.Fprintf(&b, "\n**Outcome:** a user is not contained as TDD-identity-control-005 assumes; "+
			"suspension, restoration or revocation cannot be built on these calls as designed.\n")
	} else {
		fmt.Fprintf(&b, "\n**Outcome:** a disabled and logged-out user signs in to nothing and refreshes "+
			"nothing; enabled again, it signs in afresh and no session returns; a deleted credential "+
			"reads back absent and no longer signs in.\n")
	}
	publish(t, b.String())
}

// tokenRequest posts to the token endpoint and returns the status, whatever it is.
func tokenRequest(t *testing.T, a *admin, form url.Values) (int, []byte) {
	t.Helper()
	response, err := a.http.PostForm(a.realmURL("/token"), form)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, body
}
