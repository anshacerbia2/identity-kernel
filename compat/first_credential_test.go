package compat

// The first credential of a person a provider created (ADR-IAM-010, TDD-identity-kernel-001 §Password
// Policy). identity-control creates the user with UPDATE_PASSWORD and no credential, then sets a
// temporary password through the Admin API's reset-password. This test does both as identity-control
// does, signs the person in through the hosted pages, and asserts what ADR-IAM-010 relies on:
//   - the temporary password forces a change at the first sign-in;
//   - the same value is refused as the new password, which only the realm's passwordHistory does;
//   - the temporary value signs in no more once changed, and a deleted one signs in no more;
//   - no event carries the value (STD-IAM-001 2.8.0 §3.1), and which events mark the issuance and the
//     change, for identity-control's mapping.

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// createLikeIdentityControl creates a human user the way identity-control's POST /v1/principals does:
// its identifier and subject type, an email, UPDATE_PASSWORD outstanding and no credential.
func createLikeIdentityControl(t *testing.T, a *admin) principal {
	t.Helper()
	p := principal{username: "compat-first-" + suffix(), principalID: uuidV7()}
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/users", map[string]any{
		"username": p.username, "enabled": true, "email": p.username + "@compat.invalid",
		"attributes": map[string][]string{
			"scnehaux_principal_id": {p.principalID},
			"scnehaux_subject_type": {"human"},
		},
		"requiredActions": []string{"UPDATE_PASSWORD"},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating the user: %v", err)
	}
	p.userID = created(response)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil, http.StatusNoContent)
	})
	return p
}

// issueTemporary is identity-control's issuance: reset-password with temporary true.
func issueTemporary(t *testing.T, a *admin, p principal, value string) {
	t.Helper()
	if _, err := a.call(http.MethodPut, "/admin/realms/"+realmName+"/users/"+p.userID+"/reset-password",
		map[string]any{"type": "password", "value": value, "temporary": true}, http.StatusNoContent); err != nil {
		t.Fatalf("setting the temporary password: %v", err)
	}
}

func requiredActions(t *testing.T, a *admin, p principal) []string {
	t.Helper()
	var user struct {
		RequiredActions []string `json:"requiredActions"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+p.userID, &user); err != nil {
		t.Fatalf("reading the user: %v", err)
	}
	return user.RequiredActions
}

func hasAction(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

// passwordRefused submits secret on the login page of a fresh browser, and reports whether the kernel
// answered with the login page again rather than going on, and what the page said.
func passwordRefused(t *testing.T, a *admin, c client, p principal, secret string) (bool, string) {
	t.Helper()
	b := newBrowser(t, a, c, p)
	request, _ := b.authorizationRequest(nil)
	response, page := b.send(request)
	for step := 0; step < 4 && (response.StatusCode == http.StatusFound || response.StatusCode == http.StatusSeeOther); step++ {
		request, _ = http.NewRequest(http.MethodGet, response.Header.Get("Location"), nil)
		response, page = b.send(request)
	}
	action := formAction.FindStringSubmatch(page)
	if response.StatusCode != http.StatusOK || action == nil || !namedInput("password").MatchString(page) {
		t.Fatalf("the authorization request did not reach the login page: %d %q", response.StatusCode, pageMessage(page))
	}
	form := url.Values{"username": {p.username}, "password": {secret}}
	base, _ := url.Parse(a.base)
	target, err := base.Parse(html.UnescapeString(action[1]))
	if err != nil {
		t.Fatalf("the login page's form action %q: %v", action[1], err)
	}
	request, _ = http.NewRequest(http.MethodPost, target.String(), strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, page = b.send(request)
	refused := response.StatusCode == http.StatusOK && namedInput("password").MatchString(page) &&
		!namedInput("password-new").MatchString(page)
	return refused, pageMessage(page)
}

// rawEvents reads a person's user events, or the admin events on its resource path, as the kernel
// stores them.
func rawEvents(t *testing.T, a *admin, p principal, since time.Time) (users, admins []map[string]any) {
	t.Helper()
	if err := a.getJSON("/admin/realms/"+realmName+"/events?user="+p.userID+"&max=200", &users); err != nil {
		t.Fatalf("reading the user events: %v", err)
	}
	var all []map[string]any
	if err := a.getJSON("/admin/realms/"+realmName+"/admin-events?max=1000&dateFrom="+
		since.UTC().Format("2006-01-02"), &all); err != nil {
		t.Fatalf("reading the admin events: %v", err)
	}
	for _, e := range all {
		if path, _ := e["resourcePath"].(string); strings.HasPrefix(path, "users/"+p.userID) {
			admins = append(admins, e)
		}
	}
	return users, admins
}

// userMark is a user event's type, error and the details that tell it apart; never a value.
func userMark(e map[string]any) string {
	var keys []string
	details, _ := e["details"].(map[string]any)
	for k, v := range details {
		switch k {
		case "credential_type", "custom_required_action", "reason", "auth_method":
			keys = append(keys, fmt.Sprintf("%s=%v", k, v))
		}
	}
	sort.Strings(keys)
	mark, _ := e["type"].(string)
	if failure, _ := e["error"].(string); failure != "" {
		mark += " error=" + failure
	}
	if len(keys) > 0 {
		mark += " (" + strings.Join(keys, ", ") + ")"
	}
	return mark
}

// adminMark is an admin event's operation, resource type and path with the user's id elided, and
// whether it carries a representation.
func adminMark(e map[string]any, p principal) string {
	path, _ := e["resourcePath"].(string)
	path = strings.Replace(path, p.userID, "{id}", 1)
	if i := strings.Index(path, "/credentials/"); i >= 0 {
		path = path[:i] + "/credentials/{credentialId}"
	}
	representation := "no representation"
	if r, _ := e["representation"].(string); r != "" {
		representation = "a representation"
	}
	return fmt.Sprintf("%v %v %s, %s", e["operationType"], e["resourceType"], path, representation)
}

func TestAFirstCredentialIsChangedAtFirstSignInAndNeverKept(t *testing.T) {
	a := requireKeycloak(t)
	started := time.Now().Add(-time.Minute)

	var realm struct {
		PasswordPolicy       string `json:"passwordPolicy"`
		ResetPasswordAllowed bool   `json:"resetPasswordAllowed"`
	}
	if err := a.getJSON("/admin/realms/"+realmName, &realm); err != nil {
		t.Fatalf("reading the realm: %v", err)
	}
	if !strings.Contains(realm.PasswordPolicy, "passwordHistory(3)") || realm.ResetPasswordAllowed {
		t.Errorf("the applied realm holds passwordPolicy %q and resetPasswordAllowed %t; want passwordHistory(3) "+
			"and false", realm.PasswordPolicy, realm.ResetPasswordAllowed)
	}

	c := providerCaller(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil, http.StatusNoContent)
	})

	// One: issued, signed in with, refused as the new password, then changed.
	p := createLikeIdentityControl(t, a)
	temporary := "T" + strings.ToUpper(randomToken(t)[:23])
	issueTemporary(t, a, p, temporary)
	afterIssue := requiredActions(t, a, p)
	if !hasAction(afterIssue, "UPDATE_PASSWORD") {
		t.Errorf("after a temporary password the user's required actions are %v; want UPDATE_PASSWORD", afterIssue)
	}

	p.password = temporary
	b := newBrowser(t, a, c, p)
	b.firstNewPassword = temporary
	b.newPassword = "Chosen-" + suffix() + "!"
	b.signIn(nil)
	pages := strings.Join(b.pages, ", ")
	if pages != "password, update-password, update-password" {
		t.Errorf("the first sign-in showed %s; want the password, the update-password page, and the update-password "+
			"page again after the temporary value was refused", pages)
	}
	refusedText := ""
	if len(b.updatePages) == 2 {
		refusedText = pageMessage(b.updatePages[1])
		if !strings.Contains(b.updatePages[1], "must not be equal to any of last 3 passwords") {
			t.Errorf("the update-password page shown again does not name the history rule: %q", refusedText)
		}
	}
	afterChange := requiredActions(t, a, p)
	if hasAction(afterChange, "UPDATE_PASSWORD") {
		t.Errorf("after the change the user's required actions are %v; want no UPDATE_PASSWORD", afterChange)
	}
	oldRefused, oldPage := passwordRefused(t, a, c, p, temporary)
	if !oldRefused {
		t.Errorf("the temporary value still signs in after the change: %q", oldPage)
	}
	chosen := principal{userID: p.userID, username: p.username, password: b.newPassword, principalID: p.principalID}
	newBrowser(t, a, c, chosen).signIn(nil)

	// Two: issued, then deleted as identity-control's lapse sweep deletes it.
	q := createLikeIdentityControl(t, a)
	lapsed := "L" + strings.ToUpper(randomToken(t)[:23])
	issueTemporary(t, a, q, lapsed)
	var credentials []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+q.userID+"/credentials", &credentials); err != nil {
		t.Fatalf("listing the credentials: %v", err)
	}
	deleted := 0
	for _, credential := range credentials {
		if credential.Type == "password" {
			if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+q.userID+"/credentials/"+
				credential.ID, nil, http.StatusNoContent); err != nil {
				t.Fatalf("deleting the temporary password: %v", err)
			}
			deleted++
		}
	}
	if deleted != 1 {
		t.Errorf("the user held %d password credentials after the issuance; want 1", deleted)
	}
	lapsedRefused, lapsedPage := passwordRefused(t, a, c, q, lapsed)
	if !lapsedRefused {
		t.Errorf("a deleted temporary password still signs in: %q", lapsedPage)
	}
	if actions := requiredActions(t, a, q); !hasAction(actions, "UPDATE_PASSWORD") {
		t.Errorf("after the deletion the user's required actions are %v; want UPDATE_PASSWORD still", actions)
	}

	// The events: the marks, and no value anywhere in them.
	time.Sleep(1100 * time.Millisecond)
	var out strings.Builder
	fmt.Fprintf(&out, "## A first credential, ADR-IAM-010\n\nImage: `%s`\n\n", imageRef())
	fmt.Fprintf(&out, "- the update-password page after the temporary value: %s\n", orDash(refusedText))
	fmt.Fprintf(&out, "- the temporary value signs in after the change: %s\n", yesNo(!oldRefused))
	fmt.Fprintf(&out, "- a deleted temporary password signs in: %s\n\n", yesNo(!lapsedRefused))
	fmt.Fprintf(&out, "| Person | User events, oldest first | Admin events on the user |\n| :-- | :-- | :-- |\n")
	for _, s := range []struct {
		name   string
		who    principal
		values []string
	}{{"issued and changed", p, []string{temporary, b.newPassword}}, {"issued and deleted", q, []string{lapsed}}} {
		users, admins := rawEvents(t, a, s.who, started)
		var userMarks, adminMarks []string
		for i := len(users) - 1; i >= 0; i-- {
			userMarks = append(userMarks, userMark(users[i]))
		}
		for i := len(admins) - 1; i >= 0; i-- {
			adminMarks = append(adminMarks, adminMark(admins[i], s.who))
		}
		fmt.Fprintf(&out, "| %s | %s | %s |\n", s.name, orDash(strings.Join(userMarks, "; ")),
			orDash(strings.Join(adminMarks, "; ")))
		for _, e := range append(append([]map[string]any{}, users...), admins...) {
			encoded, _ := json.Marshal(e)
			for _, value := range s.values {
				if strings.Contains(string(encoded), value) {
					t.Errorf("%s: an event carries a password value: %s", s.name, describeSafely(e))
				}
			}
		}
		joinedAdmin := strings.Join(adminMarks, "; ")
		if !strings.Contains(joinedAdmin, "ACTION USER users/{id}/reset-password") {
			t.Errorf("%s: no admin event reads ACTION USER users/{id}/reset-password; recorded %s", s.name, orDash(joinedAdmin))
		}
		if s.who == p {
			joinedUser := strings.Join(userMarks, "; ")
			for _, want := range []string{
				"UPDATE_CREDENTIAL_ERROR error=password_rejected",
				"UPDATE_CREDENTIAL (auth_method=openid-connect, credential_type=password",
			} {
				if !strings.Contains(joinedUser, want) {
					t.Errorf("the forced change: no user event reads %q; recorded %s", want, orDash(joinedUser))
				}
			}
		} else if !strings.Contains(joinedAdmin, "ACTION USER users/{id}/credentials/{credentialId}") {
			t.Errorf("the deletion: no admin event reads ACTION USER users/{id}/credentials/{credentialId}; recorded %s",
				orDash(joinedAdmin))
		}
	}
	publish(t, out.String())
}

// describeSafely names an event without any of its values, for a failure message about a value that
// should not be in it.
func describeSafely(e map[string]any) string {
	var keys []string
	for k := range e {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Sprintf("%v %v %v, fields %v", e["type"], e["operationType"], e["resourceType"], keys)
}
