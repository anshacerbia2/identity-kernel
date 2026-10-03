package compat

// One session ended, asked by identity-control: TDD-identity-control-005 2.3.0 lets a person end
// one of their own sessions, named by the identifier the Admin API lists it under, and marks the
// session a request came from by the access token's sid. The test asserts that sid is that
// identifier, and what ending one session leaves of the others.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestOneSessionIsEndedAndTheTokenSidNamesIt(t *testing.T) {
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
	require := func(name string, observed, want bool, detail string) {
		steps = append(steps, lifecycleStep{name: name, observed: observed, required: yesNo(want)})
		if observed != want {
			t.Errorf("%s: observed %v, want %v: %s", name, observed, want, snippet(detail))
		}
	}
	type session struct{ access, refresh string }
	signIn := func() session {
		t.Helper()
		status, body := tokenRequest(t, a, url.Values{
			"grant_type": {"password"}, "client_id": {c.id}, "client_secret": {c.secret},
			"username": {p.username}, "password": {p.password}, "scope": {"openid"},
		})
		var out struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(body, &out); err != nil || status != http.StatusOK {
			t.Fatalf("signing in: %d %s", status, body)
		}
		return session{out.AccessToken, out.RefreshToken}
	}
	refresh := func(s session) (bool, string) {
		status, body := tokenRequest(t, a, url.Values{
			"grant_type": {"refresh_token"}, "client_id": {c.id}, "client_secret": {c.secret},
			"refresh_token": {s.refresh},
		})
		return status == http.StatusOK, string(body)
	}
	listed := func() []string {
		t.Helper()
		var list []struct {
			ID string `json:"id"`
		}
		if err := a.getJSON(userPath+"/sessions", &list); err != nil {
			t.Fatalf("listing the sessions: %v", err)
		}
		ids := make([]string, 0, len(list))
		for _, s := range list {
			ids = append(ids, s.ID)
		}
		return ids
	}

	first, second := signIn(), signIn()
	firstSid, _ := jwtClaims(t, first.access)["sid"].(string)
	secondSid, _ := jwtClaims(t, second.access)["sid"].(string)
	ids := listed()
	require("two sign-ins are two listed sessions", len(ids) == 2, true, strings.Join(ids, ","))
	contains := func(list []string, value string) bool {
		for _, v := range list {
			if v == value {
				return true
			}
		}
		return false
	}
	require("the access token's sid is the listed session identifier",
		firstSid != "" && contains(ids, firstSid) && contains(ids, secondSid), true,
		fmt.Sprintf("sids %q %q, listed %v", firstSid, secondSid, ids))

	if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/sessions/"+url.PathEscape(firstSid), nil,
		http.StatusNoContent); err != nil {
		t.Fatalf("deleting session %s: %v", firstSid, err)
	}
	ids = listed()
	require("ended: the session is no longer listed", !contains(ids, firstSid), true, strings.Join(ids, ","))
	require("ended: the other session is still listed", contains(ids, secondSid), true, strings.Join(ids, ","))
	ok, body := refresh(first)
	require("ended: its refresh token", ok, false, body)
	ok, body = refresh(second)
	require("ended: the other session's refresh token", ok, true, body)
	response, _ := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/sessions/"+url.PathEscape(firstSid), nil,
		http.StatusNoContent)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	steps = append(steps, lifecycleStep{name: fmt.Sprintf("ended again: the second delete answers %d", status),
		observed: true})

	var b strings.Builder
	fmt.Fprintf(&b, "## One session ended\n\n")
	fmt.Fprintf(&b, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Step | Observed | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", s.name, yesNo(s.observed), orDash(s.required))
	}
	if t.Failed() {
		fmt.Fprintf(&b, "\n**Outcome:** one session cannot be ended as TDD-identity-control-005 2.3.0 assumes.\n")
	} else {
		fmt.Fprintf(&b, "\n**Outcome:** the access token's sid is the listed session identifier; deleting it ends "+
			"that session alone.\n")
	}
	publish(t, b.String())
}
