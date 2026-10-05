package compat

// User events, from TDD-identity-kernel-003: the kernel's native event store is the durable record
// reconciliation reads, so it must hold them. Keycloak stores none by default: "By default,
// {project_name} does not store or display events in the Admin Console. Only the error events are
// logged to the Admin Console and the server's log file" (Server Administration Guide, Auditing user
// events). The realm saves them for 7 days, and a login and a failed login are each readable through
// the supported Admin API, naming the user and carrying no credential.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type userEvent struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	UserID   string            `json:"userId"`
	ClientID string            `json:"clientId"`
	Error    string            `json:"error"`
	Details  map[string]string `json:"details"`
}

func TestUserEventsAreKeptASevenDayWindow(t *testing.T) {
	a := requireKeycloak(t)
	var realm struct {
		EventsEnabled    bool  `json:"eventsEnabled"`
		EventsExpiration int64 `json:"eventsExpiration"`
	}
	if err := a.getJSON("/admin/realms/"+realmName, &realm); err != nil {
		t.Fatalf("reading the realm: %v", err)
	}
	if !realm.EventsEnabled || realm.EventsExpiration != 604800 {
		t.Errorf("user events saved %v, kept %d seconds; want saved and kept 604800 (7 days)",
			realm.EventsEnabled, realm.EventsExpiration)
	}
}

func TestALoginAndAFailedLoginAreRecorded(t *testing.T) {
	a := requireKeycloak(t)
	person := createPrincipal(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+person.userID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting user %s: %v", person.username, err)
		}
	})
	key := newClientKey(t, "compat-events")
	clientID := "compat-events-" + suffix()
	app := registeredLikeIdentityControl(t, a, clientID, key, "scnehaux-internal")
	updateClient(t, a, app, func(c map[string]any) { c["directAccessGrantsEnabled"] = true })

	passwordGrantWithScope(t, a, clientID, key, person, "openid")

	wrong := "Wrong-" + suffix() + "!"
	r, err := a.http.PostForm(a.realmURL("/token"), url.Values{
		"grant_type": {"password"}, "client_id": {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {signAssertion(t, a, clientID, key)},
		"username":              {person.username}, "password": {wrong}, "scope": {"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
	if r.StatusCode == http.StatusOK {
		t.Fatal("a wrong password was accepted")
	}

	var found map[string]userEvent
	var raw []byte
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		var events []json.RawMessage
		query := url.Values{"user": {person.userID}, "max": {"50"}}
		if err := a.getJSON("/admin/realms/"+realmName+"/events?"+query.Encode(), &events); err != nil {
			t.Fatalf("reading user events: %v", err)
		}
		found = map[string]userEvent{}
		raw = nil
		for _, encoded := range events {
			var event userEvent
			if err := json.Unmarshal(encoded, &event); err != nil {
				t.Fatalf("decoding an event: %v", err)
			}
			found[event.Type] = event
			raw = append(raw, encoded...)
		}
		if _, ok := found["LOGIN"]; ok {
			if _, ok := found["LOGIN_ERROR"]; ok {
				break
			}
		}
	}

	login, ok := found["LOGIN"]
	if !ok {
		t.Fatalf("a login recorded no LOGIN event; recorded %v", keys(found))
	}
	if login.ID == "" || login.UserID != person.userID || login.ClientID != clientID {
		t.Errorf("the LOGIN event is %+v; want an id, the user and the client", login)
	}
	failed, ok := found["LOGIN_ERROR"]
	if !ok {
		t.Fatalf("a failed login recorded no LOGIN_ERROR event; recorded %v", keys(found))
	}
	if failed.Error == "" || failed.ClientID != clientID {
		t.Errorf("the LOGIN_ERROR event is %+v; want its error and the client", failed)
	}
	// TDD-identity-kernel-003 §Wire Shape: no password, token or credential value in an event.
	for _, secret := range []string{person.password, wrong} {
		if strings.Contains(string(raw), secret) {
			t.Error("a recorded user event carries a password")
		}
	}
}

func keys(events map[string]userEvent) []string {
	out := []string{}
	for name := range events {
		out = append(out, name)
	}
	return out
}
