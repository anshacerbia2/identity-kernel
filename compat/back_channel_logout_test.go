package compat

// Back-channel logout, asked by ADR-IAM-009: a session removed through the Admin API, as
// identity-control removes one, reaches a client's back-channel logout URL as a signed logout token
// naming the session, and a client with front-channel logout on is sent none. The receiver is this
// test's own listener, which the kernel's container reaches at COMPAT_CALLBACK_HOST.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// logoutReceiver records the logout tokens posted to it, by path.
type logoutReceiver struct {
	mu       sync.Mutex
	received map[string][]string
	base     string
}

func newLogoutReceiver(t *testing.T) *logoutReceiver {
	t.Helper()
	host := strings.TrimSpace(os.Getenv("COMPAT_CALLBACK_HOST"))
	if host == "" {
		host = "host.docker.internal"
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &logoutReceiver{received: map[string][]string{},
		base: fmt.Sprintf("http://%s:%d", host, listener.Addr().(*net.TCPAddr).Port)}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		token := req.PostForm.Get("logout_token")
		r.mu.Lock()
		r.received[req.URL.Path] = append(r.received[req.URL.Path], token)
		r.mu.Unlock()
		if token == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return r
}

func (r *logoutReceiver) tokens(path string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.received[path]...)
}

// await waits up to the timeout for a token at path beyond the first seen.
func (r *logoutReceiver) await(path string, seen int, timeout time.Duration) (string, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if tokens := r.tokens(path); len(tokens) > seen {
			return tokens[seen], true
		}
		if time.Now().After(deadline) {
			return "", false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestASessionRemovalReachesTheBackChannelAndNotTheFrontChannel(t *testing.T) {
	a := requireKeycloak(t)
	receiver := newLogoutReceiver(t)
	backChannel := clientWithScope(t, a, "compat-bcl-"+suffix(), "scnehaux-internal")
	frontChannel := clientWithScope(t, a, "compat-fcl-"+suffix(), "scnehaux-internal")
	for _, c := range []client{backChannel, frontChannel} {
		t.Cleanup(func() {
			if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil,
				http.StatusNoContent); err != nil {
				t.Errorf("deleting client %s: %v", c.id, err)
			}
		})
	}
	// Written as identity-control writes a registered client (TDD-identity-control-003 1.37.0).
	logoutConfig := func(front bool, path string) func(map[string]any) {
		return func(representation map[string]any) {
			representation["frontchannelLogout"] = front
			attributes, _ := representation["attributes"].(map[string]any)
			if attributes == nil {
				attributes = map[string]any{}
			}
			attributes["backchannel.logout.url"] = receiver.base + path
			attributes["backchannel.logout.session.required"] = "true"
			attributes["backchannel.logout.revoke.offline.tokens"] = "false"
			representation["attributes"] = attributes
		}
	}
	updateClient(t, a, backChannel.uuid, logoutConfig(false, "/back"))
	updateClient(t, a, frontChannel.uuid, logoutConfig(true, "/front"))

	p := createPrincipal(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting user %s: %v", p.username, err)
		}
	})

	var steps []lifecycleStep
	require := func(name string, observed, want bool, detail string) {
		steps = append(steps, lifecycleStep{name: name, observed: observed, required: yesNo(want)})
		if observed != want {
			t.Errorf("%s: observed %v, want %v: %s", name, observed, want, snippet(detail))
		}
	}
	signIn := func(c client) string {
		t.Helper()
		tokens := passwordGrant(t, a, c, p)
		sid, _ := jwtClaims(t, tokens.AccessToken)["sid"].(string)
		if sid == "" {
			t.Fatalf("the access token of %s names no sid", c.id)
		}
		return sid
	}
	var issuer string
	{
		var discovery struct {
			Issuer string `json:"issuer"`
		}
		response, err := a.http.Get(a.base + "/realms/" + realmName + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		_ = json.NewDecoder(response.Body).Decode(&discovery)
		_ = response.Body.Close()
		issuer = discovery.Issuer
	}
	checkToken := func(label, token, clientID, sid string) {
		header, claims := jwtHeader(t, token), jwtClaims(t, token)
		events, _ := claims["events"].(map[string]any)
		_, logoutEvent := events["http://schemas.openid.net/event/backchannel-logout"]
		audience := fmt.Sprint(claims["aud"])
		_, nonce := claims["nonce"]
		require(label+": typed logout+jwt", header["typ"] == "logout+jwt", true, fmt.Sprint(header))
		require(label+": signed PS256, the realm's algorithm", header["alg"] == "PS256", true, fmt.Sprint(header))
		require(label+": issued by the realm", claims["iss"] == issuer, true, fmt.Sprint(claims["iss"]))
		require(label+": for the client", strings.Contains(audience, clientID), true, audience)
		require(label+": the back-channel logout event", logoutEvent, true, fmt.Sprint(claims["events"]))
		require(label+": naming the removed session", claims["sid"] == sid, true, fmt.Sprintf("%v, want %s", claims["sid"], sid))
		require(label+": naming the user", claims["sub"] == p.userID, true, fmt.Sprint(claims["sub"]))
		require(label+": no nonce", nonce, false, fmt.Sprint(claims))
	}

	// 1. One session removed, as a person's own session end and a provider's single removal do.
	sid := signIn(backChannel)
	seen := len(receiver.tokens("/back"))
	if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/sessions/"+url.PathEscape(sid), nil,
		http.StatusNoContent); err != nil {
		t.Fatalf("deleting session %s: %v", sid, err)
	}
	// Sent inside the removal: the token has arrived by the time the delete answers.
	_, before := receiver.await("/back", seen, 0)
	require("a session delete: the token arrived before the delete answered", before, true, "")
	token, ok := receiver.await("/back", seen, 10*time.Second)
	require("a session delete: a logout token is posted", ok, true, "")
	if ok {
		checkToken("a session delete", token, backChannel.id, sid)
	}

	// 2. Every session of the user removed, as a provider's containment does.
	sid = signIn(backChannel)
	seen = len(receiver.tokens("/back"))
	if _, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/users/"+p.userID+"/logout", nil,
		http.StatusNoContent); err != nil {
		t.Fatalf("logging the user out: %v", err)
	}
	token, ok = receiver.await("/back", seen, 10*time.Second)
	require("a user logout: a logout token is posted", ok, true, "")
	if ok {
		checkToken("a user logout", token, backChannel.id, sid)
	}

	// 3. A client with front-channel logout on is skipped by the back channel, whatever URL it holds.
	sid = signIn(frontChannel)
	seen = len(receiver.tokens("/front"))
	if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/sessions/"+url.PathEscape(sid), nil,
		http.StatusNoContent); err != nil {
		t.Fatalf("deleting session %s: %v", sid, err)
	}
	_, sent := receiver.await("/front", seen, 3*time.Second)
	require("front-channel logout on: no logout token is posted", sent, false, "")

	var b strings.Builder
	fmt.Fprintf(&b, "## Back-channel logout\n\n")
	fmt.Fprintf(&b, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Step | Observed | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", s.name, yesNo(s.observed), orDash(s.required))
	}
	if t.Failed() {
		fmt.Fprintf(&b, "\n**Outcome:** a session removal does not reach the back channel as ADR-IAM-009 assumes.\n")
	} else {
		fmt.Fprintf(&b, "\n**Outcome:** an Admin API removal posts a PS256 logout token naming the session to a client's "+
			"back-channel URL, inside the removal, and none to a client with front-channel logout on.\n")
	}
	publish(t, b.String())
}
