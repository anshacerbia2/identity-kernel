package compat

// Client suspension and deletion, asked by identity-control: TDD-identity-control-003 stops a
// registered client by disabling it (`:suspend`, undone by `:restore`) or by removing its keys and
// deleting it (`:retire`), so its client_key can be registered again. This test is the evidence for
// what each leaves a client able to do, and it keeps asserting it on every upgrade.
//
// Consumers verify an access token locally (STD-IAM-002), so an access token issued before the stop
// cannot be recalled by the kernel. The test asserts that it still verifies offline, not because
// that is wanted, but because the design bounds the exposure by the token's lifetime class and has to
// rest on what the kernel does rather than on what one would like it to do.
//
// Two answers are recorded and not required, because either is a design input rather than a
// defect: whether a refresh token survives a disable and re-enable, and whether deleting a client
// deletes its service-account user. Because the first is yes, the test also asks whether setting the
// client's not-before while it is disabled ends the tokens issued before, so a suspension can
// contain a client rather than pause it.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// lifecycleStep is one row of the report. required is empty for a step that is recorded only.
type lifecycleStep struct {
	name     string
	observed bool
	required string
}

func TestASuspendedOrDeletedClientGetsNoNewToken(t *testing.T) {
	a := requireKeycloak(t)
	key := newClientKey(t, "compat-lifecycle")
	clientID := "compat-lifecycle-" + suffix()
	clientUUID := keyClient(t, a, clientID, key)
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+clientUUID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", clientID, err)
		}
	})
	// A BFF holds a user's refresh token; a workload holds none. The client does both, so one client
	// answers for both profiles.
	updateClient(t, a, clientUUID, func(c map[string]any) { c["directAccessGrantsEnabled"] = true })
	user := createPrincipal(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+user.userID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting user %s: %v", user.username, err)
		}
	})
	var serviceAccount struct {
		ID string `json:"id"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/clients/"+clientUUID+"/service-account-user",
		&serviceAccount); err != nil || serviceAccount.ID == "" {
		t.Fatalf("reading the service-account user: %v", err)
	}

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
	grant := func() (bool, string) {
		status, body := clientCredentials(t, a, clientID, signAssertion(t, a, clientID, key))
		return status == http.StatusOK, string(body)
	}
	refresh := func(refreshToken string) (bool, string) {
		status, body := refreshGrant(t, a, clientID, signAssertion(t, a, clientID, key), refreshToken)
		return status == http.StatusOK, string(body)
	}

	ok, body := grant()
	require("enabled: client credentials", ok, true, body)
	session := passwordGrantWithKey(t, a, clientID, key, user)
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Fatal("the password grant issued no access token or no refresh token")
	}

	updateClient(t, a, clientUUID, func(c map[string]any) { c["enabled"] = false })
	ok, body = grant()
	require("disabled: client credentials", ok, false, body)
	ok, body = refresh(session.RefreshToken)
	require("disabled: the refresh token issued before", ok, false, body)
	verified, reason := verifiesOffline(t, a, session.AccessToken)
	require("disabled: the access token issued before verifies offline", verified, true, reason)

	updateClient(t, a, clientUUID, func(c map[string]any) { c["enabled"] = true })
	ok, body = grant()
	require("enabled again: client credentials", ok, true, body)
	ok, _ = refresh(session.RefreshToken)
	record("enabled again: the refresh token issued before", ok)

	// A client's not-before is Keycloak's revocation of every token it was issued before that time.
	// Its unit is a second, and a token issued in the same second as the not-before is not before it,
	// so the not-before is set a second after the session's tokens.
	session = passwordGrantWithKey(t, a, clientID, key, user)
	time.Sleep(1100 * time.Millisecond)
	updateClient(t, a, clientUUID, func(c map[string]any) {
		c["enabled"] = false
		c["notBefore"] = time.Now().Unix()
	})
	updateClient(t, a, clientUUID, func(c map[string]any) { c["enabled"] = true })
	ok, body = refresh(session.RefreshToken)
	require("not-before set while disabled, enabled again: the refresh token issued before", ok, false, body)
	fresh := passwordGrantWithKey(t, a, clientID, key, user)
	ok, body = refresh(fresh.RefreshToken)
	require("not-before set while disabled, enabled again: a new sign-in and its refresh", ok, true, body)

	// A fresh session, so the deletion is asked of a refresh token that was valid a moment before.
	session = passwordGrantWithKey(t, a, clientID, key, user)
	if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+clientUUID, nil,
		http.StatusNoContent); err != nil {
		t.Fatalf("deleting client %s: %v", clientID, err)
	}
	deleted = true
	ok, body = grant()
	require("deleted: client credentials", ok, false, body)
	ok, body = refresh(session.RefreshToken)
	require("deleted: the refresh token issued before", ok, false, body)
	verified, reason = verifiesOffline(t, a, session.AccessToken)
	require("deleted: the access token issued before verifies offline", verified, true, reason)
	response, _ := a.call(http.MethodGet, "/admin/realms/"+realmName+"/users/"+serviceAccount.ID, nil,
		http.StatusOK)
	record("deleted: the service-account user is gone", response != nil && response.StatusCode == http.StatusNotFound)

	again := keyClient(t, a, clientID, key)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+again, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting the second client %s: %v", clientID, err)
		}
	})
	ok, body = grant()
	require("after deletion: a new client with the same clientId", ok, true, body)

	var b strings.Builder
	fmt.Fprintf(&b, "## Client suspension and deletion\n\n")
	fmt.Fprintf(&b, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Step | Observed | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", s.name, yesNo(s.observed), orDash(s.required))
	}
	if t.Failed() {
		fmt.Fprintf(&b, "\n**Outcome:** a disabled or deleted client is not stopped as TDD-identity-control-003 "+
			"assumes; the registration lifecycle cannot be built on it as designed.\n")
	} else {
		fmt.Fprintf(&b, "\n**Outcome:** a disabled or deleted client gets no new token and no refresh, and an "+
			"access token issued before verifies offline until it expires.\n")
	}
	publish(t, b.String())
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// updateClient changes the client's representation the way identity-control does: read it, change
// what edit changes, write it back.
func updateClient(t *testing.T, a *admin, clientUUID string, edit func(map[string]any)) {
	t.Helper()
	path := "/admin/realms/" + realmName + "/clients/" + clientUUID
	var representation map[string]any
	if err := a.getJSON(path, &representation); err != nil {
		t.Fatalf("reading the client: %v", err)
	}
	edit(representation)
	if _, err := a.call(http.MethodPut, path, representation, http.StatusNoContent); err != nil {
		t.Fatalf("writing the client: %v", err)
	}
}

type keySession struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// passwordGrantWithKey signs a user in through a key-authenticated client. The password grant stands
// in for the browser login a BFF runs; what the test asks about is the refresh token it leaves.
func passwordGrantWithKey(t *testing.T, a *admin, clientID string, key clientKey, p principal) keySession {
	t.Helper()
	body := postForm(t, a, a.realmURL("/token"), url.Values{
		"grant_type":            {"password"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {signAssertion(t, a, clientID, key)},
		"username":              {p.username},
		"password":              {p.password},
	})
	var out keySession
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("the token endpoint returned something other than tokens: %s", snippet(string(body)))
	}
	return out
}

// refreshGrant asks for a token with the refresh token and returns the status, without judging it.
func refreshGrant(t *testing.T, a *admin, clientID, assertion, refreshToken string) (int, []byte) {
	t.Helper()
	response, err := a.http.PostForm(a.realmURL("/token"), url.Values{
		"grant_type":            {"refresh_token"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"refresh_token":         {refreshToken},
	})
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, body
}

// verifiesOffline checks the token the way a consumer does, with no call to the kernel but the key
// set: a PS256 signature by a key the realm publishes, and an expiry still ahead. The reason says
// which check refused it.
func verifiesOffline(t *testing.T, a *admin, token string) (bool, string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, "not a compact JWS"
	}
	header, claims := jwtHeader(t, token), jwtClaims(t, token)
	if header["alg"] != "PS256" {
		return false, fmt.Sprintf("signed with %v, not PS256", header["alg"])
	}
	exp, _ := claims["exp"].(float64)
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return false, "expired"
	}
	public, err := realmKey(a, fmt.Sprint(header["kid"]))
	if err != nil {
		return false, err.Error()
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, "the signature is not base64url"
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
		return false, "the signature does not verify: " + err.Error()
	}
	return true, ""
}

// realmKey returns the realm's published signing key with this kid.
func realmKey(a *admin, kid string) (*rsa.PublicKey, error) {
	response, err := a.http.Get(a.realmURL("/certs"))
	if err != nil {
		return nil, fmt.Errorf("GET certs: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("decoding certs: %w", err)
	}
	for _, key := range set.Keys {
		if key.Kid != kid || key.Kty != "RSA" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(key.N)
		e, errE := base64.RawURLEncoding.DecodeString(key.E)
		if errN != nil || errE != nil {
			return nil, errors.New("the published key is not base64url")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, fmt.Errorf("the realm publishes no RSA key with kid %s", kid)
}
