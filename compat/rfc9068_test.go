package compat

// RFC 9068 access tokens, asked by STD-IAM-002 §3.2 and §3.5: an access token carries the header
// typ at+jwt and the claims iss, exp, aud, sub, client_id, iat and jti, and a verifier refuses a
// token of any other type. Two things about the pinned kernel decide who realizes that:
//
//   - The at+jwt header is a per-client setting, access.token.header.type.rfc9068, off by default
//     (Keycloak 26.2 release notes). identity-control sets it on every client it registers.
//   - client_id reaches a service-account token through the built-in service_account scope. Nothing
//     puts it in a user's token, so identity-control adds a hardcoded claim mapper per client.
//
// This test sets both the way identity-control will, and asks whether the tokens then conform, for a
// user's token and a workload's. Two answers are recorded and not required: whether the built-in
// scope alone gives a workload token its client_id, and every claim name the kernel issues, which
// STD-IAM-002 §3.2's claim closure is measured against.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// rfc9068Claims are the claims RFC 9068 §2.2 requires in every JWT access token.
var rfc9068Claims = []string{"iss", "exp", "aud", "sub", "client_id", "iat", "jti"}

func TestAnAccessTokenIsAnRFC9068Token(t *testing.T) {
	a := requireKeycloak(t)
	key := newClientKey(t, "compat-rfc9068")
	clientID := "compat-rfc9068-" + suffix()
	clientUUID := keyClient(t, a, clientID, key)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+clientUUID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", clientID, err)
		}
	})
	user := createPrincipal(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+user.userID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting user %s: %v", user.username, err)
		}
	})

	var steps []lifecycleStep
	record := func(name string, observed bool) {
		steps = append(steps, lifecycleStep{name: name, observed: observed})
	}
	require := func(name string, observed bool, detail string) {
		steps = append(steps, lifecycleStep{name: name, observed: observed, required: "yes"})
		if !observed {
			t.Errorf("%s: %s", name, detail)
		}
	}

	// Before identity-control's settings: what a client gets from the realm alone.
	status, body := clientCredentials(t, a, clientID, signAssertion(t, a, clientID, key))
	if status != http.StatusOK {
		t.Fatalf("the client credentials grant answered %d: %s", status, snippet(string(body)))
	}
	before := accessToken(t, body)
	_, builtin := jwtClaims(t, before)["client_id"]
	record("realm alone: a workload token carries client_id", builtin)
	record("realm alone: the header typ is at+jwt", jwtHeader(t, before)["typ"] == "at+jwt")

	// identity-control's settings: the at+jwt header, client_id for every token, an audience, and
	// the user sign-in a BFF runs.
	updateClient(t, a, clientUUID, func(c map[string]any) {
		c["directAccessGrantsEnabled"] = true
		attributes, _ := c["attributes"].(map[string]any)
		if attributes == nil {
			attributes = map[string]any{}
		}
		attributes["access.token.header.type.rfc9068"] = "true"
		c["attributes"] = attributes
	})
	addClientMapper(t, a, clientUUID, map[string]any{
		"name": "client_id", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
		"config": map[string]string{"claim.name": "client_id", "claim.value": clientID, "jsonType.label": "String",
			"access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true"},
	})
	addClientMapper(t, a, clientUUID, map[string]any{
		"name": "audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
		"config": map[string]string{"included.custom.audience": "compat-rfc9068-api", "access.token.claim": "true",
			"id.token.claim": "false", "introspection.token.claim": "true"},
	})

	status, body = clientCredentials(t, a, clientID, signAssertion(t, a, clientID, key))
	if status != http.StatusOK {
		t.Fatalf("the client credentials grant answered %d after the settings: %s", status, snippet(string(body)))
	}
	workload := accessToken(t, body)
	conforms(t, "workload token", workload, clientID, require)

	user9068 := passwordGrantWithScope(t, a, clientID, key, user, "openid")
	conforms(t, "user token", user9068.AccessToken, clientID, require)
	idTyp := jwtHeader(t, user9068.IDToken)["typ"]
	require("user sign-in: the ID token's header typ is not at+jwt", idTyp != "at+jwt",
		fmt.Sprintf("the ID token's typ is %v; a verifier could not tell it from an access token", idTyp))

	var b strings.Builder
	fmt.Fprintf(&b, "## RFC 9068 access tokens\n\nImage: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Step | Observed | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", s.name, yesNo(s.observed), orDash(s.required))
	}
	fmt.Fprintf(&b, "\nClaims in a workload token: `%s`\n\nClaims in a user token: `%s`\n",
		strings.Join(claimNames(t, workload), "`, `"), strings.Join(claimNames(t, user9068.AccessToken), "`, `"))
	if t.Failed() {
		fmt.Fprintf(&b, "\n**Outcome:** the kernel does not issue RFC 9068 access tokens with these settings.\n")
	} else {
		fmt.Fprintf(&b, "\n**Outcome:** with the at+jwt setting and a client_id mapper, the kernel issues RFC 9068 "+
			"access tokens, and its ID tokens stay distinguishable.\n")
	}
	publish(t, b.String())
}

// conforms records whether one access token has the RFC 9068 header and claims.
func conforms(t *testing.T, label, token, clientID string, require func(string, bool, string)) {
	t.Helper()
	header, claims := jwtHeader(t, token), jwtClaims(t, token)
	require(label+": the header typ is at+jwt", header["typ"] == "at+jwt", fmt.Sprintf("typ is %v", header["typ"]))
	require(label+": signed PS256", header["alg"] == "PS256", fmt.Sprintf("alg is %v", header["alg"]))
	var missing []string
	for _, name := range rfc9068Claims {
		if value, ok := claims[name]; !ok || value == "" || value == nil {
			missing = append(missing, name)
		}
	}
	require(label+": carries iss, exp, aud, sub, client_id, iat and jti", len(missing) == 0,
		fmt.Sprintf("missing %v", missing))
	require(label+": client_id names the client", claims["client_id"] == clientID,
		fmt.Sprintf("client_id is %v", claims["client_id"]))
}

func claimNames(t *testing.T, token string) []string {
	t.Helper()
	var names []string
	for name := range jwtClaims(t, token) {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func accessToken(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		t.Fatalf("the token endpoint returned no access token: %s", snippet(string(body)))
	}
	return out.AccessToken
}

func addClientMapper(t *testing.T, a *admin, clientUUID string, mapper map[string]any) {
	t.Helper()
	if _, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/clients/"+clientUUID+"/protocol-mappers/models",
		mapper, http.StatusCreated); err != nil {
		t.Fatalf("adding mapper %v: %v", mapper["name"], err)
	}
}

type signInTokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

// passwordGrantWithScope signs a user in through a key-authenticated client, asking for the given
// scope, and returns the access and ID tokens.
func passwordGrantWithScope(t *testing.T, a *admin, clientID string, key clientKey, p principal, scope string) signInTokens {
	t.Helper()
	body := postForm(t, a, a.realmURL("/token"), url.Values{
		"grant_type":            {"password"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {signAssertion(t, a, clientID, key)},
		"username":              {p.username},
		"password":              {p.password},
		"scope":                 {scope},
	})
	var out signInTokens
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" || out.IDToken == "" {
		t.Fatalf("the sign-in returned no access token or no ID token: %s", snippet(string(body)))
	}
	return out
}
