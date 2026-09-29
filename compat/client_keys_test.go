package compat

// Client key rotation, asked by identity-control: TDD-identity-control-003 §Credential Rotation
// requires the old and new credential of a confidential or workload client to be valid together
// through an overlap window, and the retiring one to stop working when it is revoked.
//
// A client secret cannot do that in this release without a preview feature: Keycloak holds one
// secret per client, and its secret-rotation policy (`client-secret-rotation`) is classified
// preview, "not recommended for use in production". Signed-JWT client authentication
// (`private_key_jwt`, RFC 7523) is supported, and a client's public keys can be held as a JWKS on
// the client itself. This test asks whether that JWKS gives the overlap and the revocation:
//
//  1. a client authenticates with key A;
//  2. with A and B both registered, each authenticates;
//  3. with A removed, A is refused at once, and B still authenticates;
//  4. an assertion that was already used is refused, so a captured one cannot be replayed.
//
// Keys are held on the client as a JWKS string rather than fetched from a JWKS URL, because
// identity-control is the party that registers them, and an application should not have to serve a
// key endpoint to be a client.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type clientKey struct {
	kid     string
	private *rsa.PrivateKey
}

func TestClientKeyRotationWithSignedJWT(t *testing.T) {
	a := requireKeycloak(t)
	keyA, keyB := newClientKey(t, "compat-key-a"), newClientKey(t, "compat-key-b")
	clientID := "compat-keys-" + suffix()
	clientUUID := keyClient(t, a, clientID, keyA)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+clientUUID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", clientID, err)
		}
	})

	type step struct {
		name     string
		accepted bool
		want     bool
	}
	var steps []step
	check := func(name string, key clientKey, want bool) {
		status, body := clientCredentials(t, a, clientID, signAssertion(t, a, clientID, key))
		accepted := status == http.StatusOK
		steps = append(steps, step{name, accepted, want})
		if accepted != want {
			t.Errorf("%s: token endpoint answered %d, want accepted=%v: %s", name, status, want, snippet(string(body)))
		}
	}

	check("A only registered, signed with A", keyA, true)

	setClientKeys(t, a, clientUUID, keyA, keyB)
	check("A and B registered, signed with A", keyA, true)
	check("A and B registered, signed with B", keyB, true)

	setClientKeys(t, a, clientUUID, keyB)
	check("A removed, signed with A", keyA, false)
	check("A removed, signed with B", keyB, true)

	// A captured assertion is replayed: the same jti, still unexpired.
	assertion := signAssertion(t, a, clientID, keyB)
	first, _ := clientCredentials(t, a, clientID, assertion)
	second, body := clientCredentials(t, a, clientID, assertion)
	steps = append(steps, step{"the same assertion used twice", second == http.StatusOK, false})
	if first != http.StatusOK {
		t.Errorf("a fresh assertion signed with B answered %d before the replay was tried", first)
	}
	if second == http.StatusOK {
		t.Errorf("a replayed assertion was accepted: a captured one would authenticate until it expires: %s",
			snippet(string(body)))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Client key rotation with signed-JWT client authentication\n\n")
	fmt.Fprintf(&b, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Step | Accepted | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "| %s | %v | %v |\n", s.name, s.accepted, s.want)
	}
	if t.Failed() {
		fmt.Fprintf(&b, "\n**Outcome:** the overlap or the revocation does not hold in this release; "+
			"identity-control cannot build rotation on it.\n")
	} else {
		fmt.Fprintf(&b, "\n**Outcome:** two keys overlap, a removed key is refused at once, and an assertion "+
			"cannot be replayed. identity-control can build rotation on supported features.\n")
	}
	publish(t, b.String())
}

func newClientKey(t *testing.T, kid string) clientKey {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating %s: %v", kid, err)
	}
	return clientKey{kid: kid + "-" + suffix(), private: private}
}

func (k clientKey) jwk() map[string]string {
	return map[string]string{
		"kty": "RSA",
		"kid": k.kid,
		"use": "sig",
		"alg": "PS256",
		"n":   base64.RawURLEncoding.EncodeToString(k.private.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.private.E)).Bytes()),
	}
}

func jwks(t *testing.T, keys ...clientKey) string {
	t.Helper()
	set := struct {
		Keys []map[string]string `json:"keys"`
	}{}
	for _, key := range keys {
		set.Keys = append(set.Keys, key.jwk())
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// keyClient creates a confidential client that authenticates only with a PS256-signed assertion, by a
// key in the JWKS held on the client. It uses the client credentials grant: a workload, the profile
// that authenticates with its own credential on every token request.
func keyClient(t *testing.T, a *admin, clientID string, keys ...clientKey) string {
	t.Helper()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/clients", map[string]any{
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
			"jwks.string":                     jwks(t, keys...),
		},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating client %s: %v", clientID, err)
	}
	return created(response)
}

// setClientKeys replaces the client's JWKS, the way identity-control would add a key at rotation and
// drop one at revocation: read the representation, change the one attribute, write it back.
func setClientKeys(t *testing.T, a *admin, clientUUID string, keys ...clientKey) {
	t.Helper()
	path := "/admin/realms/" + realmName + "/clients/" + clientUUID
	var representation map[string]any
	if err := a.getJSON(path, &representation); err != nil {
		t.Fatalf("reading the client: %v", err)
	}
	attributes, _ := representation["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	attributes["jwks.string"] = jwks(t, keys...)
	representation["attributes"] = attributes
	if _, err := a.call(http.MethodPut, path, representation, http.StatusNoContent); err != nil {
		t.Fatalf("writing the client's keys: %v", err)
	}
}

// signAssertion builds an RFC 7523 client assertion: the client names itself as issuer and subject,
// the realm's issuer is the audience, and a fresh jti makes it single-use.
func signAssertion(t *testing.T, a *admin, clientID string, key clientKey) string {
	t.Helper()
	now := time.Now()
	header := map[string]string{"alg": "PS256", "typ": "JWT", "kid": key.kid}
	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": a.base + "/realms/" + realmName,
		"jti": randomToken(t),
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	}
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPSS(rand.Reader, key.private, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatalf("signing the assertion: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// clientCredentials asks for a token with the assertion and returns the status, without judging it:
// a refusal is an answer this test records, not a failure of the request.
func clientCredentials(t *testing.T, a *admin, clientID, assertion string) (int, []byte) {
	t.Helper()
	response, err := a.http.PostForm(a.realmURL("/token"), url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	})
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, body
}
