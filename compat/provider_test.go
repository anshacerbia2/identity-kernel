package compat

// The provider-scope form of the privileged profile (STD-IAM-002 §3.1.1, §3.2.1).
//
// It is what identity-control accepts: minting a Principal is provider-scope, so the token must
// carry principal_id, subject_type, provider_scope, acr and auth_time, and must not carry tenant_id
// or either version claim. The kernel realizes it through the scnehaux-provider client scope.
//
// The token is obtained by Authorization Code with PKCE S256 against the kernel's own login form,
// not by a password grant. auth_time is the instant of an authentication ceremony, and a direct grant
// has none -- identity-control found its tokens structurally without it -- so a probe built on the
// password grant would report a missing claim that production never misses, or pass on a token
// production never issues.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

const providerScopeValue = "provider:identity-control"

func TestAProviderTokenMeetsTheProviderProfile(t *testing.T) {
	a := requireKeycloak(t)
	caller := providerCaller(t, a)
	resource := resourceServerFor(t, a, caller)
	who := providerPrincipal(t, a, providerScopeValue)

	before := time.Now().Add(-time.Minute).Unix()
	issued := authorizationCode(t, a, caller, who)
	header := jwtHeader(t, issued.AccessToken)
	claims := jwtClaims(t, issued.AccessToken)

	if header["alg"] != "PS256" {
		t.Errorf("the provider token is signed with %v, want PS256", header["alg"])
	}
	for name, want := range map[string]string{
		"principal_id":   who.principalID,
		"subject_type":   "human",
		"provider_scope": providerScopeValue,
	} {
		if got, _ := claims[name].(string); got != want {
			t.Errorf("the provider token carries %s=%v, want %q", name, claims[name], want)
		}
	}
	if acr, _ := claims["acr"].(string); acr == "" {
		t.Errorf("the provider token carries no acr (got %v); STD-IAM-002 §3.2 makes it mandatory", claims["acr"])
	}
	authTime, ok := claims["auth_time"].(float64)
	if !ok || int64(authTime) < before || int64(authTime) > time.Now().Add(time.Minute).Unix() {
		t.Errorf("the provider token carries auth_time %v, want the instant of the login just performed", claims["auth_time"])
	}
	// A provider operation belongs to no Tenant. A tenant_id here would put a Tenant on an action
	// that has none, which is the conflation §3.1.1 exists to prevent.
	for _, name := range []string{"tenant_id", "workspace_id", "membership_version", "tenant_security_version", "workload_owner"} {
		if value, present := claims[name]; present {
			t.Errorf("the provider token carries %s=%v, which the provider-scope form prohibits", name, value)
		}
	}
	if !audienceNames(claims["aud"], resource.id) {
		t.Errorf("the provider token's aud %v does not name the resource it was issued for (%s)", claims["aud"], resource.id)
	}
}

// providerCaller registers a client the way a provider-scope caller is registered: Authorization
// Code with PKCE S256, no password grant, and the scnehaux-provider scope attached explicitly.
func providerCaller(t *testing.T, a *admin) client {
	t.Helper()
	clientID := "compat-provider-" + suffix()
	secret := "compat-" + suffix()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/clients", map[string]any{
		"clientId":                  clientID,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"secret":                    secret,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    false,
		"redirectUris":              []string{providerRedirect},
		"attributes": map[string]string{
			"pkce.code.challenge.method":       "S256",
			"access.token.signed.response.alg": "PS256",
		},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating the provider caller: %v", err)
	}
	c := client{uuid: created(response), id: clientID, secret: secret}
	if _, err := a.call(http.MethodPut,
		"/admin/realms/"+realmName+"/clients/"+c.uuid+"/default-client-scopes/"+scopeIDByName(t, a, "scnehaux-provider"),
		nil, http.StatusNoContent); err != nil {
		t.Fatalf("attaching scnehaux-provider: %v", err)
	}
	return c
}

// The redirect is never listened on. The flow stops at the redirect's Location header, which is
// where the code is; nothing needs to receive it.
const providerRedirect = "http://127.0.0.1:9/callback"

func providerPrincipal(t *testing.T, a *admin, scope string) principal {
	t.Helper()
	p := principal{username: "compat-" + suffix(), password: "Compat-" + suffix() + "!", principalID: uuidV7()}
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/users", map[string]any{
		"username":      p.username,
		"enabled":       true,
		"email":         p.username + "@compat.invalid",
		"emailVerified": true,
		"firstName":     "Compat",
		"lastName":      "Provider",
		"attributes": map[string][]string{
			"scnehaux_principal_id":   {p.principalID},
			"scnehaux_subject_type":   {"human"},
			"scnehaux_provider_scope": {scope},
		},
		"credentials":     []map[string]any{{"type": "password", "value": p.password, "temporary": false}},
		"requiredActions": []string{},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating a provider Principal: %v", err)
	}
	p.userID = created(response)
	return p
}

var loginAction = regexp.MustCompile(`action="([^"]*login-actions/authenticate[^"]*)"`)

// authorizationCode drives the kernel's login form without a browser: the authorization request,
// the credential post, and the code exchange with its PKCE verifier.
//
// Cookies are carried by hand rather than by a cookie jar. Keycloak marks its login cookies Secure,
// a browser still sends them to http://localhost because that is a secure context by specification,
// and Go's jar implements no such exception -- so a jar would drop the session between the two
// requests and the login would restart.
func authorizationCode(t *testing.T, a *admin, c client, p principal) issuedTokens {
	t.Helper()
	verifier := randomToken(t)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	browser := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	cookies := map[string]string{}
	send := func(request *http.Request) (*http.Response, string) {
		for name, value := range cookies {
			request.AddCookie(&http.Cookie{Name: name, Value: value})
		}
		response, err := browser.Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", request.Method, request.URL.Path, err)
		}
		defer func() { _ = response.Body.Close() }()
		body, _ := io.ReadAll(response.Body)
		for _, cookie := range response.Cookies() {
			if cookie.Value == "" || cookie.MaxAge < 0 {
				delete(cookies, cookie.Name)
				continue
			}
			cookies[cookie.Name] = cookie.Value
		}
		return response, string(body)
	}

	query := url.Values{
		"client_id":             {c.id},
		"response_type":         {"code"},
		"redirect_uri":          {providerRedirect},
		"scope":                 {"openid"},
		"state":                 {"compat"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	request, _ := http.NewRequest(http.MethodGet, a.realmURL("/auth?"+query.Encode()), nil)
	response, page := send(request)
	match := loginAction.FindStringSubmatch(page)
	if response.StatusCode != http.StatusOK || match == nil {
		t.Fatalf("the authorization request answered %d without a login form: %s", response.StatusCode, snippet(page))
	}

	form := url.Values{"username": {p.username}, "password": {p.password}, "credentialId": {""}}
	request, _ = http.NewRequest(http.MethodPost, html.UnescapeString(match[1]), strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, page = send(request)
	location, err := url.Parse(response.Header.Get("Location"))
	code := ""
	if err == nil {
		code = location.Query().Get("code")
	}
	if response.StatusCode != http.StatusFound || code == "" {
		t.Fatalf("the login answered %d without a code in its redirect (Location %q): %s",
			response.StatusCode, response.Header.Get("Location"), snippet(page))
	}

	body := postForm(t, a, a.realmURL("/token"), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {providerRedirect},
		"client_id":     {c.id},
		"client_secret": {c.secret},
		"code_verifier": {verifier},
	})
	var out issuedTokens
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		t.Fatalf("the code exchange returned no access token: %s", body)
	}
	return out
}

func audienceNames(aud any, name string) bool {
	switch v := aud.(type) {
	case string:
		return v == name
	case []any:
		for _, item := range v {
			if item == name {
				return true
			}
		}
	}
	return false
}

func randomToken(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func snippet(s string) string {
	if len(s) > 600 {
		return s[:600] + "..."
	}
	return s
}
