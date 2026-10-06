package compat

// The login pages' browser security headers (STD-IAM-001 2.4.0 §3.9, TDD-identity-kernel-004 1.2.0
// §Browser Security). The realm declares them and Keycloak sends them on every HTML page the realm
// renders: the login page, the answer to a failed sign-in, and an error page each carry the declared
// set, none can be framed, and the login page names no resource on another origin.

import (
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-kernel/internal/realmdef"
)

// headerNames are the realm's browserSecurityHeaders keys and the headers Keycloak sends for them.
var headerNames = map[string]string{
	"contentSecurityPolicy":   "Content-Security-Policy",
	"xFrameOptions":           "X-Frame-Options",
	"xContentTypeOptions":     "X-Content-Type-Options",
	"xRobotsTag":              "X-Robots-Tag",
	"strictTransportSecurity": "Strict-Transport-Security",
	"referrerPolicy":          "Referrer-Policy",
}

func declaredHeaders(t *testing.T) map[string]string {
	t.Helper()
	definition, err := realmdef.Load(filepath.Join("..", "realm"))
	if err != nil {
		t.Fatal(err)
	}
	declared, _ := definition.Realm["browserSecurityHeaders"].(map[string]any)
	out := map[string]string{}
	for key, header := range headerNames {
		value, _ := declared[key].(string)
		out[header] = value
	}
	return out
}

// Each HTML answer of the realm carries the declared set, refuses framing, and sets no form-action.
func TestTheLoginPagesCarryTheDeclaredBrowserHeaders(t *testing.T) {
	a := requireKeycloak(t)
	caller := providerCaller(t, a)
	want := declaredHeaders(t)

	pages := map[string]func() *http.Response{
		"the login page": func() *http.Response {
			response, _ := newThemeBrowser(t).send(authorizationRequest(a, caller.id))
			return response
		},
		"a failed sign-in": func() *http.Response {
			b := newThemeBrowser(t)
			match := loginAction.FindStringSubmatch(b.loginPage(a, caller, "en"))
			form := url.Values{"username": {"compat-nobody-" + suffix()}, "password": {"Compat-" + suffix() + "!"},
				"credentialId": {""}}
			request, _ := http.NewRequest(http.MethodPost, html.UnescapeString(match[1]), strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, _ := b.send(request)
			return response
		},
		"an error page": func() *http.Response {
			response, _ := newThemeBrowser(t).send(authorizationRequest(a, "compat-no-such-client-"+suffix()))
			return response
		},
	}
	for name, open := range pages {
		response := open()
		if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") {
			t.Errorf("%s answered %d with %q, not a page", name, response.StatusCode, response.Header.Get("Content-Type"))
			continue
		}
		for header, value := range want {
			if got := response.Header.Get(header); got != value {
				t.Errorf("%s sends %s %q, the realm declares %q", name, header, got, value)
			}
		}
		policy := realmdef.ParseCSP(response.Header.Get("Content-Security-Policy"))
		if got := strings.Join(policy["frame-ancestors"], " "); got != "'none'" {
			t.Errorf("%s may be framed: frame-ancestors %q", name, got)
		}
		if response.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s may be framed by a browser that predates frame-ancestors", name)
		}
		if _, present := policy["form-action"]; present {
			t.Errorf("%s sets form-action, which blocks the redirect back to the client", name)
		}
	}
}

// subresource is every script, stylesheet, image and icon a page names.
var subresource = regexp.MustCompile(`<(?:script|link|img)\b[^>]*?\s(?:src|href)="([^"]*)"`)

// The login page loads what the kernel ships and nothing from another origin: no font CDN, no
// analytics, no tag manager (TDD-identity-kernel-004 §Browser Security).
func TestTheLoginPageNamesNoOtherOrigin(t *testing.T) {
	a := requireKeycloak(t)
	page := newThemeBrowser(t).loginPage(a, providerCaller(t, a), "en")
	matches := subresource.FindAllStringSubmatch(page, -1)
	if len(matches) == 0 {
		t.Fatalf("the login page names no subresource; the pattern no longer reads it: %s", snippet(page))
	}
	for _, match := range matches {
		reference := html.UnescapeString(match[1])
		sameOrigin := (strings.HasPrefix(reference, "/") && !strings.HasPrefix(reference, "//")) ||
			strings.HasPrefix(reference, a.base+"/")
		if !sameOrigin {
			t.Errorf("the login page loads %q from another origin", reference)
		}
	}
}

func authorizationRequest(a *admin, clientID string) *http.Request {
	query := url.Values{"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {providerRedirect},
		"scope": {"openid"}, "state": {"compat"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"}, "ui_locales": {"en"}}
	request, _ := http.NewRequest(http.MethodGet, a.realmURL("/auth?"+query.Encode()), nil)
	return request
}
