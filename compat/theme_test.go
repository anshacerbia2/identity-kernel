package compat

// The login theme (TDD-identity-kernel-004 1.1.0): keycloak.v2's templates and styles under the
// scnehaux theme, which replaces message bundles only. The pages render through it, declare their
// language, speak Indonesian when asked, and never tell an unknown identifier from a wrong password
// or a disabled account.

import (
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// themeBrowser carries cookies by hand, for the reason authorizationCode gives.
type themeBrowser struct {
	t       *testing.T
	http    *http.Client
	cookies map[string]string
}

func newThemeBrowser(t *testing.T) *themeBrowser {
	return &themeBrowser{t: t, cookies: map[string]string{}, http: &http.Client{Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *themeBrowser) send(request *http.Request) (*http.Response, string) {
	b.t.Helper()
	for name, value := range b.cookies {
		request.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	response, err := b.http.Do(request)
	if err != nil {
		b.t.Fatalf("%s %s: %v", request.Method, request.URL.Path, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	for _, cookie := range response.Cookies() {
		if cookie.Value == "" || cookie.MaxAge < 0 {
			delete(b.cookies, cookie.Name)
			continue
		}
		b.cookies[cookie.Name] = cookie.Value
	}
	return response, string(body)
}

// loginPage opens the authorization request in the locale asked for, and returns the login page.
func (b *themeBrowser) loginPage(a *admin, c client, locale string) string {
	b.t.Helper()
	query := url.Values{"client_id": {c.id}, "response_type": {"code"}, "redirect_uri": {providerRedirect},
		"scope": {"openid"}, "state": {"compat"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"}, "ui_locales": {locale}}
	request, _ := http.NewRequest(http.MethodGet, a.realmURL("/auth?"+query.Encode()), nil)
	response, page := b.send(request)
	if response.StatusCode != http.StatusOK || loginAction.FindStringSubmatch(page) == nil {
		b.t.Fatalf("the authorization request answered %d without a login form: %s", response.StatusCode, snippet(page))
	}
	return page
}

// signIn posts a credential to the form on page and returns the status and the page that answers.
func (b *themeBrowser) signIn(page, username, password string) (int, string) {
	b.t.Helper()
	match := loginAction.FindStringSubmatch(page)
	form := url.Values{"username": {username}, "password": {password}, "credentialId": {""}}
	request, _ := http.NewRequest(http.MethodPost, html.UnescapeString(match[1]), strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, answer := b.send(request)
	return response.StatusCode, answer
}

var htmlLang = regexp.MustCompile(`<html[^>]*\slang="([^"]*)"`)

// The page renders through the scnehaux theme and declares its language, in each supported locale.
func TestTheLoginPageIsTheThemesInEachLocale(t *testing.T) {
	a := requireKeycloak(t)
	caller := providerCaller(t, a)
	for locale, title := range map[string]string{"en": "Sign in to your account", "id": "Masuk ke akun Anda"} {
		page := newThemeBrowser(t).loginPage(a, caller, locale)
		if !strings.Contains(page, "/login/scnehaux/") {
			t.Errorf("%s: the login page loads no resource of the scnehaux theme: %s", locale, snippet(page))
		}
		if m := htmlLang.FindStringSubmatch(page); m == nil || m[1] != locale {
			t.Errorf("%s: the document declares lang %v, want %q", locale, m, locale)
		}
		if !strings.Contains(html.UnescapeString(page), title) {
			t.Errorf("%s: the login page does not read %q", locale, title)
		}
	}
}

// TDD-identity-kernel-004 §Enumeration Resistance: an unknown identifier, a wrong password and a
// disabled account answer with the same status and the same message, in each locale. The kernel's
// default wording for a disabled account names it; the theme's bundle does not.
func TestASignInFailureTellsNoAccountState(t *testing.T) {
	a := requireKeycloak(t)
	caller := providerCaller(t, a)
	active, disabled := providerPrincipal(t, a), providerPrincipal(t, a)
	for _, p := range []principal{active, disabled} {
		userID := p.userID
		t.Cleanup(func() {
			if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+userID, nil,
				http.StatusNoContent); err != nil {
				t.Errorf("deleting a user: %v", err)
			}
		})
	}
	if _, err := a.call(http.MethodPut, "/admin/realms/"+realmName+"/users/"+disabled.userID,
		map[string]any{"enabled": false}, http.StatusNoContent); err != nil {
		t.Fatalf("disabling a user: %v", err)
	}

	for locale, message := range map[string]string{"en": "Invalid username or password.",
		"id": "Nama pengguna atau kata sandi tidak valid."} {
		attempts := map[string][2]string{
			"an unknown identifier": {"compat-nobody-" + suffix(), "Compat-" + suffix() + "!"},
			"a wrong password":      {active.username, "Wrong-" + suffix() + "!"},
			"a disabled account":    {disabled.username, disabled.password},
		}
		statuses := map[string]int{}
		for name, credential := range attempts {
			b := newThemeBrowser(t)
			status, answer := b.signIn(b.loginPage(a, caller, locale), credential[0], credential[1])
			statuses[name] = status
			text := html.UnescapeString(answer)
			if !strings.Contains(text, message) {
				t.Errorf("%s, %s: the answer does not read %q: %s", locale, name, message, snippet(answer))
			}
			// The kernel's own wording for a disabled account, in each locale. "disabled" alone appears in
			// the page's markup as an attribute, so the message itself is what is looked for.
			if strings.Contains(text, "Account is disabled") || strings.Contains(text, "Akun dinonaktifkan") {
				t.Errorf("%s, %s: the answer names the account's state", locale, name)
			}
		}
		for name, status := range statuses {
			if status != statuses["an unknown identifier"] {
				t.Errorf("%s: %s answered %d, an unknown identifier %d", locale, name, status, statuses["an unknown identifier"])
			}
		}
	}
}
