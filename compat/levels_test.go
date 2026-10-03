package compat

// Authentication levels, asked by identity-control: ADR-IAM-004 names aal1 (a password) and aal2
// (a password and a second factor), and TDD-identity-kernel-001 §Authentication Levels binds a
// browser flow that reaches each. This test signs a person in through the hosted pages the way a
// browser does -- cookies kept, forms filled, a TOTP code computed -- and asserts the acr each
// sign-in carries and which pages it showed.

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP, the realm's OTP policy (HmacSHA1).
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	formAction  = regexp.MustCompile(`<form[^>]*action="([^"]+)"`)
	hiddenInput = regexp.MustCompile(`<input[^>]*type="hidden"[^>]*>`)
	inputName   = regexp.MustCompile(`name="([^"]+)"`)
	inputValue  = regexp.MustCompile(`value="([^"]*)"`)
	namedInput  = func(field string) *regexp.Regexp { return regexp.MustCompile(`name="` + field + `"`) }
)

// browser signs one person in, keeping the kernel's cookies between sign-ins, and records which
// pages each sign-in showed.
type browser struct {
	t          *testing.T
	a          *admin
	c          client
	p          principal
	http       *http.Client
	totpSecret string
	pages      []string
}

func newBrowser(t *testing.T, a *admin, c client, p principal) *browser {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, a: a, c: c, p: p, http: &http.Client{
		Timeout: 20 * time.Second, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) send(request *http.Request) (*http.Response, string) {
	b.t.Helper()
	response, err := b.http.Do(request)
	if err != nil {
		b.t.Fatalf("%s %s: %v", request.Method, request.URL.Path, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response, string(body)
}

// signIn runs one authorization request to its code, filling the pages the kernel shows, and
// returns the tokens' claims. extra carries acr_values and max_age.
func (b *browser) signIn(extra url.Values) map[string]any {
	b.t.Helper()
	b.pages = nil
	verifier := randomToken(b.t)
	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id": {b.c.id}, "response_type": {"code"}, "redirect_uri": {providerRedirect},
		"scope": {"openid"}, "state": {"compat"}, "nonce": {randomToken(b.t)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		query[k] = v
	}
	request, _ := http.NewRequest(http.MethodGet, b.a.realmURL("/auth?"+query.Encode()), nil)
	response, page := b.send(request)
	for step := 0; step < 8; step++ {
		if response.StatusCode == http.StatusFound || response.StatusCode == http.StatusSeeOther {
			location, _ := url.Parse(response.Header.Get("Location"))
			if code := location.Query().Get("code"); code != "" && strings.HasPrefix(location.String(), providerRedirect) {
				return b.exchange(code, verifier)
			}
			request, _ = http.NewRequest(http.MethodGet, response.Header.Get("Location"), nil)
			response, page = b.send(request)
			continue
		}
		action := formAction.FindStringSubmatch(page)
		if response.StatusCode != http.StatusOK || action == nil {
			b.t.Fatalf("the sign-in answered %d with no form: %s", response.StatusCode, snippet(page))
		}
		form := url.Values{}
		for _, input := range hiddenInput.FindAllString(page, -1) {
			if n := inputName.FindStringSubmatch(input); n != nil {
				value := ""
				if v := inputValue.FindStringSubmatch(input); v != nil {
					value = html.UnescapeString(v[1])
				}
				form.Set(n[1], value)
			}
		}
		switch {
		case namedInput("password").MatchString(page):
			b.pages = append(b.pages, "password")
			form.Set("username", b.p.username)
			form.Set("password", b.p.password)
		case namedInput("totpSecret").MatchString(page):
			b.pages = append(b.pages, "configure-totp")
			b.totpSecret = form.Get("totpSecret")
			form.Set("totp", totp(b.totpSecret, time.Now()))
			form.Set("userLabel", "compat")
		case namedInput("otp").MatchString(page):
			b.pages = append(b.pages, "otp")
			if b.totpSecret == "" {
				b.t.Fatal("the kernel asked for a code before one was enrolled")
			}
			form.Set("otp", totp(b.totpSecret, time.Now()))
		default:
			b.t.Fatalf("an unexpected page: %s", snippet(page))
		}
		request, _ = http.NewRequest(http.MethodPost, html.UnescapeString(action[1]), strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, page = b.send(request)
	}
	b.t.Fatalf("the sign-in did not reach a code; pages %v", b.pages)
	return nil
}

func (b *browser) exchange(code, verifier string) map[string]any {
	b.t.Helper()
	body := postForm(b.t, b.a, b.a.realmURL("/token"), url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {providerRedirect},
		"client_id": {b.c.id}, "client_secret": {b.c.secret}, "code_verifier": {verifier},
	})
	var tokens issuedTokens
	if err := json.Unmarshal(body, &tokens); err != nil || tokens.AccessToken == "" {
		b.t.Fatalf("the code exchange returned no tokens: %s", body)
	}
	claims := jwtClaims(b.t, tokens.AccessToken)
	if tokens.IDToken != "" {
		claims["id_token_acr"] = jwtClaims(b.t, tokens.IDToken)["acr"]
	}
	return claims
}

// totp is RFC 6238 with the realm's policy: HmacSHA1, 30-second steps, six digits. Keycloak keys
// the HMAC with the secret's bytes as it shows them in totpSecret.
func totp(secret string, at time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

func TestAuthenticationLevels(t *testing.T) {
	a := requireKeycloak(t)
	c := providerCaller(t, a)
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
	b := newBrowser(t, a, c, p)

	var steps []lifecycleStep
	require := func(name string, observed, want bool, detail string) {
		steps = append(steps, lifecycleStep{name: name, observed: observed, required: yesNo(want)})
		if observed != want {
			t.Errorf("%s: observed %v, want %v: %s", name, observed, want, detail)
		}
	}
	pages := func() string { return strings.Join(b.pages, ",") }

	claims := b.signIn(nil)
	require("a password sign-in carries acr aal1", claims["acr"] == "aal1", true, fmt.Sprint(claims["acr"]))
	require("it showed the password page alone", pages() == "password", true, pages())

	claims = b.signIn(url.Values{"acr_values": {"aal2"}})
	require("asked for aal2 with no second factor: TOTP is enrolled in that sign-in",
		strings.Contains(pages(), "configure-totp"), true, pages())
	require("then the token carries acr aal2", claims["acr"] == "aal2", true, fmt.Sprint(claims["acr"]))
	require("the ID token carries acr aal2", claims["id_token_acr"] == "aal2", true, fmt.Sprint(claims["id_token_acr"]))

	claims = b.signIn(url.Values{"acr_values": {"aal2"}})
	require("aal2 asked again within 300 s shows no page", pages() == "", true, pages())
	require("and still carries aal2", claims["acr"] == "aal2", true, fmt.Sprint(claims["acr"]))

	// A new TOTP step, so the code differs from the one just used.
	time.Sleep(time.Until(time.Unix((time.Now().Unix()/30+1)*30, 0)) + time.Second)
	claims = b.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}})
	require("aal2 with max_age 0 asks for the password and the code again", pages() == "password,otp", true, pages())
	require("and carries aal2", claims["acr"] == "aal2", true, fmt.Sprint(claims["acr"]))

	claims = b.signIn(url.Values{"acr_values": {"phr"}})
	require("an unmapped acr is never answered with that level", claims["acr"] != "phr", true, fmt.Sprint(claims["acr"]))
	steps = append(steps, lifecycleStep{name: fmt.Sprintf("an unmapped acr is answered with %v", claims["acr"]),
		observed: true})

	var out strings.Builder
	fmt.Fprintf(&out, "## Authentication levels\n\n")
	fmt.Fprintf(&out, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&out, "| Step | Observed | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&out, "| %s | %s | %s |\n", s.name, yesNo(s.observed), orDash(s.required))
	}
	if t.Failed() {
		fmt.Fprintf(&out, "\n**Outcome:** the realm does not reach aal1 and aal2 as ADR-IAM-004 requires.\n")
	} else {
		fmt.Fprintf(&out, "\n**Outcome:** a password sign-in is aal1; aal2 adds a TOTP code, enrolled at the first "+
			"aal2 sign-in, reused for 300 s, and asked again with max_age 0.\n")
	}
	publish(t, out.String())
}
