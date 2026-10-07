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
	"strconv"
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
	// label names the next TOTP enrolled; secrets holds every enrolled one by label.
	label   string
	secrets map[string]string
	// credential, when set, is the OTP credential the code page is answered for.
	credential string
	// key answers the WebAuthn pages, once set.
	key *softKey
	// codes are the recovery codes the kernel showed, in order; asked holds the number of each code
	// the kernel asked for. recover, when set, leaves the second-factor page through "Try another
	// way" for the recovery code (ADR-IAM-005 §5.2).
	codes   []string
	asked   []int
	recover bool
	// newPassword, when set, answers the update-password page; the sign-in after it uses it.
	newPassword string
	// refresh is the refresh token of the last sign-in.
	refresh string
}

var (
	recoveryCode       = regexp.MustCompile(`<li>([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})</li>`)
	recoveryCodeNumber = regexp.MustCompile(`[Cc]ode #(\d+)`)
	// One option of the selection page: its form, and beside it, in the same list item, its name.
	selectionForm = regexp.MustCompile(`(?s)<li[^>]*>\s*<form[^>]*id="kc-select-credential-form".*?</li>`)
)

// tryAnotherWay is the "Try another way" form a page offers beside its own.
func tryAnotherWay(page string) bool { return strings.Contains(page, `name="tryAnotherWay"`) }

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
			b.t.Fatalf("the sign-in answered %d with no form, after pages %v, saying %q", response.StatusCode, b.pages,
				pageMessage(page))
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
		// The "Try another way" form is a separate form on the same page; a browser submitting the
		// page's own form does not send it.
		form.Del("tryAnotherWay")
		base, _ := url.Parse(b.a.base)
		origin := base.Scheme + "://" + base.Host
		switch {
		case b.recover && tryAnotherWay(page) && !namedInput("authenticationExecution").MatchString(page) &&
			!namedInput("recoveryCodeInput").MatchString(page):
			b.pages = append(b.pages, "try-another-way")
			form = url.Values{"tryAnotherWay": {"on"}}
		case namedInput("authenticationExecution").MatchString(page):
			b.pages = append(b.pages, "select")
			chosen := ""
			for _, option := range selectionForm.FindAllString(page, -1) {
				if strings.Contains(option, "Recovery") {
					if v := regexp.MustCompile(`name="authenticationExecution" value="([^"]+)"`).FindStringSubmatch(option); v != nil {
						chosen = v[1]
					}
				}
			}
			if chosen == "" {
				b.t.Fatalf("the selection offers no recovery code: %q", pageMessage(page))
			}
			form = url.Values{"authenticationExecution": {chosen}}
		case namedInput("generatedRecoveryAuthnCodes").MatchString(page):
			b.pages = append(b.pages, "recovery-codes")
			b.codes = nil
			for _, code := range recoveryCode.FindAllStringSubmatch(page, -1) {
				b.codes = append(b.codes, code[1])
			}
			if len(b.codes) == 0 {
				b.t.Fatal("the recovery-code page shows no codes")
			}
		case namedInput("recoveryCodeInput").MatchString(page):
			b.pages = append(b.pages, "recovery-code")
			n := recoveryCodeNumber.FindStringSubmatch(page)
			if n == nil {
				b.t.Fatalf("the recovery-code page names no code number: %q", pageMessage(page))
			}
			number, _ := strconv.Atoi(n[1])
			if number < 1 || number > len(b.codes) {
				b.t.Fatalf("the kernel asked for recovery code #%d of the %d the test holds", number, len(b.codes))
			}
			b.asked = append(b.asked, number)
			form.Set("recoveryCodeInput", b.codes[number-1])
		case namedInput("attestationObject").MatchString(page):
			b.pages = append(b.pages, "webauthn-register")
			if b.key == nil {
				b.t.Fatal("the kernel asked to register a WebAuthn authenticator the test holds none of")
			}
			b.key.register(b.t, page, origin, form)
		case namedInput("authenticatorData").MatchString(page):
			b.pages = append(b.pages, "webauthn")
			if b.key == nil {
				b.t.Fatal("the kernel asked for a WebAuthn assertion the test holds no key for")
			}
			b.key.assert(b.t, page, origin, form)
		case namedInput("password-new").MatchString(page):
			b.pages = append(b.pages, "update-password")
			if b.newPassword == "" {
				b.t.Fatal("the kernel asked for a new password the test holds none of")
			}
			form.Set("password-new", b.newPassword)
			form.Set("password-confirm", b.newPassword)
		case namedInput("accept").MatchString(page) && strings.Contains(page, `id="kc-oauth"`):
			// The consent page (login-oauth-grant.ftl): "Yes" grants the client what it asked for.
			b.pages = append(b.pages, "consent")
			form.Set("accept", "")
		case namedInput("accept").MatchString(page) && strings.Contains(page, "kc-delete-text"):
			b.pages = append(b.pages, "delete-credential")
			form.Set("accept", "")
		case namedInput("password").MatchString(page):
			b.pages = append(b.pages, "password")
			form.Set("username", b.p.username)
			form.Set("password", b.p.password)
		case namedInput("totpSecret").MatchString(page):
			b.pages = append(b.pages, "configure-totp")
			secret := form.Get("totpSecret")
			label := b.label
			if label == "" {
				label = "compat"
			}
			if b.secrets == nil {
				b.secrets = map[string]string{}
			}
			b.secrets[label] = secret
			if b.totpSecret == "" {
				b.totpSecret = secret
			}
			form.Set("totp", totp(secret, time.Now()))
			form.Set("userLabel", label)
		case namedInput("otp").MatchString(page):
			b.pages = append(b.pages, "otp")
			if b.totpSecret == "" {
				b.t.Fatal("the kernel asked for a code before one was enrolled")
			}
			secret := b.totpSecret
			if b.credential != "" {
				form.Set("selectedCredentialId", b.credential)
				secret = b.secrets[b.label]
			}
			form.Set("otp", totp(secret, time.Now()))
		default:
			var names []string
			for _, n := range regexp.MustCompile(`name="([^"]+)"`).FindAllStringSubmatch(page, -1) {
				names = append(names, n[1])
			}
			b.t.Fatalf("an unexpected page after pages %v, saying %q, with inputs %v", b.pages, pageMessage(page), names)
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
	b.refresh = tokens.RefreshToken
	claims := jwtClaims(b.t, tokens.AccessToken)
	if tokens.IDToken != "" {
		claims["id_token_acr"] = jwtClaims(b.t, tokens.IDToken)["acr"]
	}
	return claims
}

// pageMessage is the text a Keycloak page shows as its message: an alert's, or an instruction's.
func pageMessage(page string) string {
	var out []string
	for _, pattern := range []string{`(?s)class="[^"]*kc-feedback-text[^"]*"[^>]*>(.*?)<`,
		`(?s)id="kc-page-title"[^>]*>(.*?)<`, `(?s)class="instruction"[^>]*>(.*?)<`,
		`(?s)<title>(.*?)</title>`} {
		for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(page, -1) {
			if text := strings.TrimSpace(html.UnescapeString(m[1])); text != "" {
				out = append(out, text)
			}
		}
	}
	if len(out) == 0 {
		return snippet(page)
	}
	return strings.Join(out, " | ")
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
	require("and recovery codes are issued after it (ADR-IAM-005 §5.3)",
		strings.HasSuffix(pages(), "configure-totp,recovery-codes") && len(b.codes) == 12, true,
		fmt.Sprint(pages(), " ", len(b.codes)))
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

	// A second TOTP, bound at aal2 through the application-initiated action (ADR-IAM-004 §5.5): the
	// account already holds a TOTP, so the binding authenticates at aal2 first (NIST SP 800-63B-4
	// §4.1.2.1).
	time.Sleep(time.Until(time.Unix((time.Now().Unix()/30+1)*30, 0)) + time.Second)
	b.label = "compat-server"
	claims = b.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}, "kc_action": {"CONFIGURE_TOTP"}})
	require("kc_action CONFIGURE_TOTP after an aal2 sign-in sets up another TOTP",
		pages() == "password,otp,configure-totp", true, pages())
	var credentials []struct {
		ID        string `json:"id"`
		Type      string `json:"type"`
		UserLabel string `json:"userLabel"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+p.userID+"/credentials", &credentials); err != nil {
		t.Fatalf("listing the credentials: %v", err)
	}
	second := ""
	otps := 0
	for _, credential := range credentials {
		if credential.Type == "otp" {
			otps++
			if credential.UserLabel == "compat-server" {
				second = credential.ID
			}
		}
	}
	require("the person then holds two TOTP credentials", otps == 2 && second != "", true, fmt.Sprint(credentials))

	time.Sleep(time.Until(time.Unix((time.Now().Unix()/30+1)*30, 0)) + time.Second)
	b.credential = second
	claims = b.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}})
	require("the second TOTP alone signs in at aal2", claims["acr"] == "aal2" && pages() == "password,otp", true,
		fmt.Sprint(claims["acr"], " ", pages()))
	b.credential, b.label = "", ""
	time.Sleep(time.Until(time.Unix((time.Now().Unix()/30+1)*30, 0)) + time.Second)
	claims = b.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}})
	require("the first TOTP still signs in at aal2", claims["acr"] == "aal2", true, fmt.Sprint(claims["acr"]))

	// WebAuthn at level 2 (scnehaux-browser-v2). A WebAuthn authenticator is registered through the
	// application-initiated action after an aal2 sign-in, the TOTPs are then deleted, and a sign-in
	// at aal2 is answered by the key alone.
	time.Sleep(time.Until(time.Unix((time.Now().Unix()/30+1)*30, 0)) + time.Second)
	b.key = newSoftKey(t)
	b.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}, "kc_action": {"webauthn-register"}})
	require("kc_action webauthn-register after an aal2 sign-in registers a WebAuthn authenticator",
		strings.HasSuffix(pages(), "webauthn-register"), true, pages())

	// Holding both factors, the person is shown one of them; which one is recorded, not required.
	time.Sleep(time.Until(time.Unix((time.Now().Unix()/30+1)*30, 0)) + time.Second)
	claims = b.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}})
	require("holding a TOTP and a key, aal2 is reached", claims["acr"] == "aal2", true, fmt.Sprint(claims["acr"]))
	steps = append(steps, lifecycleStep{name: "holding both, the pages shown are " + pages(), observed: true})

	credentials = nil
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+p.userID+"/credentials", &credentials); err != nil {
		t.Fatalf("listing the credentials: %v", err)
	}
	webauthns := 0
	for _, credential := range credentials {
		switch credential.Type {
		case "webauthn":
			webauthns++
		case "otp", "recovery-authn-codes":
			if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID+"/credentials/"+credential.ID,
				nil, http.StatusNoContent); err != nil {
				t.Fatalf("deleting a TOTP: %v", err)
			}
		}
	}
	require("the person holds a WebAuthn credential", webauthns == 1, true, fmt.Sprint(credentials))
	// max_age 0 is measured in whole seconds from the last authentication, so let one pass.
	time.Sleep(2 * time.Second)
	claims = b.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}})
	require("with the key alone, aal2 asks for the password and the key", pages() == "password,webauthn", true, pages())
	require("and carries aal2", claims["acr"] == "aal2", true, fmt.Sprint(claims["acr"]))

	// A person with neither factor still enrolls a TOTP in their first aal2 sign-in under v2.
	fresh := createPrincipal(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+fresh.userID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting user %s: %v", fresh.username, err)
		}
	})
	other := newBrowser(t, a, c, fresh)
	claims = other.signIn(url.Values{"acr_values": {"aal2"}})
	require("a person with neither factor enrolls a TOTP, then saves recovery codes, at aal2",
		strings.Join(other.pages, ",") == "password,configure-totp,recovery-codes", true, strings.Join(other.pages, ","))
	require("and carries aal2 after it", claims["acr"] == "aal2", true, fmt.Sprint(claims["acr"]))

	// Recovery (ADR-IAM-005 §5.2): the person still holds the TOTP but not the phone, so they leave
	// its page through "Try another way" and give a recovery code after the password.
	time.Sleep(2 * time.Second)
	other.recover = true
	claims = other.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}})
	recovered := strings.Join(other.pages, ",")
	require("a recovery code after the password reaches aal2",
		strings.HasSuffix(recovered, "recovery-code") && claims["acr"] == "aal2", true,
		fmt.Sprint(recovered, " ", claims["acr"]))
	steps = append(steps, lifecycleStep{name: "recovering, the pages shown are " + recovered, observed: true})
	time.Sleep(2 * time.Second)
	claims = other.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}})
	require("a used code is not asked for again: the next sign-in asks for the next one",
		len(other.asked) == 2 && other.asked[1] == other.asked[0]+1 && claims["acr"] == "aal2", true,
		fmt.Sprint(other.asked, " ", claims["acr"]))

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
		fmt.Fprintf(&out, "\n**Outcome:** a password sign-in is aal1; aal2 adds a TOTP code, enrolled with "+
			"recovery codes at the first aal2 sign-in, a WebAuthn authenticator, or a recovery code; level 2 is "+
			"reused for 300 s and asked again with max_age 0.\n")
	}
	publish(t, out.String())
}
