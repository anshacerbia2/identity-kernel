package compat

// The declared realm contract, and proof-of-concept question 1.
//
// Question 1 runs first because it is the only one whose answer can force a restricted Keycloak
// extension or a standard amendment. TDD-identity-kernel-001 pre-decides the three outcomes so a
// partial answer needs no unplanned design round:
//
//	1  all four surfaces carry the claims      adopt the target configuration
//	2  the access token does, others do not    adopt access-token-only, record the gap
//	3  the access token does not               ESCALATE
//
// Outcome 3 fails the suite. Outcomes 1 and 2 pass and are reported, because both are acceptable
// and the difference between them is a recorded fact rather than a defect.

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------------------------
// Question 1
// ---------------------------------------------------------------------------------------------

func TestQuestion1ProtocolMapperCoverage(t *testing.T) {
	a := requireKeycloak(t)
	client := internalClient(t, a)
	// The party that introspects is a resource server named in the token's audience, as it is in
	// production (aud=["hcm-api"] in TDD-identity-kernel-001's token shape). Keycloak 26.7.4 refuses
	// introspection by any client outside aud -- found by this suite's first run, which introspected
	// with the issuing client and was told {"active":false} with the event reason "Client ... is not
	// in the token audience". Adding the issuing client to its own audience would have made the probe
	// pass by describing a deployment nobody runs.
	resource := resourceServerFor(t, a, client)
	who := createPrincipal(t, a)

	issued := passwordGrant(t, a, client, who)
	surfaces := []surface{
		{name: "access token", claims: jwtClaims(t, issued.AccessToken)},
		{name: "ID token", claims: jwtClaims(t, issued.IDToken)},
		{name: "UserInfo", claims: userInfo(t, a, issued.AccessToken)},
		{name: "introspection", claims: introspect(t, a, resource, issued.AccessToken)},
	}

	var covered, uncovered []string
	for i := range surfaces {
		s := &surfaces[i]
		s.principalID, _ = s.claims["principal_id"].(string)
		s.subjectType, _ = s.claims["subject_type"].(string)
		s.covered = s.principalID != "" && s.subjectType != ""
		if s.covered {
			covered = append(covered, s.name)
		} else {
			uncovered = append(uncovered, s.name)
		}
	}

	outcome := 1
	switch {
	case !surfaces[0].covered:
		outcome = 3
	case len(uncovered) > 0:
		outcome = 2
	}
	report(t, surfaces, outcome)

	if outcome == 3 {
		t.Fatalf("OUTCOME 3 -- ESCALATE: the access token does not carry principal_id and subject_type "+
			"through a supported mapper (got principal_id=%q subject_type=%q). STD-IAM-001 §3.3 makes "+
			"this mandatory; per TDD-identity-kernel-001 this is the one answer that forces a restricted "+
			"extension or a standard amendment.", surfaces[0].principalID, surfaces[0].subjectType)
	}

	// The answer is now a contract. Question 1 was answered with outcome 1 against the pinned image,
	// and realm/contract.json declares all four surfaces covered -- so a later release that drops the
	// claim from any of them must fail here, not quietly report outcome 2 and pass. TDD-identity-
	// kernel-001: "A release dropping the claim from a covered surface fails the suite."
	for _, name := range declaredSurfaces(t) {
		for _, s := range surfaces {
			if s.name == name && !s.covered {
				t.Errorf("REGRESSION: %s is declared covered in realm/contract.json and no longer carries "+
					"principal_id and subject_type (principal_id=%q subject_type=%q). Downstream consumers "+
					"build against this surface; a release that drops it is a breaking change.",
					s.name, s.principalID, s.subjectType)
			}
		}
	}

	// Every covered surface must say the same thing. A surface carrying a different value is worse
	// than one carrying none: a consumer reading it would resolve a different Principal.
	for _, s := range surfaces {
		if !s.covered {
			continue
		}
		if s.principalID != who.principalID {
			t.Errorf("%s carries principal_id %q, and the Principal holds %q", s.name, s.principalID, who.principalID)
		}
		if s.subjectType != "human" {
			t.Errorf("%s carries subject_type %q, want human", s.name, s.subjectType)
		}
	}
	t.Logf("question 1: outcome %d -- covered: %s; uncovered: %s",
		outcome, strings.Join(covered, ", "), orNone(uncovered))
}

// The negative control. Every coverage verdict above is "the claim is present", and a probe that
// could not see absence would report outcome 1 against any Keycloak at all. So the same mapper is
// attached with every surface switched off, and the probe must find the claim missing from all
// four. Without this, the regression assertion above is a check that cannot fail.
func TestTheProbeSeesAnAbsentClaim(t *testing.T) {
	a := requireKeycloak(t)

	name := "compat-control-" + suffix()
	_, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/client-scopes", map[string]any{
		"name":       name,
		"protocol":   "openid-connect",
		"attributes": map[string]string{"include.in.token.scope": "true"},
		"protocolMappers": []map[string]any{{
			"name":           "principal_id",
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-usermodel-attribute-mapper",
			"config": map[string]string{
				"user.attribute":            "scnehaux_principal_id",
				"claim.name":                "principal_id",
				"jsonType.label":            "String",
				"access.token.claim":        "false",
				"id.token.claim":            "false",
				"userinfo.token.claim":      "false",
				"introspection.token.claim": "false",
			},
		}},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating the control scope: %v", err)
	}

	control := clientWithScope(t, a, "compat-control-"+suffix(), name)
	resource := resourceServerFor(t, a, control)
	who := createPrincipal(t, a)
	issued := passwordGrant(t, a, control, who)

	for surfaceName, claims := range map[string]map[string]any{
		"access token":  jwtClaims(t, issued.AccessToken),
		"ID token":      jwtClaims(t, issued.IDToken),
		"UserInfo":      userInfo(t, a, issued.AccessToken),
		"introspection": introspect(t, a, resource, issued.AccessToken),
	} {
		if value, present := claims["principal_id"]; present {
			t.Errorf("%s carries principal_id=%v from a mapper with that surface switched off: the probe "+
				"cannot tell a covered surface from an uncovered one", surfaceName, value)
		}
	}
}

// declaredContract is the part of realm/contract.json the suite asserts against. Each field is an
// answer other repositories now build on, so a release that changes one fails as a regression.
type declaredContract struct {
	ClaimSurfaces []string `json:"claim_surfaces"`
	Question2     struct {
		ExactMatch bool `json:"exact_match"`
	} `json:"question_2"`
	Question3 struct {
		WriteOnceAchievable       bool `json:"write_once_achievable"`
		PartialPutKeepsIdentifier bool `json:"partial_put_keeps_identifier"`
	} `json:"question_3"`
}

func loadContract(t *testing.T) declaredContract {
	t.Helper()
	raw, err := readFile("contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract declaredContract
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("parsing realm/contract.json: %v", err)
	}
	return contract
}

func declaredSurfaces(t *testing.T) []string {
	t.Helper()
	surfaces := loadContract(t).ClaimSurfaces
	if len(surfaces) == 0 {
		t.Fatal("realm/contract.json declares no claim surfaces; the regression check would assert nothing")
	}
	return surfaces
}

// ---------------------------------------------------------------------------------------------
// The rest of the declared contract
// ---------------------------------------------------------------------------------------------

// The attribute survives creation. Asserted separately, because every claim assertion above rests
// on it: since Keycloak 24 an attribute the user profile does not declare is dropped on write, and
// a probe against a user whose attribute never landed reports a coverage gap that is really a
// configuration one.
func TestACreatedPrincipalCarriesItsIdentifier(t *testing.T) {
	a := requireKeycloak(t)
	who := createPrincipal(t, a)

	var user struct {
		Attributes map[string][]string `json:"attributes"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+who.userID, &user); err != nil {
		t.Fatalf("reading the user: %v", err)
	}
	if got := user.Attributes["scnehaux_principal_id"]; len(got) != 1 || got[0] != who.principalID {
		t.Fatalf("the created user holds scnehaux_principal_id %v, want [%s]", got, who.principalID)
	}
}

func TestTheInternalAccessTokenMeetsTheContract(t *testing.T) {
	a := requireKeycloak(t)
	client := internalClient(t, a)
	who := createPrincipal(t, a)
	issued := passwordGrant(t, a, client, who)

	header := jwtHeader(t, issued.AccessToken)
	claims := jwtClaims(t, issued.AccessToken)

	// PS256 is STD-IAM-002 §3.2.2's baseline, and the estate's verifier accepts nothing else.
	if header["alg"] != "PS256" {
		t.Errorf("the access token is signed with %v, want PS256", header["alg"])
	}

	// The path form, recorded as the current issuer. Question 4 decides whether it is kept; until it
	// has, the contract is whatever this instance issues, asserted exactly so a change is seen.
	if want := a.base + "/realms/" + realmName; claims["iss"] != want {
		t.Errorf("iss is %v, want %s", claims["iss"], want)
	}

	// sub is the issuer-scoped protocol subject and principal_id the enterprise identifier.
	// STD-IAM-001 §3.3 forbids using sub as an enterprise foreign key, which is only enforceable if
	// the two can never be confused for one another.
	sub, _ := claims["sub"].(string)
	if sub == "" {
		t.Error("the access token carries no sub; the realm's basic client scope is not attached")
	}
	if sub == who.principalID {
		t.Errorf("sub and principal_id hold the same value %q; the two claims must stay distinct", sub)
	}
}

// An external relying party receives iss and sub and nothing enterprise-wide. principal_id is a
// correlation key by design, which is exactly why it must not leave the internal audiences.
func TestAnExternalTokenCarriesNoEnterpriseClaim(t *testing.T) {
	a := requireKeycloak(t)
	client := clientWithScope(t, a, "compat-external-"+suffix(), "scnehaux-external")
	who := createPrincipal(t, a)
	issued := passwordGrant(t, a, client, who)

	claims := jwtClaims(t, issued.AccessToken)
	for _, name := range []string{"principal_id", "subject_type", "workload_owner",
		"tenant_id", "workspace_id", "membership_version", "tenant_security_version"} {
		if value, present := claims[name]; present {
			t.Errorf("an external access token carries %s=%v", name, value)
		}
	}
}

func TestSelfRegistrationIsClosed(t *testing.T) {
	a := requireKeycloak(t)
	var realm struct {
		RegistrationAllowed bool `json:"registrationAllowed"`
	}
	if err := a.getJSON("/admin/realms/"+realmName, &realm); err != nil {
		t.Fatalf("reading the realm: %v", err)
	}
	if realm.RegistrationAllowed {
		t.Error("self-registration is enabled: a Principal can be created outside identity-control")
	}
}

// No enterprise scope is a realm default. Attached as one, every client in the realm -- external
// relying parties included -- would receive principal_id without asking for it.
func TestNoEnterpriseScopeIsARealmDefault(t *testing.T) {
	a := requireKeycloak(t)
	for _, kind := range []string{"default-default-client-scopes", "default-optional-client-scopes"} {
		var scopes []struct {
			Name string `json:"name"`
		}
		if err := a.getJSON("/admin/realms/"+realmName+"/"+kind, &scopes); err != nil {
			t.Fatalf("reading %s: %v", kind, err)
		}
		for _, scope := range scopes {
			if strings.HasPrefix(scope.Name, "scnehaux-") {
				t.Errorf("%s is a realm %s; enterprise claims would reach every client", scope.Name, kind)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Fixtures -- test-only clients and Principals, created through the Admin API
// ---------------------------------------------------------------------------------------------
//
// The clients below enable the resource-owner password grant, which the realm definition does not
// and must not. It is the one way a suite can obtain a user's tokens without driving a browser, and
// it exists only on clients this suite creates for itself.

type client struct {
	uuid, id, secret string
}

type principal struct {
	userID, username, password, principalID string
}

func internalClient(t *testing.T, a *admin) client {
	return clientWithScope(t, a, "compat-internal-"+suffix(), "scnehaux-internal")
}

func clientWithScope(t *testing.T, a *admin, clientID, scope string) client {
	t.Helper()
	secret := "compat-" + suffix()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/clients", map[string]any{
		"clientId":                  clientID,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"secret":                    secret,
		"standardFlowEnabled":       false,
		"directAccessGrantsEnabled": true,
		"serviceAccountsEnabled":    false,
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating client %s: %v", clientID, err)
	}
	clientUUID := created(response)

	// Attached explicitly rather than through the representation's defaultClientScopes, so the
	// scope a test depends on is known to be attached rather than assumed to have been honoured.
	scopeID := scopeIDByName(t, a, scope)
	if _, err := a.call(http.MethodPut,
		"/admin/realms/"+realmName+"/clients/"+clientUUID+"/default-client-scopes/"+scopeID,
		nil, http.StatusNoContent); err != nil {
		t.Fatalf("attaching %s to %s: %v", scope, clientID, err)
	}
	return client{uuid: clientUUID, id: clientID, secret: secret}
}

// resourceServerFor creates a resource server and puts it in the audience of tokens issued to
// `issuer`, the way a product API receives tokens in production.
//
// The audience mapper sits on the issuing client rather than in scnehaux-internal: which API a token
// is for is a property of the client relationship, while the scope carries the claim allowlist.
// Folding the audience into the scope would make every internal token valid at every API.
func resourceServerFor(t *testing.T, a *admin, issuer client) client {
	t.Helper()
	resourceID := "compat-resource-" + suffix()
	secret := "compat-" + suffix()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/clients", map[string]any{
		"clientId":                  resourceID,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"secret":                    secret,
		"standardFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    false,
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating resource server %s: %v", resourceID, err)
	}
	resource := client{uuid: created(response), id: resourceID, secret: secret}

	if _, err := a.call(http.MethodPost,
		"/admin/realms/"+realmName+"/clients/"+issuer.uuid+"/protocol-mappers/models", map[string]any{
			"name":           "audience-" + resourceID,
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-audience-mapper",
			"config": map[string]string{
				"included.client.audience":  resourceID,
				"access.token.claim":        "true",
				"id.token.claim":            "false",
				"introspection.token.claim": "true",
			},
		}, http.StatusCreated); err != nil {
		t.Fatalf("adding %s to the audience of %s: %v", resourceID, issuer.id, err)
	}
	return resource
}

func scopeIDByName(t *testing.T, a *admin, name string) string {
	t.Helper()
	var scopes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/client-scopes", &scopes); err != nil {
		t.Fatalf("listing client scopes: %v", err)
	}
	for _, scope := range scopes {
		if scope.Name == name {
			return scope.ID
		}
	}
	t.Fatalf("client scope %s does not exist; the apply step did not create it", name)
	return ""
}

// createPrincipal creates a user the way identity-control does: through the Admin API, with the
// canonical identifier already minted and written as an attribute at creation.
func createPrincipal(t *testing.T, a *admin) principal {
	t.Helper()
	p, err := newPrincipal(a, uuidV7(), true)
	if err != nil {
		t.Fatalf("creating a Principal: %v", err)
	}
	return p
}

// newPrincipal is createPrincipal without the verdict, for the probes whose question is whether
// Keycloak accepts the user at all -- a second user carrying the same identifier, for one.
func newPrincipal(a *admin, principalID string, enabled bool) (principal, error) {
	p := principal{
		username:    "compat-" + suffix(),
		password:    "Compat-" + suffix() + "!",
		principalID: principalID,
	}
	// email, first and last name are required for the user role in the default profile. Without
	// them the first login demands a profile update, and the password grant refuses a login that has
	// a required action pending.
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/users", map[string]any{
		"username":      p.username,
		"enabled":       enabled,
		"email":         p.username + "@compat.invalid",
		"emailVerified": true,
		"firstName":     "Compat",
		"lastName":      "Principal",
		"attributes": map[string][]string{
			"scnehaux_principal_id": {p.principalID},
			"scnehaux_subject_type": {"human"},
		},
		"credentials": []map[string]any{{
			"type": "password", "value": p.password, "temporary": false,
		}},
		"requiredActions": []string{},
	}, http.StatusCreated)
	if err != nil {
		return p, err
	}
	p.userID = created(response)
	return p, nil
}

// ---------------------------------------------------------------------------------------------
// The four surfaces
// ---------------------------------------------------------------------------------------------

type issuedTokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

func (a *admin) realmURL(path string) string {
	return a.base + "/realms/" + realmName + "/protocol/openid-connect" + path
}

func passwordGrant(t *testing.T, a *admin, c client, p principal) issuedTokens {
	t.Helper()
	body := postForm(t, a, a.realmURL("/token"), url.Values{
		"grant_type":    {"password"},
		"client_id":     {c.id},
		"client_secret": {c.secret},
		"username":      {p.username},
		"password":      {p.password},
		// openid is what makes Keycloak issue an ID token and accept the access token at UserInfo.
		"scope": {"openid"},
	})
	var out issuedTokens
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		t.Fatalf("the token endpoint returned no access token: %s", body)
	}
	return out
}

func userInfo(t *testing.T, a *admin, accessToken string) map[string]any {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, a.realmURL("/userinfo"), nil)
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := a.http.Do(request)
	if err != nil {
		t.Fatalf("calling UserInfo: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("UserInfo answered %d: %s", response.StatusCode, body)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatalf("UserInfo returned something other than JSON claims: %s", body)
	}
	return claims
}

func introspect(t *testing.T, a *admin, c client, accessToken string) map[string]any {
	t.Helper()
	body := postForm(t, a, a.realmURL("/token/introspect"), url.Values{
		"token":         {accessToken},
		"client_id":     {c.id},
		"client_secret": {c.secret},
	})
	claims := map[string]any{}
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatalf("introspection returned something other than JSON: %s", body)
	}
	if active, _ := claims["active"].(bool); !active {
		t.Fatalf("introspection reports a token issued a moment ago as inactive: %s", body)
	}
	return claims
}

func postForm(t *testing.T, a *admin, target string, form url.Values) []byte {
	t.Helper()
	response, err := a.http.PostForm(target, form)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST %s answered %d: %s", target, response.StatusCode, body)
	}
	return body
}

func jwtClaims(t *testing.T, token string) map[string]any { return jwtPart(t, token, 1) }

func jwtHeader(t *testing.T, token string) map[string]any { return jwtPart(t, token, 0) }

// jwtPart decodes without verifying. The suite asserts what Keycloak put in a token it has just
// issued over a direct connection; signature verification is the consumers' contract, asserted in
// foundation-platform, and re-implementing it here would test a copy.
func jwtPart(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWT (%d segments)", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatalf("decoding JWT segment %d: %v", index, err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("JWT segment %d is not JSON: %v", index, err)
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------------------------

type surface struct {
	name        string
	claims      map[string]any
	principalID string
	subjectType string
	covered     bool
}

// report writes the question 1 answer to the log and, in CI, to the job summary -- with the image
// it was answered against, because an answer is only as reproducible as the bytes it was run on.
func report(t *testing.T, surfaces []surface, outcome int) {
	t.Helper()
	meaning := map[int]string{
		1: "all four surfaces covered -- adopt the target configuration",
		2: "access token covered, others not -- adopt access-token-only and record the gap",
		3: "access token NOT covered -- ESCALATE",
	}[outcome]

	var b strings.Builder
	fmt.Fprintf(&b, "## Proof-of-concept question 1: protocol mapper coverage\n\n")
	fmt.Fprintf(&b, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "| Surface | principal_id | subject_type | Covered |\n| :-- | :-- | :-- | :-- |\n")
	for _, s := range surfaces {
		mark := "no"
		if s.covered {
			mark = "yes"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", s.name, orDash(s.principalID), orDash(s.subjectType), mark)
	}
	fmt.Fprintf(&b, "\n**Outcome %d:** %s\n", outcome, meaning)
	publish(t, b.String())
}

// publish logs a question's answer and, in CI, appends it to the job summary.
func publish(t *testing.T, markdown string) {
	t.Helper()
	t.Log("\n" + markdown)
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		if file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			_, _ = file.WriteString(markdown + "\n")
			_ = file.Close()
		}
	}
}

func imageRef() string {
	file, err := os.Open(filepath.Join("..", "image", "keycloak.ref"))
	if err != nil {
		return "(image/keycloak.ref unreadable)"
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return "(no reference in image/keycloak.ref)"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return "`" + s + "`"
}

func orNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// ---------------------------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------------------------

var counter int

// suffix keeps fixture names unique within one run against one instance.
func suffix() string {
	counter++
	return fmt.Sprintf("%d-%d", time.Now().UnixNano()%1e9, counter)
}

// uuidV7 mints a UUIDv7-shaped identifier: identity-control's format for principal_id. Built here
// rather than imported, because this module takes no dependencies (see go.mod).
func uuidV7() string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	for i := 0; i < 6; i++ {
		b[i] = byte(ms >> (40 - 8*i))
	}
	if _, err := rand.Read(b[6:]); err != nil {
		panic("reading randomness for a fixture identifier: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
