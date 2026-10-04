package compat

// Guessing limits (ADR-IAM-005 §5.6). The realm's own values reach a permanent lockout at the 100th
// consecutive failure, after waits that add up to hours, which no test can sit through; the
// arithmetic is asserted in internal/realmdef. This test asks the pinned kernel how the mode
// behaves, on a throwaway realm with the same mode and small values:
//   - a temporary lockout refuses even the right password;
//   - the failure after the last temporary lockout locks the user permanently, by disabling it;
//   - enabling the user, which identity-control's restore does, lets the right password in again.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTheLockoutModeAndItsRelease(t *testing.T) {
	a := requireKeycloak(t)
	realm := "compat-lockout-" + strings.ToLower(randomToken(t)[:8])
	// MULTIPLE strategy: a temporary lockout from the failureFactor-th failure, and a permanent one
	// once more than maxTemporaryLockouts were counted, here at the third failure.
	if _, err := a.call(http.MethodPost, "/admin/realms", map[string]any{
		"realm": realm, "enabled": true,
		"bruteForceProtected": true, "permanentLockout": true, "bruteForceStrategy": "MULTIPLE",
		"failureFactor": 2, "maxTemporaryLockouts": 1, "waitIncrementSeconds": 2, "maxFailureWaitSeconds": 2,
		"maxDeltaTimeSeconds": 3600, "quickLoginCheckMilliSeconds": 1, "minimumQuickLoginWaitSeconds": 1,
	}, http.StatusCreated); err != nil {
		t.Fatalf("creating realm %s: %v", realm, err)
	}
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realm, nil, http.StatusNoContent); err != nil {
			t.Errorf("deleting realm %s: %v", realm, err)
		}
	})
	password := randomToken(t)
	response, err := a.call(http.MethodPost, "/admin/realms/"+realm+"/users", map[string]any{
		"username": "locked", "enabled": true, "email": "locked@compat.invalid", "emailVerified": true,
		"firstName": "Locked", "lastName": "Out",
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating the user: %v", err)
	}
	userID := created(response)

	// signIn reports whether the password grant of the realm's built-in admin-cli client succeeds.
	signIn := func(secret string) bool {
		t.Helper()
		form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"locked"},
			"password": {secret}}
		r, err := a.http.Post(a.base+"/realms/"+realm+"/protocol/openid-connect/token",
			"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("the token request: %v", err)
		}
		defer func() { _ = r.Body.Close() }()
		_, _ = io.Copy(io.Discard, r.Body)
		return r.StatusCode == http.StatusOK
	}
	user := func() map[string]any {
		t.Helper()
		var u map[string]any
		if err := a.getJSON("/admin/realms/"+realm+"/users/"+userID, &u); err != nil {
			t.Fatalf("reading the user: %v", err)
		}
		return u
	}

	var steps []lifecycleStep
	require := func(name string, observed, want bool, detail string) {
		steps = append(steps, lifecycleStep{name: name, observed: observed, required: yesNo(want)})
		if observed != want {
			t.Errorf("%s: observed %v, want %v: %s", name, observed, want, detail)
		}
	}

	require("the right password signs in before any failure", signIn(password), true, "")
	wrong := randomToken(t)
	signIn(wrong)
	time.Sleep(1100 * time.Millisecond)
	signIn(wrong)
	require("during a temporary lockout the right password is refused", signIn(password), false, "")
	require("a temporary lockout leaves the user enabled", user()["enabled"] == true, true, fmt.Sprint(user()))

	time.Sleep(3 * time.Second)
	signIn(wrong)
	locked := user()
	require("the failure after the last temporary lockout disables the user", locked["enabled"] == false, true,
		fmt.Sprint(locked))
	reason, _ := json.Marshal(locked["attributes"])
	steps = append(steps, lifecycleStep{name: "a permanently locked user carries the attributes " + string(reason),
		observed: true})
	time.Sleep(3 * time.Second)
	require("a permanent lockout refuses the right password after the wait", signIn(password), false, "")

	locked["enabled"] = true
	if _, err := a.call(http.MethodPut, "/admin/realms/"+realm+"/users/"+userID, locked, http.StatusNoContent); err != nil {
		t.Fatalf("enabling the user: %v", err)
	}
	require("enabling the user, as a restore does, lets the right password in", signIn(password), true, "")

	var out strings.Builder
	fmt.Fprintf(&out, "## Guessing limits\n\n")
	fmt.Fprintf(&out, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&out, "| Step | Observed | Required |\n| :-- | :-- | :-- |\n")
	for _, s := range steps {
		fmt.Fprintf(&out, "| %s | %s | %s |\n", s.name, yesNo(s.observed), orDash(s.required))
	}
	if t.Failed() {
		fmt.Fprintf(&out, "\n**Outcome:** the lockout mode does not behave as ADR-IAM-005 §5.6 relies on.\n")
	} else {
		fmt.Fprintf(&out, "\n**Outcome:** temporary lockouts refuse even the right password; the failure after "+
			"the last one disables the user; enabling it again lets the person in.\n")
	}
	publish(t, out.String())
}
