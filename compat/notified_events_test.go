package compat

// The events ADR-IAM-007 §5.1 notifies, as the pinned kernel records them. Identity Control decides
// each notification from the kernel event record, so each event must be told apart there: a TOTP
// bound and recovery codes issued at the first aal2 sign-in, a recovery code used, a security key
// bound through the application-initiated action, and a credential a provider removes through the
// Admin API. The test signs one person through all of them, reads the realm's user and admin events
// for that person, and records which event and which details mark each step. TDD-identity-control-008
// maps notifications from this table, and the assertions below hold the marks it relies on.

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

type recordedUserEvent struct {
	Time    int64             `json:"time"`
	Type    string            `json:"type"`
	Details map[string]string `json:"details"`
}

type recordedAdminEvent struct {
	Time          int64  `json:"time"`
	OperationType string `json:"operationType"`
	ResourceType  string `json:"resourceType"`
	ResourcePath  string `json:"resourcePath"`
}

// describe is an event's type and the details that tell it apart, never a value that could be a
// credential.
func describe(e recordedUserEvent) string {
	var keys []string
	for k, v := range e.Details {
		switch k {
		case "credential_type", "custom_required_action", "credential_id", "auth_method", "operation":
			if k == "credential_id" {
				v = "…"
			}
			keys = append(keys, k+"="+v)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return e.Type
	}
	return e.Type + " (" + strings.Join(keys, ", ") + ")"
}

func TestEachNotifiedEventIsToldApartInTheEventRecord(t *testing.T) {
	a := requireKeycloak(t)
	c := providerCaller(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil, http.StatusNoContent)
	})
	p := createPrincipal(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil, http.StatusNoContent)
	})
	b := newBrowser(t, a, c, p)

	type step struct {
		name     string
		from, to int64
	}
	var steps []step
	mark := func(name string, run func()) {
		from := time.Now().UnixMilli()
		run()
		// The event store's clock is the kernel's; a second either side keeps an event at the edge in
		// its own step without reaching the next.
		time.Sleep(1100 * time.Millisecond)
		steps = append(steps, step{name, from - 500, time.Now().UnixMilli() - 500})
	}
	nextStep := func() { time.Sleep(time.Until(time.Unix((time.Now().Unix()/30+1)*30, 0)) + time.Second) }

	mark("a TOTP bound and recovery codes issued, at the first aal2 sign-in", func() {
		b.signIn(url.Values{"acr_values": {"aal2"}})
	})
	mark("a recovery code used, after the password", func() {
		b.recover = true
		b.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}})
		b.recover = false
	})
	nextStep()
	mark("a security key bound through kc_action=webauthn-register", func() {
		b.key = newSoftKey(t)
		b.signIn(url.Values{"acr_values": {"aal2"}, "max_age": {"0"}, "kc_action": {"webauthn-register"}})
	})
	var credentials []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/users/"+p.userID+"/credentials", &credentials); err != nil {
		t.Fatalf("listing the credentials: %v", err)
	}
	mark("the TOTP removed by a provider through the Admin API", func() {
		for _, credential := range credentials {
			if credential.Type == "otp" {
				if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID+"/credentials/"+
					credential.ID, nil, http.StatusNoContent); err != nil {
					t.Fatalf("removing the TOTP: %v", err)
				}
			}
		}
	})

	var users []recordedUserEvent
	if err := a.getJSON("/admin/realms/"+realmName+"/events?user="+p.userID+"&max=200", &users); err != nil {
		t.Fatalf("reading the user events: %v", err)
	}
	var admins []recordedAdminEvent
	if err := a.getJSON("/admin/realms/"+realmName+"/admin-events?max=500&dateFrom="+
		time.UnixMilli(steps[0].from).UTC().Format("2006-01-02"), &admins); err != nil {
		t.Fatalf("reading the admin events: %v", err)
	}

	var out strings.Builder
	fmt.Fprintf(&out, "## The events ADR-IAM-007 notifies\n\nImage: `%s`\n\n", imageRef())
	fmt.Fprintf(&out, "| Step | User events | Admin events on the person's credentials |\n| :-- | :-- | :-- |\n")
	seen := map[string][]string{}
	for _, s := range steps {
		var userTypes, adminTypes []string
		for _, e := range users {
			if e.Time >= s.from && e.Time < s.to {
				userTypes = append(userTypes, describe(e))
			}
		}
		for _, e := range admins {
			if e.Time >= s.from && e.Time < s.to && strings.HasPrefix(e.ResourcePath, "users/"+p.userID+"/credentials") {
				adminTypes = append(adminTypes, e.OperationType+" "+e.ResourceType+" users/…/credentials/…")
			}
		}
		sort.Strings(userTypes)
		seen[s.name] = append(userTypes, adminTypes...)
		fmt.Fprintf(&out, "| %s | %s | %s |\n", s.name, orDash(strings.Join(userTypes, "; ")), orDash(strings.Join(adminTypes, "; ")))
	}
	publish(t, out.String())

	// What the mapping needs, as 26.7.5 records it. Each step's mark is the event, and the details that
	// tell it from its neighbours:
	//   - a binding is UPDATE_CREDENTIAL naming the credential type;
	//   - a recovery code used is a LOGIN naming recovery-authn-codes with no required action, where
	//     the LOGIN that ends enrolment names the same type and CONFIGURE_RECOVERY_AUTHN_CODES;
	//   - a provider's removal is an admin ACTION, not a DELETE, on the person's credential.
	for name, wants := range map[string][]string{
		"a TOTP bound and recovery codes issued, at the first aal2 sign-in": {
			"UPDATE_CREDENTIAL (auth_method=openid-connect, credential_type=otp,",
			"UPDATE_CREDENTIAL (auth_method=openid-connect, credential_type=recovery-authn-codes,"},
		"a recovery code used, after the password": {
			"LOGIN (auth_method=openid-connect, credential_type=recovery-authn-codes)"},
		"a security key bound through kc_action=webauthn-register": {
			"UPDATE_CREDENTIAL (auth_method=openid-connect, credential_type=webauthn,"},
		"the TOTP removed by a provider through the Admin API": {"ACTION USER users/…/credentials/…"},
	} {
		joined := strings.Join(seen[name], "; ")
		for _, want := range wants {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: no event reads %q; recorded %s", name, want, orDash(joined))
			}
		}
	}
	// The enrolment's own LOGIN is not a recovery: it carries the required action.
	if enrolment := strings.Join(seen["a TOTP bound and recovery codes issued, at the first aal2 sign-in"], "; "); strings.Contains(enrolment,
		"LOGIN (auth_method=openid-connect, credential_type=recovery-authn-codes)") {
		t.Errorf("the enrolment's LOGIN reads as a recovery: %s", enrolment)
	}
}
