package compat

// The kernel sends no mail (ADR-IAM-007 §5.4, STD-IAM-001 §3.1): account security notifications are
// the Identity Control API's to decide and the Notification Platform's to deliver. The applied realm
// holds no SMTP server and does not enable Keycloak's email event listener, whatever the release's
// defaults are.

import "testing"

func TestTheKernelSendsNoMail(t *testing.T) {
	a := requireKeycloak(t)

	var realm struct {
		SMTPServer map[string]any `json:"smtpServer"`
	}
	if err := a.getJSON("/admin/realms/"+realmName, &realm); err != nil {
		t.Fatalf("reading the realm: %v", err)
	}
	if host, _ := realm.SMTPServer["host"].(string); host != "" {
		t.Errorf("the realm holds an SMTP server, %q", host)
	}

	var events struct {
		EventsListeners []string `json:"eventsListeners"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/events/config", &events); err != nil {
		t.Fatalf("reading the event configuration: %v", err)
	}
	for _, listener := range events.EventsListeners {
		if listener == "email" {
			t.Errorf("the realm enables the email event listener: %v", events.EventsListeners)
		}
	}
}
