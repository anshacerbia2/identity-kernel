package realmdef

import (
	"errors"
	"fmt"
)

// The kernel sends no mail (ADR-IAM-007 §5.4). Account security notifications are decided by the
// Identity Control API and delivered by the Notification Platform: Keycloak's email event listener
// sees no admin event, mails one address, and only logs a failure. A definition that would give the
// realm an SMTP server or that listener is refused before anything is applied.
func (d Definition) validateNoMail() error {
	if server, present := d.Realm["smtpServer"]; present {
		if settings, ok := server.(map[string]any); !ok || len(settings) > 0 {
			return errors.New("scnehaux.json declares an smtpServer; the kernel sends no mail, account security " +
				"notifications go through the Notification Platform (ADR-IAM-007 §5.4)")
		}
	}
	if listeners, present := d.Realm["eventsListeners"]; present {
		names, ok := listeners.([]any)
		if !ok {
			return errors.New("scnehaux.json declares eventsListeners that are not a list")
		}
		for _, n := range names {
			if n == "email" {
				return fmt.Errorf("scnehaux.json enables the %q event listener; the kernel sends no mail (ADR-IAM-007 §5.4)", n)
			}
		}
	}
	return nil
}
