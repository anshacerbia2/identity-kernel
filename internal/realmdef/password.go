package realmdef

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// minPasswordHistory is the least passwordHistory the realm may declare. With any value Keycloak
// checks a new password against the current one, so 1 already refuses a temporary password as the
// password that replaces it (ADR-IAM-010 §5.2, TDD-identity-kernel-001 §Password Policy).
const minPasswordHistory = 1

var passwordHistory = regexp.MustCompile(`^passwordHistory\((\d+)\)$`)

// validatePasswordPolicy refuses a definition under which a temporary password could become the
// lasting one, or the login page could offer a reset. ASVS 5.0 6.4.1: "These initial secrets must not
// be permitted to become the long term password". Keycloak's update-password action compares nothing
// itself; only the realm's passwordHistory refuses the current password at the forced change.
func (d Definition) validatePasswordPolicy() error {
	if allowed, _ := d.Realm["resetPasswordAllowed"].(bool); allowed {
		return errors.New("scnehaux.json sets resetPasswordAllowed true; the login page offers no reset and the " +
			"kernel sends no mail (ADR-IAM-010 §5.5, ADR-IAM-007 §5.4)")
	}
	policy, _ := d.Realm["passwordPolicy"].(string)
	for _, part := range strings.Split(policy, " and ") {
		match := passwordHistory.FindStringSubmatch(strings.TrimSpace(part))
		if match == nil {
			continue
		}
		n, err := strconv.Atoi(match[1])
		if err != nil || n < minPasswordHistory {
			return fmt.Errorf("scnehaux.json declares %s; at least passwordHistory(%d) keeps a temporary password "+
				"from becoming the lasting one (ADR-IAM-010 §5.2)", part, minPasswordHistory)
		}
		return nil
	}
	return fmt.Errorf("scnehaux.json declares no passwordHistory in passwordPolicy %q; without it the forced change "+
		"accepts the temporary password as the new one (ADR-IAM-010 §5.2)", policy)
}
