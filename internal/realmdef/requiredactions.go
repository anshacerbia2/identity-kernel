package realmdef

// Required actions: the kernel's own pages a person is sent through during a sign-in, such as
// setting up a TOTP authenticator or saving recovery codes. Keycloak registers its built-in ones in
// every new realm, so the definition does not create them: it declares the fields it governs on
// those that exist, whether each is enabled and its configuration, and the apply lays them over the
// live representation (ADR-IAM-005 §5.3, TDD-identity-kernel-001 §Authentication Levels).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
)

const KindRequiredAction = "required action"

// requiredActionFields are the fields a definition may declare. Priority and the default-action
// switch are left to Keycloak: neither changes what a person is asked to prove.
var requiredActionFields = map[string]bool{"alias": true, "enabled": true, "config": true}

func validateRequiredActions(actions []map[string]any) error {
	seen := map[string]bool{}
	for _, action := range actions {
		alias, _ := action["alias"].(string)
		if alias == "" || seen[alias] {
			return fmt.Errorf("required-actions.json declares an action with an empty or repeated alias %q", alias)
		}
		seen[alias] = true
		for key := range action {
			if !requiredActionFields[key] {
				return fmt.Errorf("required action %s declares %s; only enabled and config are governed", alias, key)
			}
		}
		if config, present := action["config"]; present {
			values, ok := config.(map[string]any)
			if !ok {
				return fmt.Errorf("required action %s declares a config that is not an object", alias)
			}
			for key, value := range values {
				if _, isString := value.(string); !isString {
					return fmt.Errorf("required action %s declares config %s as %v; Keycloak keeps it as a "+
						"string, so anything else would read as drift", alias, key, value)
				}
			}
		}
	}
	return nil
}

// observeRequiredActions reads each declared action. One Keycloak does not register is absent.
func observeRequiredActions(ctx context.Context, c *admin.Client, base string,
	declared []map[string]any) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}
	for _, action := range declared {
		alias, _ := action["alias"].(string)
		var observed map[string]any
		err := c.GetJSON(ctx, base+"/authentication/required-actions/"+url.PathEscape(alias), &observed)
		switch {
		case admin.IsNotFound(err):
			continue
		case err != nil:
			return nil, fmt.Errorf("reading required action %s: %w", alias, err)
		}
		out[alias] = observed
	}
	return out, nil
}

// ErrRequiredActionAbsent is a declared required action the kernel does not register.
var ErrRequiredActionAbsent = errors.New("the kernel registers no such required action")

// applyRequiredAction lays the declared fields over the live action and writes it back whole, as
// Keycloak's update replaces every field it is sent.
func applyRequiredAction(ctx context.Context, c *admin.Client, base string, declared map[string]any,
	l *live) error {
	alias, _ := declared["alias"].(string)
	observed := l.requiredActions[alias]
	if observed == nil {
		return ErrRequiredActionAbsent
	}
	body := overlay(observed, normalise(declared).(map[string]any))
	_, err := c.Call(ctx, http.MethodPut, base+"/authentication/required-actions/"+url.PathEscape(alias), body,
		http.StatusNoContent)
	return err
}

func requiredActionNamed(d Definition, alias string) map[string]any {
	for _, action := range d.RequiredActions {
		if action["alias"] == alias {
			return action
		}
	}
	return nil
}
