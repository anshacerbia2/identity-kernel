// Package realmdef applies the declarative realm definition in realm/ to a live Keycloak, and
// detects the changes a live realm carries that the definition does not.
//
// TDD-identity-kernel-001 fixes the procedure: render the definition for the target environment,
// diff it against the live realm through the supported Admin API, fail when the live realm carries
// changes the definition does not, apply the difference, record the applied revision. The hard
// part is the third step, because "the live realm differs from the definition" has two causes that
// must be told apart: the definition changed (apply it), or someone changed the realm by hand
// (refuse). The only way to tell them apart is to know what was applied last. So the applied
// revision and a digest of its definition are recorded in the realm itself, and the caller
// supplies the definition at that revision: any difference between it and the live realm was made
// outside this tool.
//
// The reach of the drift check is exactly the reach of the definition. A key the definition does
// not declare is not compared, so a console change to it is not seen; widening what is declared
// widens what is guarded.
package realmdef

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Environment names where a definition is applied. Only environments that may hold an in-process
// generated signing key are accepted, because that is the only key this definition knows how to
// provide.
type Environment string

const (
	Local       Environment = "local"
	CI          Environment = "ci"
	Development Environment = "development"
)

// ParseEnvironment refuses every environment that would serve real tokens. TDD-identity-kernel-002
// prohibits per-process key generation there, including as a fallback, and the key custody it
// requires instead is not built; refusing here keeps the generated key from reaching one.
func ParseEnvironment(name string) (Environment, error) {
	switch environment := Environment(name); environment {
	case Local, CI, Development:
		return environment, nil
	case "":
		return "", errors.New("an environment is required: local, ci, or development")
	default:
		return "", fmt.Errorf("environment %q is refused: this definition signs with a key Keycloak "+
			"generates in-process, which TDD-identity-kernel-002 prohibits wherever real tokens are "+
			"served, and the key custody it requires instead is not built", name)
	}
}

// Files are the definition's sources under realm/, in the order they are applied.
var Files = []string{"scnehaux.json", "signing-key.generated.json", "client-scopes.json", "user-profile.json"}

// OptionalFiles are sources a definition may lack. A revision from before one was added is still a
// definition, so the drift check can judge the live realm against it.
var OptionalFiles = []string{"default-client-scopes.json", "authentication-flows.json", "required-actions.json"}

// Definition is the declared state of one realm.
type Definition struct {
	Realm   map[string]any   `json:"realm"`
	Key     map[string]any   `json:"key"`
	Scopes  []map[string]any `json:"scopes"`
	Profile []map[string]any `json:"profile"`
	// Defaults are the realm's default client scopes, the ones every new client is given. Nil when
	// the definition does not govern them, as before it declared them; omitted from the digest then,
	// so an earlier revision's digest is unchanged.
	Defaults *DefaultScopes `json:"defaults,omitempty"`
	// Flows are the authentication flows the definition declares, and the bindings they take. Nil
	// when it declares none, as before it governed them, and omitted from the digest then.
	Flows []Flow `json:"flows,omitempty"`
	// RequiredActions are the fields the definition governs on the kernel's required actions, by
	// alias. Nil when it declares none, and omitted from the digest then.
	RequiredActions []map[string]any `json:"requiredActions,omitempty"`
}

// DefaultScopes are the client scopes a new client holds as default and as optional scopes, by name.
// Both sets are the definition's: a scope it does not name is not a realm default.
type DefaultScopes struct {
	Default  []string `json:"default"`
	Optional []string `json:"optional"`
}

// Name is the realm's name.
func (d Definition) Name() string {
	name, _ := d.Realm["realm"].(string)
	return name
}

// Digest identifies the definition's content. Map keys marshal sorted, so equal definitions have
// equal digests.
func (d Definition) Digest() string {
	encoded, err := json.Marshal(d)
	if err != nil {
		panic("realmdef: a decoded definition failed to encode: " + err.Error())
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// Clone returns a deep copy, for a caller that derives a changed definition from this one.
func (d Definition) Clone() Definition {
	encoded, _ := json.Marshal(d)
	var out Definition
	_ = json.Unmarshal(encoded, &out)
	return out
}

// Load reads the definition from a directory.
func Load(dir string) (Definition, error) {
	files := map[string][]byte{}
	for _, name := range Files {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return Definition{}, fmt.Errorf("reading the realm definition: %w", err)
		}
		files[name] = content
	}
	for _, name := range OptionalFiles {
		content, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			return Definition{}, fmt.Errorf("reading the realm definition: %w", err)
		}
		files[name] = content
	}
	return Parse(files)
}

// Parse builds a definition from file contents by name, the way Load reads them from a directory
// and a caller reads them from an earlier revision.
func Parse(files map[string][]byte) (Definition, error) {
	var d Definition
	var profile struct {
		Attributes []map[string]any `json:"attributes"`
	}
	for name, into := range map[string]any{
		"scnehaux.json":              &d.Realm,
		"signing-key.generated.json": &d.Key,
		"client-scopes.json":         &d.Scopes,
		"user-profile.json":          &profile,
	} {
		content, ok := files[name]
		if !ok {
			return Definition{}, fmt.Errorf("the realm definition has no %s", name)
		}
		if err := json.Unmarshal(content, into); err != nil {
			return Definition{}, fmt.Errorf("parsing %s: %w", name, err)
		}
	}
	d.Profile = profile.Attributes
	if content, ok := files["default-client-scopes.json"]; ok {
		var defaults DefaultScopes
		if err := json.Unmarshal(content, &defaults); err != nil {
			return Definition{}, fmt.Errorf("parsing default-client-scopes.json: %w", err)
		}
		d.Defaults = &defaults
	}
	if content, ok := files["authentication-flows.json"]; ok {
		if err := json.Unmarshal(content, &d.Flows); err != nil {
			return Definition{}, fmt.Errorf("parsing authentication-flows.json: %w", err)
		}
	}
	if content, ok := files["required-actions.json"]; ok {
		if err := json.Unmarshal(content, &d.RequiredActions); err != nil {
			return Definition{}, fmt.Errorf("parsing required-actions.json: %w", err)
		}
	}
	return d, d.validate()
}

// maxScopeDescription is the length of Keycloak's CLIENT_SCOPE.DESCRIPTION column.
const maxScopeDescription = 255

func (d Definition) validate() error {
	if d.Name() == "" {
		return errors.New("scnehaux.json names no realm")
	}
	// Realm attributes are where Keycloak keeps some settings with no top-level key, admin-event
	// retention among them, so the definition may declare them. Not the two that hold the applied
	// revision: a definition that declared those could forge the baseline drift is judged by.
	if declared, present := d.Realm["attributes"]; present {
		attributes, ok := declared.(map[string]any)
		if !ok {
			return errors.New("scnehaux.json declares realm attributes that are not an object")
		}
		for key, value := range attributes {
			if key == AttrRevision || key == AttrDigest {
				return fmt.Errorf("scnehaux.json declares the realm attribute %s; it holds the applied "+
					"revision and is written only by the apply step", key)
			}
			if _, isString := value.(string); !isString {
				return fmt.Errorf("scnehaux.json declares the realm attribute %s as %v; Keycloak keeps "+
					"realm attributes as strings, so anything else would read as drift", key, value)
			}
		}
	}
	if err := d.validateRetention(); err != nil {
		return err
	}
	if name(d.Key) == "" || d.Key["providerId"] == nil {
		return errors.New("signing-key.generated.json needs a name and a providerId")
	}
	scopes := map[string]bool{}
	for _, scope := range d.Scopes {
		scopeName := name(scope)
		if scopeName == "" || scopes[scopeName] {
			return fmt.Errorf("client-scopes.json declares a scope with an empty or repeated name %q", scopeName)
		}
		scopes[scopeName] = true
		// Keycloak stores a client scope's description in a 255-character column, and a longer one
		// fails the create with an unexplained 500 (found applying scnehaux-privileged).
		if description, _ := scope["description"].(string); len([]rune(description)) > maxScopeDescription {
			return fmt.Errorf("client scope %s has a %d-character description; Keycloak stores at most %d",
				scopeName, len([]rune(description)), maxScopeDescription)
		}
		mappers := map[string]bool{}
		for _, mapper := range listOfMaps(scope["protocolMappers"]) {
			mapperName := name(mapper)
			if mapperName == "" || mappers[mapperName] {
				return fmt.Errorf("client scope %s declares a mapper with an empty or repeated name %q",
					scopeName, mapperName)
			}
			mappers[mapperName] = true
		}
	}
	if d.Defaults != nil {
		seen := map[string]bool{}
		for _, scopeName := range append(append([]string{}, d.Defaults.Default...), d.Defaults.Optional...) {
			if scopeName == "" || seen[scopeName] {
				return fmt.Errorf("default-client-scopes.json names an empty or repeated scope %q; a scope is "+
					"a default or an optional one, not both", scopeName)
			}
			seen[scopeName] = true
		}
	}
	if err := validateFlows(d.Flows); err != nil {
		return err
	}
	if err := validateRequiredActions(d.RequiredActions); err != nil {
		return err
	}
	attributes := map[string]bool{}
	for _, attribute := range d.Profile {
		attributeName := name(attribute)
		if attributeName == "" || attributes[attributeName] {
			return fmt.Errorf("user-profile.json declares an attribute with an empty or repeated name %q",
				attributeName)
		}
		attributes[attributeName] = true
	}
	return nil
}

func name(object map[string]any) string {
	value, _ := object["name"].(string)
	return value
}

// listOfMaps reads a decoded JSON array of objects, whichever way it was decoded.
func listOfMaps(value any) []map[string]any {
	switch list := value.(type) {
	case []map[string]any:
		return list
	case []any:
		out := make([]map[string]any, 0, len(list))
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// minEventRetention is TDD-identity-kernel-003 §Retention Constraint's floor: a one-hour reconcile
// interval times a safety factor of twenty-four. Events kept for less are gone from the only durable
// record before reconciliation has read them twice.
const minEventRetention = 24 * 60 * 60

// validateRetention refuses a definition that does not keep user and admin events, or keeps them for
// less than the floor (TDD-identity-kernel-003 §Retention Constraint): "A realm configured with
// retention below the floor fails the configuration diff."
func (d Definition) validateRetention() error {
	for _, key := range []string{"eventsEnabled", "adminEventsEnabled", "adminEventsDetailsEnabled"} {
		if enabled, _ := d.Realm[key].(bool); !enabled {
			return fmt.Errorf("scnehaux.json must set %s true: the native event store is the durable record "+
				"reconciliation reads (TDD-identity-kernel-003)", key)
		}
	}
	userRetention, _ := d.Realm["eventsExpiration"].(float64)
	if userRetention < minEventRetention {
		return fmt.Errorf("scnehaux.json keeps user events %v seconds; the floor is %d (TDD-identity-kernel-003 "+
			"§Retention Constraint)", d.Realm["eventsExpiration"], minEventRetention)
	}
	attributes, _ := d.Realm["attributes"].(map[string]any)
	raw, _ := attributes["adminEventsExpiration"].(string)
	adminRetention, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || adminRetention < minEventRetention {
		return fmt.Errorf("scnehaux.json keeps admin events %q seconds; the floor is %d (TDD-identity-kernel-003 "+
			"§Retention Constraint)", raw, minEventRetention)
	}
	return nil
}
