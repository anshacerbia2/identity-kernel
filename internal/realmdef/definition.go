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

// Definition is the declared state of one realm.
type Definition struct {
	Realm   map[string]any   `json:"realm"`
	Key     map[string]any   `json:"key"`
	Scopes  []map[string]any `json:"scopes"`
	Profile []map[string]any `json:"profile"`
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
	return d, d.validate()
}

func (d Definition) validate() error {
	if d.Name() == "" {
		return errors.New("scnehaux.json names no realm")
	}
	if _, present := d.Realm["attributes"]; present {
		return errors.New("scnehaux.json declares realm attributes; they hold the applied revision and " +
			"are written only by the apply step")
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
