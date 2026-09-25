package realmdef

// The comparison, without a Keycloak. What is asserted against a live one is in compat/.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func definition(t *testing.T) Definition {
	t.Helper()
	d, err := Load(filepath.Join("..", "..", "realm"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// liveFrom builds a live realm that holds exactly the definition, plus the extra fields a real
// Keycloak adds to every representation.
func liveFrom(d Definition) *live {
	c := d.Clone()
	l := &live{keys: map[string]map[string]any{}, scopes: map[string]map[string]any{}}
	l.realm = overlay(map[string]any{"id": "realm-id", "accessTokenLifespan": 300.0}, c.Realm)
	key := overlay(map[string]any{"id": "key-id", "parentId": "realm-id"}, c.Key)
	key["config"].(map[string]any)["certificate"] = []any{"MIIC..."}
	l.keys[name(key)] = key
	for _, scope := range c.Scopes {
		live := overlay(map[string]any{"id": "scope-" + name(scope)}, scope)
		for _, mapper := range listOfMaps(live["protocolMappers"]) {
			mapper["id"] = "mapper-" + name(mapper)
			mapper["consentRequired"] = false
		}
		l.scopes[name(scope)] = live
	}
	attributes := []any{map[string]any{"name": "username"}, map[string]any{"name": "email"}}
	for _, attribute := range c.Profile {
		attributes = append(attributes, overlay(map[string]any{"annotations": map[string]any{}}, attribute))
	}
	l.profile = map[string]any{"attributes": attributes}
	return l
}

func TestAMatchingRealmIsInSync(t *testing.T) {
	d := definition(t)
	for _, change := range compare(d, liveFrom(d)) {
		if change.Action != InSync {
			t.Errorf("%s %s: %s %v -- fields Keycloak adds must not read as a difference",
				change.Kind, change.Name, change.Action, change.Diffs)
		}
	}
}

func TestAnAbsentRealmCreatesEverything(t *testing.T) {
	d := definition(t)
	changes := compare(d, &live{})
	if want := 2 + len(d.Scopes) + len(d.Profile); len(changes) != want {
		t.Fatalf("%d changes for an absent realm, want %d", len(changes), want)
	}
	for _, change := range changes {
		if change.Action != Create {
			t.Errorf("%s %s: %s, want create", change.Kind, change.Name, change.Action)
		}
	}
}

func TestAChangedMapperFlagIsAnUpdateNamingThePath(t *testing.T) {
	d := definition(t)
	l := liveFrom(d)
	for _, mapper := range listOfMaps(l.scopes["scnehaux-internal"]["protocolMappers"]) {
		if name(mapper) == "principal_id" {
			mapper["config"].(map[string]any)["id.token.claim"] = "false"
		}
	}
	change := find(t, compare(d, l), KindScope, "scnehaux-internal")
	if change.Action != Update {
		t.Fatalf("action %s, want update", change.Action)
	}
	if !has(change.Diffs, "protocolMappers.principal_id.config.id.token.claim") {
		t.Errorf("the diff does not name the changed flag: %v", change.Diffs)
	}
}

// The mapper set is closed. A mapper added by hand is exactly how principal_id would reach an
// audience it is kept from, so an undeclared one must be a difference.
func TestAnUndeclaredMapperIsADifference(t *testing.T) {
	d := definition(t)
	l := liveFrom(d)
	scope := l.scopes["scnehaux-external"]
	scope["protocolMappers"] = append(listOfMaps(scope["protocolMappers"]), map[string]any{
		"id": "added", "name": "principal_id", "protocolMapper": "oidc-usermodel-attribute-mapper",
	})
	change := find(t, compare(d, l), KindScope, "scnehaux-external")
	if change.Action != Update || !has(change.Diffs, "protocolMappers.principal_id: present live") {
		t.Errorf("an undeclared mapper on scnehaux-external is not a difference: %s %v", change.Action, change.Diffs)
	}
}

// A declared null is a governed absence. The definition makes firstName optional by declaring
// required: null, and Keycloak's default still carrying required must read as a difference --
// otherwise the plan would call the realm in sync and never apply the change.
func TestADeclaredNullIsComparedLikeAnyValue(t *testing.T) {
	d := definition(t)
	l := liveFrom(d)
	for _, attribute := range listOfMaps(l.profile["attributes"]) {
		if name(attribute) == "firstName" {
			attribute["required"] = map[string]any{"roles": []any{"user"}}
			attribute["validations"] = map[string]any{"length": map[string]any{"max": 255.0}}
		}
	}
	change := find(t, compare(d, l), KindAttribute, "firstName")
	if change.Action != Update || !has(change.Diffs, "required") {
		t.Fatalf("a required firstName against a definition declaring it optional: %s %v", change.Action, change.Diffs)
	}
	for _, diff := range change.Diffs {
		if strings.Contains(diff, "validations") {
			t.Errorf("a field the definition does not declare was compared: %s", diff)
		}
	}
}

func TestAMissingProfileAttributeIsACreate(t *testing.T) {
	d := definition(t)
	l := liveFrom(d)
	l.profile = map[string]any{"attributes": []any{map[string]any{"name": "username"}}}
	if change := find(t, compare(d, l), KindAttribute, "scnehaux_principal_id"); change.Action != Create {
		t.Errorf("action %s, want create", change.Action)
	}
}

func TestTheDigestFollowsTheContent(t *testing.T) {
	d := definition(t)
	if d.Digest() != d.Clone().Digest() {
		t.Fatal("a definition and its clone have different digests")
	}
	changed := d.Clone()
	changed.Realm["sslRequired"] = "none"
	if d.Digest() == changed.Digest() {
		t.Error("changing a declared value left the digest unchanged: drift judged against it would be blind")
	}
}

func TestParseRefusesWhatOnlyTheApplyStepMayWrite(t *testing.T) {
	files := files(t)
	files["scnehaux.json"] = []byte(`{"realm":"scnehaux","attributes":{"scnehaux.definition.revision":"x"}}`)
	if _, err := Parse(files); err == nil {
		t.Error("a definition declaring realm attributes parsed; it could forge the applied revision")
	}
}

func TestParseRefusesARepeatedMapperName(t *testing.T) {
	files := files(t)
	files["client-scopes.json"] = []byte(`[{"name":"s","protocolMappers":[{"name":"m"},{"name":"m"}]}]`)
	if _, err := Parse(files); err == nil {
		t.Error("two mappers sharing a name parsed; the comparison keys mappers by name and would see one")
	}
}

func TestOnlyEnvironmentsWithoutRealTokensAreAccepted(t *testing.T) {
	for _, accepted := range []string{"local", "ci", "development"} {
		if _, err := ParseEnvironment(accepted); err != nil {
			t.Errorf("%s refused: %v", accepted, err)
		}
	}
	for _, refused := range []string{"", "staging", "production", "prod"} {
		if _, err := ParseEnvironment(refused); err == nil {
			t.Errorf("%q accepted: the generated signing key would reach an environment serving real tokens", refused)
		}
	}
}

func files(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, name := range Files {
		content, err := os.ReadFile(filepath.Join("..", "..", "realm", name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = content
	}
	return out
}

func find(t *testing.T, changes []Change, kind, objectName string) Change {
	t.Helper()
	for _, change := range changes {
		if change.Kind == kind && change.Name == objectName {
			return change
		}
	}
	t.Fatalf("no change for %s %s", kind, objectName)
	return Change{}
}

func has(lines []string, fragment string) bool {
	for _, line := range lines {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}
