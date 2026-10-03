package realmdef

// The comparison, without a Keycloak. What is asserted against a live one is in compat/.

import (
	"encoding/json"
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
	if c.Defaults != nil {
		l.defaults = DefaultScopes{Default: sortedCopy(c.Defaults.Default), Optional: sortedCopy(c.Defaults.Optional)}
	}
	l.flows = map[string][]Execution{}
	for _, f := range c.Flows {
		l.flows[f.Alias] = withLiveConfig(f.Executions)
		if f.Binding != "" {
			l.realm[f.Binding] = f.Alias
		}
	}
	return l
}

// withLiveConfig adds a configuration key Keycloak keeps that the declaration does not name.
func withLiveConfig(executions []Execution) []Execution {
	out := make([]Execution, len(executions))
	for i, e := range executions {
		if e.ConfigAlias != "" {
			config := map[string]string{"unmanaged": "x"}
			for k, v := range e.Config {
				config[k] = v
			}
			e.Config = config
		}
		e.Executions = withLiveConfig(e.Executions)
		out[i] = e
	}
	return out
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
	// Each flow is built, and each binding then set to the flow it names.
	bindings := 0
	for _, f := range d.Flows {
		if f.Binding != "" {
			bindings++
		}
	}
	if want := 3 + len(d.Scopes) + len(d.Profile) + len(d.Flows) + bindings; len(changes) != want {
		t.Fatalf("%d changes for an absent realm, want %d", len(changes), want)
	}
	for _, change := range changes {
		if change.Kind == KindBinding {
			if change.Action != Update {
				t.Errorf("binding %s: %s, want update", change.Name, change.Action)
			}
			continue
		}
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
	for _, attribute := range []string{AttrRevision, AttrDigest} {
		files["scnehaux.json"] = []byte(`{"realm":"scnehaux","attributes":{"` + attribute + `":"x"}}`)
		if _, err := Parse(files); err == nil {
			t.Errorf("a definition declaring %s parsed; it could forge the applied revision", attribute)
		}
	}
}

// Admin-event retention has no top-level key; Keycloak keeps it as a realm attribute.
func TestParseAcceptsAnyOtherRealmAttributeAsAString(t *testing.T) {
	files := files(t)
	files["scnehaux.json"] = []byte(`{"realm":"scnehaux","attributes":{"adminEventsExpiration":"604800"}}`)
	if _, err := Parse(files); err != nil {
		t.Errorf("a definition declaring admin-event retention was refused: %v", err)
	}
	files["scnehaux.json"] = []byte(`{"realm":"scnehaux","attributes":{"adminEventsExpiration":604800}}`)
	if _, err := Parse(files); err == nil {
		t.Error("a realm attribute declared as a number parsed; Keycloak returns it as a string, so it would read as drift")
	}
}

// A console change to a declared realm attribute is a difference like any other; an attribute the
// definition does not declare, the recorded revision among them, is not compared.
func TestADeclaredRealmAttributeIsCompared(t *testing.T) {
	d := definition(t)
	l := liveFrom(d)
	attributes := l.realm["attributes"].(map[string]any)
	attributes[AttrRevision] = "abc123"
	if change := find(t, compare(d, l), KindRealm, d.Name()); change.Action != InSync {
		t.Fatalf("an undeclared realm attribute reads as %s %v", change.Action, change.Diffs)
	}
	attributes["adminEventsExpiration"] = "60"
	change := find(t, compare(d, l), KindRealm, d.Name())
	if change.Action != Update || !strings.Contains(strings.Join(change.Diffs, " "), "attributes.adminEventsExpiration") {
		t.Errorf("a shortened admin-event retention reads as %s %v, want an update naming it", change.Action, change.Diffs)
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

// The realm's default client scopes are a closed set: a built-in scope Keycloak makes a default, and
// the definition does not name, is a difference.
func TestARealmDefaultScopeTheDefinitionDoesNotNameIsADifference(t *testing.T) {
	d := definition(t)
	if d.Defaults == nil {
		t.Fatal("realm/ declares no default client scopes")
	}
	l := liveFrom(d)
	l.defaults.Default = sortedCopy(append(l.defaults.Default, "profile", "email"))
	l.defaults.Optional = []string{"offline_access"}
	change := find(t, compare(d, l), KindDefaults, d.Name())
	if change.Action != Update || len(change.Diffs) != 2 {
		t.Fatalf("change = %+v, want an update naming both sets", change)
	}
	for _, want := range []string{"default: live [acr basic email profile], definition [acr basic]",
		"optional: live [offline_access], definition []"} {
		if !containsDiff(change.Diffs, want) {
			t.Errorf("diffs %v do not name %q", change.Diffs, want)
		}
	}
}

// A revision from before the file existed is still a definition: it governs no default scopes, so the
// drift check judges nothing about them, and its digest is what it always was.
func TestADefinitionWithoutDefaultScopesGovernsNone(t *testing.T) {
	d := definition(t)
	files := map[string][]byte{}
	for _, name := range Files {
		content, err := os.ReadFile(filepath.Join("..", "..", "realm", name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = content
	}
	earlier, err := Parse(files)
	if err != nil {
		t.Fatal(err)
	}
	if earlier.Defaults != nil {
		t.Fatal("a definition without default-client-scopes.json governs default scopes")
	}
	for _, change := range compare(earlier, liveFrom(d)) {
		if change.Kind == KindDefaults {
			t.Errorf("a definition without default scopes compared them: %+v", change)
		}
	}
	if strings.Contains(string(mustJSON(t, earlier)), "defaults") {
		t.Error("a definition without default scopes carries them in its digest input")
	}
}

func TestParseRefusesAScopeThatIsBothDefaultAndOptional(t *testing.T) {
	files := map[string][]byte{}
	for _, name := range Files {
		content, err := os.ReadFile(filepath.Join("..", "..", "realm", name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = content
	}
	files["default-client-scopes.json"] = []byte(`{"default":["basic"],"optional":["basic"]}`)
	if _, err := Parse(files); err == nil {
		t.Error("a scope both default and optional was accepted")
	}
}

func containsDiff(diffs []string, want string) bool {
	for _, d := range diffs {
		if d == want {
			return true
		}
	}
	return false
}

func mustJSON(t *testing.T, d Definition) []byte {
	t.Helper()
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestAnAbsentFlowIsBuiltAndThenBound(t *testing.T) {
	d := definition(t)
	l := liveFrom(d)
	delete(l.flows, "scnehaux-browser-v2")
	l.realm["browserFlow"] = "scnehaux-browser-v1"
	changes := compare(d, l)
	if c := find(t, changes, KindFlow, "scnehaux-browser-v2"); c.Action != Create {
		t.Errorf("flow: %s", c.Action)
	}
	if c := find(t, changes, KindBinding, "browserFlow"); c.Action != Update {
		t.Errorf("binding: %s", c.Action)
	}
	flowAt, bindingAt := -1, -1
	for i, c := range changes {
		switch c.Kind {
		case KindFlow:
			flowAt = i
		case KindBinding:
			bindingAt = i
		}
	}
	if bindingAt < flowAt {
		t.Error("the binding is applied before the flow it names exists")
	}
}

// A requirement changed by hand in the bound flow is a difference naming the step.
func TestAHandEditedFlowIsADifference(t *testing.T) {
	d := definition(t)
	l := liveFrom(d)
	forms := l.flows["scnehaux-browser-v2"][1]
	level2 := forms.Executions[1]
	level2.Executions[1].Executions[1].Executions[0].Requirement = "DISABLED"
	c := find(t, compare(d, l), KindFlow, "scnehaux-browser-v2")
	if c.Action != Update || !has(c.Diffs, "auth-otp-form: requirement live DISABLED, definition REQUIRED") {
		t.Errorf("%s %v", c.Action, c.Diffs)
	}
	l = liveFrom(d)
	l.flows["scnehaux-browser-v2"][1].Executions[1].Executions[0].Config["loa-max-age"] = "0"
	c = find(t, compare(d, l), KindFlow, "scnehaux-browser-v2")
	if c.Action != Update || !has(c.Diffs, "loa-max-age live \"0\", definition \"300\"") {
		t.Errorf("%s %v", c.Action, c.Diffs)
	}
}

func TestParseRefusesAMalformedFlow(t *testing.T) {
	for name, flows := range map[string]string{
		"a repeated alias":     `[{"alias":"a","executions":[]},{"alias":"a","executions":[]}]`,
		"two bindings":         `[{"alias":"a","binding":"browserFlow","executions":[]},{"alias":"b","binding":"browserFlow","executions":[]}]`,
		"an unknown binding":   `[{"alias":"a","binding":"directGrantFlow","executions":[]}]`,
		"a step of both kinds": `[{"alias":"a","executions":[{"authenticator":"x","flow":"y","requirement":"REQUIRED"}]}]`,
		"a bad requirement":    `[{"alias":"a","executions":[{"authenticator":"x","requirement":"SOMETIMES"}]}]`,
		"config without alias": `[{"alias":"a","executions":[{"authenticator":"x","requirement":"REQUIRED","config":{"k":"v"}}]}]`,
	} {
		f := files(t)
		f["authentication-flows.json"] = []byte(flows)
		if _, err := Parse(f); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A definition from before flows were declared keeps its digest.
func TestADefinitionWithoutFlowsKeepsItsDigest(t *testing.T) {
	d := definition(t)
	without := d.Clone()
	without.Flows = nil
	encoded, _ := json.Marshal(without)
	if strings.Contains(string(encoded), "flows") {
		t.Error("an absent flow list is part of the digest")
	}
}
