package compat

// The apply step's own contract, from TDD-identity-kernel-001 §Configuration Integrity: applying the
// definition twice changes nothing on the second run, and a realm changed outside the definition is
// detected before the next apply and refused. Plus the property those two rest on: a change to the
// definition itself is applied, not mistaken for drift.
//
// Each test leaves the realm as it found it -- in sync with the definition at the recorded
// revision -- because every other test in the suite asserts against the same realm.

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-kernel/internal/realmdef"
)

func TestApplyingTwiceChangesNothing(t *testing.T) {
	a := requireKeycloak(t)
	definition := loadDefinition(t)

	plan := newPlan(t, a, definition, &definition)
	if len(plan.Drift) > 0 {
		t.Fatalf("a realm just applied reports drift against its own definition:\n  %s",
			strings.Join(plan.Drift, "\n  "))
	}
	for _, change := range plan.Changes {
		if change.Action != realmdef.InSync {
			t.Errorf("%s %s: %s after an apply %v -- the second run would change it again",
				change.Kind, change.Name, change.Action, change.Diffs)
		}
	}
}

func TestTheAppliedRevisionIsRecorded(t *testing.T) {
	a := requireKeycloak(t)
	definition := loadDefinition(t)
	record := recorded(t, a)
	if record.Revision == "" {
		t.Error("the realm carries no applied revision: the next run could not judge drift")
	}
	if record.Digest != definition.Digest() {
		t.Errorf("the recorded digest %s is not the definition's %s", record.Digest, definition.Digest())
	}
}

// The drift that matters most: an enterprise claim mapper added by hand to the external scope,
// which is how principal_id would reach a relying party it is kept from.
func TestConsoleDriftIsRefused(t *testing.T) {
	a := requireKeycloak(t)
	definition := loadDefinition(t)
	external := scopeIDByName(t, a, "scnehaux-external")
	mapperName := "compat-drift-" + suffix()

	if _, err := a.call(http.MethodPost,
		"/admin/realms/"+realmName+"/client-scopes/"+external+"/protocol-mappers/models", map[string]any{
			"name":           mapperName,
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-usermodel-attribute-mapper",
			"config": map[string]string{
				"user.attribute": "scnehaux_principal_id", "claim.name": "principal_id",
				"jsonType.label": "String", "access.token.claim": "true",
			},
		}, http.StatusCreated); err != nil {
		t.Fatalf("adding a mapper by hand: %v", err)
	}

	plan := newPlan(t, a, definition, &definition)
	if !containsLine(plan.Drift, mapperName) {
		t.Fatalf("a mapper added by hand to scnehaux-external is not reported as drift; drift: %v", plan.Drift)
	}

	err := realmdef.Apply(context.Background(), a.client, plan, options(t, a))
	if !errors.Is(err, realmdef.ErrDrift) {
		t.Fatalf("apply over drift answered %v, want ErrDrift", err)
	}
	if !scopeHasMapper(t, a, "scnehaux-external", mapperName) {
		t.Fatal("apply refused the drift and still removed the mapper: a refusal must change nothing")
	}

	// Adopting converges the realm to the definition, which removes the undeclared mapper.
	adopting := options(t, a)
	adopting.Adopt = true
	if err := realmdef.Apply(context.Background(), a.client, newPlan(t, a, definition, nil), adopting); err != nil {
		t.Fatalf("adopting and converging: %v", err)
	}
	if scopeHasMapper(t, a, "scnehaux-external", mapperName) {
		t.Error("converging to the definition left an undeclared mapper on scnehaux-external")
	}
}

// A change to the definition is an update, not drift -- the distinction the recorded revision
// exists to make. Applied forward and back, so the realm ends where it started.
func TestADefinitionChangeIsAnUpdateNotDrift(t *testing.T) {
	a := requireKeycloak(t)
	definition := loadDefinition(t)
	changed := definition.Clone()
	for _, scope := range changed.Scopes {
		if scope["name"] == "scnehaux-external" {
			scope["description"] = "changed by compat " + suffix()
		}
	}

	for _, step := range []struct {
		name           string
		target, before realmdef.Definition
	}{
		{"forward", changed, definition},
		{"back", definition, changed},
	} {
		plan := newPlan(t, a, step.target, &step.before)
		if len(plan.Drift) > 0 {
			t.Fatalf("%s: a definition change reads as drift:\n  %s", step.name, strings.Join(plan.Drift, "\n  "))
		}
		updated := false
		for _, change := range plan.Changes {
			if change.Kind == realmdef.KindScope && change.Name == "scnehaux-external" && change.Action == realmdef.Update {
				updated = true
			}
		}
		if !updated {
			t.Fatalf("%s: the changed scope description is not planned as an update: %+v", step.name, plan.Changes)
		}
		if err := realmdef.Apply(context.Background(), a.client, plan, options(t, a)); err != nil {
			t.Fatalf("%s: applying a definition change: %v", step.name, err)
		}
	}
}

func loadDefinition(t *testing.T) realmdef.Definition {
	t.Helper()
	definition, err := realmdef.Load(filepath.Join("..", "realm"))
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func newPlan(t *testing.T, a *admin, definition realmdef.Definition, previous *realmdef.Definition) realmdef.Plan {
	t.Helper()
	plan, err := realmdef.NewPlan(context.Background(), a.client, definition, previous)
	if err != nil {
		t.Fatalf("planning: %v", err)
	}
	return plan
}

func recorded(t *testing.T, a *admin) realmdef.Record {
	t.Helper()
	record, err := realmdef.ReadRecord(context.Background(), a.client, realmName)
	if err != nil {
		t.Fatalf("reading the applied record: %v", err)
	}
	return record
}

// options re-records the revision already recorded, so a test's apply does not rewrite which commit
// the realm says it came from.
func options(t *testing.T, a *admin) realmdef.Options {
	return realmdef.Options{Environment: realmdef.CI, Revision: recorded(t, a).Revision}
}

func scopeHasMapper(t *testing.T, a *admin, scopeName, mapperName string) bool {
	t.Helper()
	var mappers []struct {
		Name string `json:"name"`
	}
	if err := a.getJSON("/admin/realms/"+realmName+"/client-scopes/"+scopeIDByName(t, a, scopeName)+
		"/protocol-mappers/models", &mappers); err != nil {
		t.Fatalf("listing the mappers of %s: %v", scopeName, err)
	}
	for _, mapper := range mappers {
		if mapper.Name == mapperName {
			return true
		}
	}
	return false
}

func containsLine(lines []string, fragment string) bool {
	for _, line := range lines {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}
