package realmdef

// Authentication flows (TDD-identity-kernel-001 §Authentication Levels). A flow is declared by
// alias and never edited in place: a change declares a new alias, which the apply builds whole and
// then binds in one realm update, so no sign-in runs through a half-built flow. The previous flow
// stays, unbound, because the apply deletes nothing. A bound flow that differs from its declaration
// was edited by hand, and the drift check reports it like any other difference.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
)

// Flow is one declared top-level authentication flow.
type Flow struct {
	Alias       string `json:"alias"`
	Description string `json:"description,omitempty"`
	// Binding names the realm binding this flow is bound to: browserFlow, or empty for none.
	Binding    string      `json:"binding,omitempty"`
	Executions []Execution `json:"executions"`
}

// Execution is one step of a flow: an authenticator, or a sub-flow with its own executions.
type Execution struct {
	Authenticator string            `json:"authenticator,omitempty"`
	Flow          string            `json:"flow,omitempty"`
	Requirement   string            `json:"requirement"`
	ConfigAlias   string            `json:"configAlias,omitempty"`
	Config        map[string]string `json:"config,omitempty"`
	Executions    []Execution       `json:"executions,omitempty"`
}

const (
	KindFlow    = "authentication flow"
	KindBinding = "flow binding"
)

// The bindings a flow may take, by the realm field that holds the bound alias.
var flowBindings = map[string]bool{"browserFlow": true}

var requirements = map[string]bool{"REQUIRED": true, "ALTERNATIVE": true, "CONDITIONAL": true, "DISABLED": true}

func validateFlows(flows []Flow) error {
	aliases := map[string]bool{}
	bound := map[string]string{}
	configs := map[string]bool{}
	claim := func(alias string) error {
		if alias == "" || aliases[alias] {
			return fmt.Errorf("authentication-flows.json declares an empty or repeated flow alias %q", alias)
		}
		aliases[alias] = true
		return nil
	}
	var walk func(owner string, executions []Execution) error
	walk = func(owner string, executions []Execution) error {
		for _, e := range executions {
			switch {
			case (e.Authenticator == "") == (e.Flow == ""):
				return fmt.Errorf("flow %s declares a step that is not exactly one of an authenticator or a sub-flow", owner)
			case !requirements[e.Requirement]:
				return fmt.Errorf("flow %s declares the requirement %q", owner, e.Requirement)
			case (e.ConfigAlias == "") != (len(e.Config) == 0):
				return fmt.Errorf("flow %s declares a configuration without its alias, or an alias without one", owner)
			case e.Flow != "" && (e.ConfigAlias != "" || len(e.Config) > 0):
				return fmt.Errorf("flow %s configures its sub-flow %s; only an authenticator takes a configuration", owner, e.Flow)
			}
			if e.ConfigAlias != "" {
				if configs[e.ConfigAlias] {
					return fmt.Errorf("flow %s repeats the configuration alias %s", owner, e.ConfigAlias)
				}
				configs[e.ConfigAlias] = true
			}
			if e.Flow != "" {
				if err := claim(e.Flow); err != nil {
					return err
				}
				if err := walk(e.Flow, e.Executions); err != nil {
					return err
				}
			} else if len(e.Executions) > 0 {
				return fmt.Errorf("flow %s gives the authenticator %s executions of its own", owner, e.Authenticator)
			}
		}
		return nil
	}
	for _, f := range flows {
		if err := claim(f.Alias); err != nil {
			return err
		}
		if f.Binding != "" {
			if !flowBindings[f.Binding] {
				return fmt.Errorf("flow %s names the binding %q; only %v are managed", f.Alias, f.Binding, sortedKeys(flowBindings))
			}
			if other, taken := bound[f.Binding]; taken {
				return fmt.Errorf("flows %s and %s both take the binding %s", other, f.Alias, f.Binding)
			}
			bound[f.Binding] = f.Alias
		}
		if err := walk(f.Alias, f.Executions); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------------------------

// flowAliases are the top-level flows a definition, or the previous one, declares: the only ones
// observed, because a flow nobody declared is the realm's own.
func flowAliases(definitions ...*Definition) []string {
	seen := map[string]bool{}
	for _, d := range definitions {
		if d == nil {
			continue
		}
		for _, f := range d.Flows {
			seen[f.Alias] = true
		}
	}
	return sortedKeys(seen)
}

// executionRepresentation is one entry of GET .../flows/{alias}/executions, which lists a flow's
// steps depth-first, each with its depth.
type executionRepresentation struct {
	ID                   string `json:"id"`
	Requirement          string `json:"requirement"`
	DisplayName          string `json:"displayName"`
	ProviderID           string `json:"providerId"`
	AuthenticationFlow   bool   `json:"authenticationFlow"`
	AuthenticationConfig string `json:"authenticationConfig"`
	Level                int    `json:"level"`
	Index                int    `json:"index"`
}

// observeFlows reads each named top-level flow as a tree of executions, configurations included. A
// flow that does not exist is absent from the map.
func observeFlows(ctx context.Context, c *admin.Client, base string, aliases []string) (map[string][]Execution, error) {
	out := map[string][]Execution{}
	if len(aliases) == 0 {
		return out, nil
	}
	var top []struct {
		Alias string `json:"alias"`
	}
	if err := c.GetJSON(ctx, base+"/authentication/flows", &top); err != nil {
		return nil, fmt.Errorf("reading the authentication flows: %w", err)
	}
	exists := map[string]bool{}
	for _, f := range top {
		exists[f.Alias] = true
	}
	for _, alias := range aliases {
		if !exists[alias] {
			continue
		}
		var listed []executionRepresentation
		if err := c.GetJSON(ctx, base+"/authentication/flows/"+url.PathEscape(alias)+"/executions", &listed); err != nil {
			return nil, fmt.Errorf("reading flow %s: %w", alias, err)
		}
		tree, err := treeOf(ctx, c, base, listed)
		if err != nil {
			return nil, fmt.Errorf("reading flow %s: %w", alias, err)
		}
		out[alias] = tree
	}
	return out, nil
}

// treeOf rebuilds the nesting a depth-first listing flattens.
func treeOf(ctx context.Context, c *admin.Client, base string, listed []executionRepresentation) ([]Execution, error) {
	var build func(i, level int) ([]Execution, int, error)
	build = func(i, level int) ([]Execution, int, error) {
		var out []Execution
		for i < len(listed) && listed[i].Level >= level {
			r := listed[i]
			e := Execution{Requirement: r.Requirement}
			if r.AuthenticationFlow {
				e.Flow = r.DisplayName
			} else {
				e.Authenticator = r.ProviderID
			}
			if r.AuthenticationConfig != "" {
				var config struct {
					Alias  string            `json:"alias"`
					Config map[string]string `json:"config"`
				}
				if err := c.GetJSON(ctx, base+"/authentication/config/"+url.PathEscape(r.AuthenticationConfig), &config); err != nil {
					return nil, i, fmt.Errorf("reading configuration %s: %w", r.AuthenticationConfig, err)
				}
				e.ConfigAlias, e.Config = config.Alias, config.Config
			}
			i++
			if r.AuthenticationFlow {
				children, next, err := build(i, level+1)
				if err != nil {
					return nil, next, err
				}
				e.Executions, i = children, next
			}
			out = append(out, e)
		}
		return out, i, nil
	}
	tree, _, err := build(0, 0)
	return tree, err
}

// ---------------------------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------------------------

// compareFlows compares each declared flow with the live one, and each binding with the realm's.
func compareFlows(d Definition, l *live) []Change {
	var changes []Change
	for _, f := range d.Flows {
		observed, exists := l.flows[f.Alias]
		switch {
		case !exists:
			changes = append(changes, Change{Kind: KindFlow, Name: f.Alias, Action: Create})
		default:
			if diffs := diffExecutions(f.Alias, f.Executions, observed); len(diffs) > 0 {
				changes = append(changes, Change{Kind: KindFlow, Name: f.Alias, Action: Update, Diffs: diffs})
			} else {
				changes = append(changes, Change{Kind: KindFlow, Name: f.Alias, Action: InSync})
			}
		}
	}
	for _, f := range d.Flows {
		if f.Binding == "" {
			continue
		}
		var current string
		if l.realm != nil {
			current, _ = l.realm[f.Binding].(string)
		}
		if current == f.Alias {
			changes = append(changes, Change{Kind: KindBinding, Name: f.Binding, Action: InSync})
		} else {
			changes = append(changes, Change{Kind: KindBinding, Name: f.Binding, Action: Update,
				Diffs: []string{fmt.Sprintf("%s: live %q, definition %q", f.Binding, current, f.Alias)}})
		}
	}
	return changes
}

// diffExecutions compares two trees step by step, in order: a step's kind, provider or alias,
// requirement and declared configuration values. A live configuration key the declaration does not
// name is Keycloak's default and is not compared.
func diffExecutions(path string, declared, observed []Execution) []string {
	var out []string
	if len(declared) != len(observed) {
		out = append(out, fmt.Sprintf("%s: live has %d steps, definition %d", path, len(observed), len(declared)))
	}
	for i := 0; i < len(declared) && i < len(observed); i++ {
		want, got := declared[i], observed[i]
		at := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case want.Authenticator != got.Authenticator || want.Flow != got.Flow:
			out = append(out, fmt.Sprintf("%s: live %s, definition %s", at, stepName(got), stepName(want)))
			continue
		case want.Requirement != got.Requirement:
			out = append(out, fmt.Sprintf("%s %s: requirement live %s, definition %s", at, stepName(want), got.Requirement, want.Requirement))
		}
		if want.ConfigAlias != "" {
			if got.ConfigAlias != want.ConfigAlias {
				out = append(out, fmt.Sprintf("%s %s: configuration live %q, definition %q", at, stepName(want), got.ConfigAlias, want.ConfigAlias))
			}
			keys := make([]string, 0, len(want.Config))
			for key := range want.Config {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if got.Config[key] != want.Config[key] {
					out = append(out, fmt.Sprintf("%s %s: %s live %q, definition %q", at, stepName(want), key, got.Config[key], want.Config[key]))
				}
			}
		}
		if want.Flow != "" {
			out = append(out, diffExecutions(want.Flow, want.Executions, got.Executions)...)
		}
	}
	return out
}

func stepName(e Execution) string {
	if e.Flow != "" {
		return "sub-flow " + e.Flow
	}
	return e.Authenticator
}

// ---------------------------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------------------------

// ErrFlowChanged refuses an edit of a flow that exists: a changed flow is a new alias.
var ErrFlowChanged = errors.New("a declared flow differs from the live flow of the same alias; flows are " +
	"never edited in place, so declare the change as a new alias")

func flowNamed(d Definition, alias string) (Flow, bool) {
	for _, f := range d.Flows {
		if f.Alias == alias {
			return f, true
		}
	}
	return Flow{}, false
}

// rebuildUnbound replaces a declared flow that is bound to nothing and differs from its declaration.
// That is a build that stopped part way: no sign-in runs through an unbound flow, so it is deleted
// and built again whole. A bound flow is never replaced; ErrFlowChanged refuses that.
func rebuildUnbound(ctx context.Context, c *admin.Client, base string, l *live, f Flow) error {
	if l.realm != nil {
		for binding := range flowBindings {
			if current, _ := l.realm[binding].(string); current == f.Alias {
				return ErrFlowChanged
			}
		}
	}
	var top []struct {
		ID    string `json:"id"`
		Alias string `json:"alias"`
	}
	if err := c.GetJSON(ctx, base+"/authentication/flows", &top); err != nil {
		return err
	}
	for _, flow := range top {
		if flow.Alias == f.Alias {
			if _, err := c.Call(ctx, http.MethodDelete, base+"/authentication/flows/"+url.PathEscape(flow.ID), nil,
				http.StatusNoContent); err != nil {
				return fmt.Errorf("deleting the partly built flow %s: %w", f.Alias, err)
			}
		}
	}
	return buildFlow(ctx, c, base, f)
}

// buildFlow creates a declared top-level flow and every step beneath it.
func buildFlow(ctx context.Context, c *admin.Client, base string, f Flow) error {
	if _, err := c.Call(ctx, http.MethodPost, base+"/authentication/flows", map[string]any{
		"alias": f.Alias, "description": f.Description, "providerId": "basic-flow", "topLevel": true, "builtIn": false,
	}, http.StatusCreated); err != nil {
		return err
	}
	return addExecutions(ctx, c, base, f.Alias, f.Executions)
}

// addExecutions appends each step to the flow named parent, sets its requirement, configures it,
// and descends into a sub-flow. Keycloak adds a step disabled and last, so the step just added is
// the parent's last direct child.
func addExecutions(ctx context.Context, c *admin.Client, base, parent string, executions []Execution) error {
	flowPath := base + "/authentication/flows/" + url.PathEscape(parent) + "/executions"
	for _, e := range executions {
		if e.Flow != "" {
			if _, err := c.Call(ctx, http.MethodPost, flowPath+"/flow", map[string]any{
				"alias": e.Flow, "type": "basic-flow", "provider": "registration-page-form", "description": "",
			}, http.StatusCreated); err != nil {
				return fmt.Errorf("adding sub-flow %s to %s: %w", e.Flow, parent, err)
			}
		} else {
			if _, err := c.Call(ctx, http.MethodPost, flowPath+"/execution", map[string]any{"provider": e.Authenticator},
				http.StatusCreated); err != nil {
				return fmt.Errorf("adding %s to %s: %w", e.Authenticator, parent, err)
			}
		}
		var listed []executionRepresentation
		if err := c.GetJSON(ctx, flowPath, &listed); err != nil {
			return err
		}
		var added *executionRepresentation
		for i := range listed {
			if listed[i].Level == 0 {
				added = &listed[i]
			}
		}
		if added == nil {
			return fmt.Errorf("the step added to %s is not listed", parent)
		}
		update := map[string]any{"id": added.ID, "requirement": e.Requirement}
		if _, err := c.Call(ctx, http.MethodPut, flowPath, update, http.StatusNoContent); err != nil {
			return fmt.Errorf("setting %s in %s to %s: %w", stepName(e), parent, e.Requirement, err)
		}
		if e.ConfigAlias != "" {
			if _, err := c.Call(ctx, http.MethodPost, base+"/authentication/executions/"+url.PathEscape(added.ID)+"/config",
				map[string]any{"alias": e.ConfigAlias, "config": e.Config}, http.StatusCreated); err != nil {
				return fmt.Errorf("configuring %s in %s: %w", stepName(e), parent, err)
			}
		}
		if e.Flow != "" {
			if err := addExecutions(ctx, c, base, e.Flow, e.Executions); err != nil {
				return err
			}
		}
	}
	return nil
}

// bindFlow sets one realm binding to a flow, which takes effect for the next sign-in.
func bindFlow(ctx context.Context, c *admin.Client, d Definition, binding string) error {
	for _, f := range d.Flows {
		if f.Binding == binding {
			_, err := c.Call(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(d.Name()),
				map[string]any{"realm": d.Name(), binding: f.Alias}, http.StatusNoContent)
			return err
		}
	}
	return fmt.Errorf("no declared flow takes the binding %s", binding)
}
