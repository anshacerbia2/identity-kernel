package realmdef

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
)

var (
	// ErrDrift refuses a plan whose live realm carries changes the previous definition does not.
	ErrDrift = errors.New("the live realm carries changes the previously applied definition does not")
	// ErrUnmanaged refuses a realm this tool never applied, which has no baseline to judge drift by.
	ErrUnmanaged = errors.New("the realm exists and was never applied by this tool")
	// ErrNotConverged is an apply after which the live realm still differs from the definition.
	ErrNotConverged = errors.New("the live realm does not match the definition after applying it")
)

// Options govern one apply.
type Options struct {
	Environment Environment
	// Revision is recorded in the realm as the definition's source. Required.
	Revision string
	// Adopt accepts the live realm as the baseline, skipping the drift and unmanaged refusals, and
	// then converges it to the definition. It is for taking over a realm made by hand, or for
	// accepting a console change after committing it to realm/ -- and it is the one way to
	// overwrite a change nobody recorded, so it is never a default.
	Adopt bool
}

// Apply converges the live realm to the plan's definition, verifies that it did, and records the
// revision. Nothing is deleted: an object removed from the definition stays in the realm, because
// removing a user-profile attribute makes Keycloak discard that attribute's values from every user
// on their next write, and removing a client scope strips its claims from every client using it.
// Both are migrations, not configuration changes. Mappers inside a managed scope are the exception:
// the scope's mapper set is the definition's, so an undeclared mapper is removed.
func Apply(ctx context.Context, c *admin.Client, plan Plan, options Options) error {
	if _, err := ParseEnvironment(string(options.Environment)); err != nil {
		return err
	}
	if strings.TrimSpace(options.Revision) == "" {
		return errors.New("a revision to record is required")
	}
	if len(plan.Drift) > 0 && !options.Adopt {
		return fmt.Errorf("%w:\n  %s", ErrDrift, strings.Join(plan.Drift, "\n  "))
	}
	if plan.Unmanaged && !options.Adopt {
		return ErrUnmanaged
	}

	d := plan.definition
	base := "/admin/realms/" + url.PathEscape(d.Name())
	profileChanged := false
	for _, change := range plan.Changes {
		if change.Action == InSync {
			continue
		}
		var err error
		switch change.Kind {
		case KindRealm:
			err = applyRealm(ctx, c, d, change.Action)
		case KindKey:
			err = applyKey(ctx, c, base, d.Key, plan.live, change.Action)
		case KindScope:
			err = applyScope(ctx, c, base, scopeNamed(d, change.Name), plan.live, change.Action)
		case KindAttribute:
			profileChanged = true
		}
		if err != nil {
			return fmt.Errorf("applying %s %s: %w", change.Kind, change.Name, err)
		}
	}
	if profileChanged {
		if err := applyProfile(ctx, c, base, d.Profile); err != nil {
			return fmt.Errorf("applying the user profile: %w", err)
		}
	}

	// Verify before recording. A value Keycloak normalises on write -- or silently drops, as it does
	// an undeclared user attribute -- would otherwise be recorded as applied and read as drift on the
	// next run, blaming a person for what the definition got wrong.
	after, err := NewPlan(ctx, c, d, nil)
	if err != nil {
		return fmt.Errorf("verifying the apply: %w", err)
	}
	if !after.InSync() {
		var diffs []string
		for _, change := range after.Changes {
			if change.Action == InSync {
				continue
			}
			if len(change.Diffs) == 0 {
				diffs = append(diffs, fmt.Sprintf("%s %s: still %s", change.Kind, change.Name, change.Action))
			}
			for _, diff := range change.Diffs {
				diffs = append(diffs, fmt.Sprintf("%s %s: %s", change.Kind, change.Name, diff))
			}
		}
		return fmt.Errorf("%w:\n  %s", ErrNotConverged, strings.Join(diffs, "\n  "))
	}
	return record(ctx, c, base, d, options.Revision)
}

func applyRealm(ctx context.Context, c *admin.Client, d Definition, action Action) error {
	if action == Create {
		_, err := c.Call(ctx, http.MethodPost, "/admin/realms", d.Realm, http.StatusCreated)
		return err
	}
	// A partial representation: Keycloak updates the fields present and leaves the rest.
	_, err := c.Call(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(d.Name()), d.Realm, http.StatusNoContent)
	return err
}

func applyKey(ctx context.Context, c *admin.Client, base string, key map[string]any, l *live, action Action) error {
	if action == Create {
		var realm struct {
			ID string `json:"id"`
		}
		if err := c.GetJSON(ctx, base, &realm); err != nil {
			return err
		}
		body := overlay(nil, key)
		body["parentId"] = realm.ID
		_, err := c.Call(ctx, http.MethodPost, base+"/components", body, http.StatusCreated)
		return err
	}
	observed := l.keys[name(key)]
	id, _ := observed["id"].(string)
	_, err := c.Call(ctx, http.MethodPut, base+"/components/"+url.PathEscape(id), overlay(observed, key),
		http.StatusNoContent)
	return err
}

func applyScope(ctx context.Context, c *admin.Client, base string, scope map[string]any, l *live, action Action) error {
	if action == Create {
		_, err := c.Call(ctx, http.MethodPost, base+"/client-scopes", scope, http.StatusCreated)
		return err
	}
	observed := l.scopes[name(scope)]
	id, _ := observed["id"].(string)
	scopePath := base + "/client-scopes/" + url.PathEscape(id)
	if _, err := c.Call(ctx, http.MethodPut, scopePath, overlay(withoutMappers(observed), withoutMappers(scope)),
		http.StatusNoContent); err != nil {
		return err
	}

	declared := byName(scope["protocolMappers"])
	existing := byName(observed["protocolMappers"])
	for _, mapperName := range sortedKeys(declared) {
		mapper := declared[mapperName]
		current, present := existing[mapperName]
		switch {
		case !present:
			if _, err := c.Call(ctx, http.MethodPost, scopePath+"/protocol-mappers/models", mapper,
				http.StatusCreated); err != nil {
				return err
			}
		case len(diff("", mapper, current)) > 0:
			mapperID, _ := current["id"].(string)
			if _, err := c.Call(ctx, http.MethodPut, scopePath+"/protocol-mappers/models/"+url.PathEscape(mapperID),
				overlay(current, mapper), http.StatusNoContent); err != nil {
				return err
			}
		}
	}
	for _, mapperName := range sortedKeys(existing) {
		if _, kept := declared[mapperName]; kept {
			continue
		}
		mapperID, _ := existing[mapperName]["id"].(string)
		if _, err := c.Call(ctx, http.MethodDelete, scopePath+"/protocol-mappers/models/"+url.PathEscape(mapperID),
			nil, http.StatusNoContent); err != nil {
			return err
		}
	}
	return nil
}

// applyProfile writes the declared attributes into the live profile by name, leaving every other
// attribute as it is. PUT replaces the whole configuration, so the live one is read and edited rather
// than replaced.
//
// A declared attribute is laid over the live one rather than substituted for it: the definition states
// what it governs and Keycloak keeps the rest, the same rule the comparison follows. That is what lets
// the definition govern one field of a built-in attribute -- firstName's required, for one -- without
// restating, and silently discarding, the validations Keycloak ships it with. A declared null removes
// the field.
func applyProfile(ctx context.Context, c *admin.Client, base string, declared []map[string]any) error {
	path := base + "/users/profile"
	var profile map[string]any
	if err := c.GetJSON(ctx, path, &profile); err != nil {
		return err
	}
	attributes := listOfMaps(profile["attributes"])
	for _, attribute := range declared {
		replaced := false
		for i := range attributes {
			if name(attributes[i]) == name(attribute) {
				attributes[i] = overlay(attributes[i], attribute)
				replaced = true
			}
		}
		if !replaced {
			attributes = append(attributes, attribute)
		}
	}
	profile["attributes"] = attributes
	_, err := c.Call(ctx, http.MethodPut, path, profile, http.StatusOK)
	return err
}

// record writes the revision and digest into the realm's attributes, merged with the attributes it
// already has, and reads them back: a realm that did not keep them would make every later run
// report the realm unmanaged.
func record(ctx context.Context, c *admin.Client, base string, d Definition, revision string) error {
	var realm map[string]any
	if err := c.GetJSON(ctx, base, &realm); err != nil {
		return err
	}
	attributes, _ := realm["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	attributes[AttrRevision] = revision
	attributes[AttrDigest] = d.Digest()
	if _, err := c.Call(ctx, http.MethodPut, base, map[string]any{"realm": d.Name(), "attributes": attributes},
		http.StatusNoContent); err != nil {
		return fmt.Errorf("recording the applied revision: %w", err)
	}
	got, err := ReadRecord(ctx, c, d.Name())
	if err != nil {
		return err
	}
	if got.Revision != revision || got.Digest != d.Digest() {
		return fmt.Errorf("the realm did not keep the recorded revision (holds %q, digest %q)", got.Revision, got.Digest)
	}
	return nil
}

func scopeNamed(d Definition, scopeName string) map[string]any {
	for _, scope := range d.Scopes {
		if name(scope) == scopeName {
			return scope
		}
	}
	return nil
}

// overlay returns base with every value the definition declares written over it, recursively for
// objects, so an update carries the live representation's other fields back unchanged.
func overlay(base, declared map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(declared))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range declared {
		if declaredMap, ok := v.(map[string]any); ok {
			baseMap, _ := out[k].(map[string]any)
			out[k] = overlay(baseMap, declaredMap)
			continue
		}
		out[k] = v
	}
	return out
}
