package realmdef

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
)

// The realm attributes the apply step records. Written only by Apply, and refused in a definition.
const (
	AttrRevision = "scnehaux.definition.revision"
	AttrDigest   = "scnehaux.definition.digest"
)

// Action is what applying the definition does to one managed object.
type Action string

const (
	InSync Action = "in sync"
	Create Action = "create"
	Update Action = "update"
)

// Change is one managed object's comparison with the live realm.
type Change struct {
	Kind, Name string
	Action     Action
	// Diffs name each declared value the live realm holds differently, for an Update.
	Diffs []string
}

// Record is what the last apply wrote into the realm.
type Record struct {
	RealmExists      bool
	Revision, Digest string
}

// Plan is a definition compared with a live realm.
type Plan struct {
	Realm   string
	Record  Record
	Changes []Change
	// Drift holds every difference between the live realm and the previously applied definition:
	// changes made outside this tool. Apply refuses a plan that carries any.
	Drift []string
	// Unmanaged is a realm that exists and was never applied by this tool, so there is no previous
	// definition to judge drift against. Apply refuses it unless adopted.
	Unmanaged bool

	definition Definition
	live       *live
}

// InSync reports whether applying would change nothing.
func (p Plan) InSync() bool {
	for _, change := range p.Changes {
		if change.Action != InSync {
			return false
		}
	}
	return true
}

// ReadRecord reads what the last apply recorded, so the caller can fetch the definition at that
// revision before planning.
func ReadRecord(ctx context.Context, c *admin.Client, realm string) (Record, error) {
	var rep map[string]any
	if err := c.GetJSON(ctx, "/admin/realms/"+url.PathEscape(realm), &rep); err != nil {
		if admin.IsNotFound(err) {
			return Record{}, nil
		}
		return Record{}, err
	}
	return recordOf(rep), nil
}

func recordOf(realm map[string]any) Record {
	attributes, _ := realm["attributes"].(map[string]any)
	revision, _ := attributes[AttrRevision].(string)
	digest, _ := attributes[AttrDigest].(string)
	return Record{RealmExists: true, Revision: revision, Digest: digest}
}

// NewPlan compares the definition with the live realm. previous is the definition the recorded
// revision applied; nil when nothing was recorded, or when the caller is adopting the live state.
func NewPlan(ctx context.Context, c *admin.Client, definition Definition, previous *Definition) (Plan, error) {
	observed, err := observe(ctx, c, definition.Name())
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Realm: definition.Name(), Changes: compare(definition, observed),
		definition: definition, live: observed}
	if observed.realm == nil {
		return plan, nil
	}
	plan.Record = recordOf(observed.realm)
	switch {
	case previous != nil:
		for _, change := range compare(*previous, observed) {
			switch change.Action {
			case Create:
				plan.Drift = append(plan.Drift, fmt.Sprintf("%s %s: removed from the live realm", change.Kind, change.Name))
			case Update:
				for _, diff := range change.Diffs {
					plan.Drift = append(plan.Drift, fmt.Sprintf("%s %s: %s", change.Kind, change.Name, diff))
				}
			}
		}
	case plan.Record.Revision == "":
		plan.Unmanaged = true
	}
	return plan, nil
}

// ---------------------------------------------------------------------------------------------
// The live realm
// ---------------------------------------------------------------------------------------------

type live struct {
	realm   map[string]any            // nil when the realm does not exist
	keys    map[string]map[string]any // key provider components, by name
	scopes  map[string]map[string]any // client scopes, by name
	profile map[string]any            // the whole user profile configuration
}

func (l *live) profileAttribute(attributeName string) map[string]any {
	for _, attribute := range listOfMaps(l.profile["attributes"]) {
		if name(attribute) == attributeName {
			return attribute
		}
	}
	return nil
}

func observe(ctx context.Context, c *admin.Client, realm string) (*live, error) {
	base := "/admin/realms/" + url.PathEscape(realm)
	observed := &live{keys: map[string]map[string]any{}, scopes: map[string]map[string]any{}}
	if err := c.GetJSON(ctx, base, &observed.realm); err != nil {
		if admin.IsNotFound(err) {
			observed.realm = nil
			return observed, nil
		}
		return nil, fmt.Errorf("reading realm %s: %w", realm, err)
	}

	var components []map[string]any
	if err := c.GetJSON(ctx, base+"/components?type="+url.QueryEscape("org.keycloak.keys.KeyProvider"),
		&components); err != nil {
		return nil, fmt.Errorf("reading the key providers: %w", err)
	}
	for _, component := range components {
		observed.keys[name(component)] = component
	}

	var scopes []map[string]any
	if err := c.GetJSON(ctx, base+"/client-scopes", &scopes); err != nil {
		return nil, fmt.Errorf("reading the client scopes: %w", err)
	}
	for _, scope := range scopes {
		observed.scopes[name(scope)] = scope
	}

	if err := c.GetJSON(ctx, base+"/users/profile", &observed.profile); err != nil {
		return nil, fmt.Errorf("reading the user profile: %w", err)
	}
	return observed, nil
}

// ---------------------------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------------------------

const (
	KindRealm     = "realm"
	KindKey       = "signing key"
	KindScope     = "client scope"
	KindAttribute = "user-profile attribute"
)

func compare(d Definition, l *live) []Change {
	var changes []Change
	if l.realm == nil {
		changes = append(changes, Change{Kind: KindRealm, Name: d.Name(), Action: Create},
			Change{Kind: KindKey, Name: name(d.Key), Action: Create})
		for _, scope := range d.Scopes {
			changes = append(changes, Change{Kind: KindScope, Name: name(scope), Action: Create})
		}
		for _, attribute := range d.Profile {
			changes = append(changes, Change{Kind: KindAttribute, Name: name(attribute), Action: Create})
		}
		return changes
	}

	changes = append(changes, compareObject(KindRealm, d.Name(), d.Realm, l.realm),
		compareObject(KindKey, name(d.Key), d.Key, l.keys[name(d.Key)]))
	for _, scope := range d.Scopes {
		changes = append(changes, compareScope(scope, l.scopes[name(scope)]))
	}
	for _, attribute := range d.Profile {
		changes = append(changes, compareObject(KindAttribute, name(attribute), attribute,
			l.profileAttribute(name(attribute))))
	}
	return changes
}

func compareObject(kind, objectName string, declared, observed map[string]any) Change {
	if observed == nil {
		return Change{Kind: kind, Name: objectName, Action: Create}
	}
	if diffs := diff("", declared, observed); len(diffs) > 0 {
		return Change{Kind: kind, Name: objectName, Action: Update, Diffs: diffs}
	}
	return Change{Kind: kind, Name: objectName, Action: InSync}
}

// compareScope compares mappers by name, and as a closed set: a mapper the definition does not
// declare is a difference, not an unmanaged detail. A console-added mapper on a scope is how an
// enterprise claim would reach an audience it is kept from, so the set is guarded, not just its
// members.
func compareScope(declared, observed map[string]any) Change {
	if observed == nil {
		return Change{Kind: KindScope, Name: name(declared), Action: Create}
	}
	declaredMappers := byName(declared["protocolMappers"])
	observedMappers := byName(observed["protocolMappers"])

	diffs := diff("", withoutMappers(declared), withoutMappers(observed))
	diffs = append(diffs, diff("protocolMappers", toAny(declaredMappers), toAny(observedMappers))...)
	for _, mapperName := range sortedKeys(observedMappers) {
		if _, declared := declaredMappers[mapperName]; !declared {
			diffs = append(diffs, fmt.Sprintf("protocolMappers.%s: present live, absent from the definition", mapperName))
		}
	}
	if len(diffs) > 0 {
		return Change{Kind: KindScope, Name: name(declared), Action: Update, Diffs: diffs}
	}
	return Change{Kind: KindScope, Name: name(declared), Action: InSync}
}

// diff compares what the definition declares, and only that: a live key the definition does not
// name is Keycloak's default or an unmanaged detail, and comparing it would make every Keycloak
// release that adds a field read as drift.
func diff(path string, declared, observed any) []string {
	if declaredMap, ok := declared.(map[string]any); ok {
		observedMap, ok := observed.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: live %s, definition %s", orRoot(path), show(observed), show(declared))}
		}
		var out []string
		for _, key := range sortedKeys(declaredMap) {
			out = append(out, diff(join(path, key), declaredMap[key], observedMap[key])...)
		}
		return out
	}
	if !reflect.DeepEqual(normalise(declared), normalise(observed)) {
		return []string{fmt.Sprintf("%s: live %s, definition %s", orRoot(path), show(observed), show(declared))}
	}
	return nil
}

// normalise puts a value into the shape JSON decoding gives it, so a definition built in Go
// compares equal to one read from a file.
func normalise(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var out any
	_ = json.Unmarshal(encoded, &out)
	return out
}

func byName(list any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, item := range listOfMaps(list) {
		out[name(item)] = item
	}
	return out
}

func toAny(m map[string]map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func withoutMappers(scope map[string]any) map[string]any {
	out := make(map[string]any, len(scope))
	for k, v := range scope {
		if k != "protocolMappers" {
			out[k] = v
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func orRoot(path string) string {
	if path == "" {
		return "(object)"
	}
	return path
}

func show(value any) string {
	if value == nil {
		return "absent"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return strings.TrimSpace(string(encoded))
}
