package compat

// Admin events, from TDD-identity-kernel-003 §Configuration: enabled, with representation, and kept
// longer than the reconcile interval. identity-control's Proof B depends on them. A change made in
// the console is told apart from drift by the admin event that recorded it, which only works if the
// event names who made it and what it changed to.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type adminEvent struct {
	OperationType  string `json:"operationType"`
	ResourceType   string `json:"resourceType"`
	ResourcePath   string `json:"resourcePath"`
	Representation string `json:"representation"`
	AuthDetails    struct {
		UserID string `json:"userId"`
	} `json:"authDetails"`
}

// A group is created and deleted by hand: groups are outside the definition, so the realm ends in
// sync with it.
func TestAnAdminChangeIsRecordedWithWhoAndWhat(t *testing.T) {
	a := requireKeycloak(t)
	groupName := "compat-admin-event-" + suffix()
	response, err := a.call(http.MethodPost, "/admin/realms/"+realmName+"/groups",
		map[string]any{"name": groupName}, http.StatusCreated)
	if err != nil {
		t.Fatalf("creating a group by hand: %v", err)
	}
	groupID := created(response)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/groups/"+groupID, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting the group: %v", err)
		}
	})

	query := url.Values{"operationTypes": {"CREATE"}, "resourceTypes": {"GROUP"}, "max": {"50"}}
	var found *adminEvent
	for deadline := time.Now().Add(10 * time.Second); found == nil && time.Now().Before(deadline); {
		var events []adminEvent
		if err := a.getJSON("/admin/realms/"+realmName+"/admin-events?"+query.Encode(), &events); err != nil {
			t.Fatalf("reading admin events: %v", err)
		}
		for i := range events {
			if events[i].ResourcePath == "groups/"+groupID {
				found = &events[i]
			}
		}
		if found == nil {
			time.Sleep(250 * time.Millisecond)
		}
	}
	if found == nil {
		t.Fatal("creating a group recorded no admin event: a console change could not be attributed")
	}
	if !strings.Contains(found.Representation, groupName) {
		t.Errorf("the admin event carries representation %q, want the group it created: without it the "+
			"event records that something changed and not what it changed to", found.Representation)
	}
	if found.AuthDetails.UserID == "" {
		t.Error("the admin event names no user: a change nobody can be attributed with is never sanctioned")
	}
}

// Retention is a realm attribute, not a top-level key, so it is asserted where Keycloak keeps it.
func TestAdminEventsAreKeptASevenDayWindow(t *testing.T) {
	a := requireKeycloak(t)
	var realm struct {
		AdminEventsEnabled        bool              `json:"adminEventsEnabled"`
		AdminEventsDetailsEnabled bool              `json:"adminEventsDetailsEnabled"`
		Attributes                map[string]string `json:"attributes"`
	}
	if err := a.getJSON("/admin/realms/"+realmName, &realm); err != nil {
		t.Fatalf("reading the realm: %v", err)
	}
	if !realm.AdminEventsEnabled || !realm.AdminEventsDetailsEnabled {
		t.Errorf("admin events enabled %v, with representation %v; want both", realm.AdminEventsEnabled,
			realm.AdminEventsDetailsEnabled)
	}
	if got := realm.Attributes["adminEventsExpiration"]; got != "604800" {
		t.Errorf("admin-event retention is %q seconds, want 604800 (7 days)", got)
	}
}
