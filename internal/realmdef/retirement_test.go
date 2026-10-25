package realmdef

import (
	"strings"
	"testing"
	"time"
)

func TestTheRetirementFloorIsTheLongestLifetimePlusCacheAndSkew(t *testing.T) {
	// TDD-identity-kernel-002 §Retirement Window's own example: L2 at 15 minutes gives 26 minutes.
	realm := map[string]any{"accessTokenLifespan": 300.0, "accessTokenLifespanForImplicitFlow": 900.0}
	clients := []map[string]any{
		{"clientId": "plain"},
		{"clientId": "l2", "attributes": map[string]any{"access.token.lifespan": "900"}},
		{"clientId": "unset", "attributes": map[string]any{"access.token.lifespan": ""}},
	}
	f := retirementFloor(realm, clients)
	if f.LongestAccessToken != 15*time.Minute || f.Floor != 26*time.Minute || !strings.Contains(f.From, "l2") {
		t.Errorf("floor %+v; want 15m from client l2, floor 26m", f)
	}
	if err := checkRetirementWindow(f, RetirementWindow); err != nil {
		t.Errorf("a 26-minute floor fails the 7-day window: %v", err)
	}
}

func TestTheRealmLifespanSetsTheFloorWithoutOverrides(t *testing.T) {
	f := retirementFloor(map[string]any{"accessTokenLifespan": 300.0}, nil)
	if f.LongestAccessToken != 5*time.Minute || f.Floor != 16*time.Minute {
		t.Errorf("floor %+v; want 5m, floor 16m", f)
	}
}

func TestTheImplicitLifespanCountsOnlyForAnImplicitClient(t *testing.T) {
	realm := map[string]any{"accessTokenLifespan": 300.0, "accessTokenLifespanForImplicitFlow": 3600.0}
	if f := retirementFloor(realm, []map[string]any{{"clientId": "code"}}); f.LongestAccessToken != 5*time.Minute {
		t.Errorf("no implicit client, floor %+v; want 5m", f)
	}
	f := retirementFloor(realm, []map[string]any{{"clientId": "legacy", "implicitFlowEnabled": true}})
	if f.LongestAccessToken != time.Hour || !strings.Contains(f.From, "legacy") {
		t.Errorf("an implicit client, floor %+v; want 1h for legacy", f)
	}
}

func TestRaisingALifetimeRaisesTheFloorAndAFloorPastTheWindowFails(t *testing.T) {
	realm := map[string]any{"accessTokenLifespan": 300.0}
	short := retirementFloor(realm, []map[string]any{{"clientId": "c",
		"attributes": map[string]any{"access.token.lifespan": "900"}}})
	long := retirementFloor(realm, []map[string]any{{"clientId": "c",
		"attributes": map[string]any{"access.token.lifespan": "604800"}}})
	if long.Floor <= short.Floor {
		t.Fatalf("raising the lifetime left the floor at %s", long.Floor)
	}
	err := checkRetirementWindow(long, RetirementWindow)
	if err == nil || !strings.Contains(err.Error(), "client c") {
		t.Errorf("a 7-day lifetime passes the 7-day window: %v", err)
	}
}
