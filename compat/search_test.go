package compat

// Proof-of-concept question 2: attribute search semantics.
//
// identity-control's crash recovery (TDD-identity-control-001) searches Keycloak by
// scnehaux_principal_id and branches on the count: one match is adopted, zero retries the create,
// more than one quarantines every match. That algorithm is only as correct as the index under it,
// so this file asks the index four things:
//
//	exact     does a near-miss value match? A prefix or substring match would hand recovery a
//	          stranger's user to adopt, unless identity-control compares for equality itself
//	case      does a value differing only in case match? Harmless while the identifier is always
//	          written in canonical lowercase, and a rule identity-control must keep if it does
//	disabled  is a disabled user still found? If not, "zero found, retry the create" makes a second
//	          user for a Principal whose first one was quarantined
//	paging    do first/max page a many-match result without overlap or loss? The many-match branch
//	          quarantines EVERY match, and a page that dropped one would leave it enabled
//
// Only the last two can make the recovery design wrong, so only they fail the suite. The first two
// are answered either way; they change how identity-control reads the result, not whether it can.

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type searchHit struct {
	ID         string              `json:"id"`
	Enabled    bool                `json:"enabled"`
	Attributes map[string][]string `json:"attributes"`
}

func TestQuestion2AttributeSearchSemantics(t *testing.T) {
	a := requireKeycloak(t)
	target := createPrincipal(t, a)
	id := target.principalID
	var rows [][3]string // property, answer, consequence

	// The value itself returns exactly the target. Not one of the questions: without it recovery has
	// no index at all, whatever the other answers are.
	if hits := searchByPrincipalID(t, a, id, 0, 10); len(hits) != 1 || hits[0].ID != target.userID {
		t.Fatalf("searching for the identifier a user was created with returned %d users %v, want exactly "+
			"that user: attribute search is not a recovery index", len(hits), hitIDs(hits))
	}

	// Near misses. A UUIDv7's head is the millisecond timestamp, which every fixture in this run
	// shares, and its tail is random. So the probes drop or add a character at the end, or keep only
	// the random tail: a probe built from the head would match other fixtures and measure the run
	// rather than the matcher.
	exact := true
	for _, probe := range []struct{ name, value string }{
		{"prefix, last character dropped", id[:len(id)-1]},
		{"substring, random tail only", id[len(id)-12:]},
		{"extension, one character added", id + "0"},
	} {
		if holds(searchByPrincipalID(t, a, probe.value, 0, 10), target.userID) {
			exact = false
			t.Logf("near miss (%s) %q matches the user holding %q", probe.name, probe.value, id)
		}
	}
	if exact {
		rows = append(rows, [3]string{"exact match", "yes -- no prefix, substring or extension matches",
			"recovery may branch on the count as returned"})
	} else {
		rows = append(rows, [3]string{"exact match", "**no** -- a near miss matches",
			"identity-control must keep only hits whose attribute equals the identifier before counting"})
		// Answered exact against the pinned release, and identity-control counts the result as
		// returned on the strength of that answer. A release that loosens the match hands recovery a
		// stranger's user to adopt.
		if loadContract(t).Question2.ExactMatch {
			t.Error("REGRESSION: realm/contract.json records attribute search as exact-match and a near miss " +
				"now matches; identity-control's recovery counts hits as returned and would adopt the wrong user")
		}
	}

	caseSensitive := !holds(searchByPrincipalID(t, a, strings.ToUpper(id), 0, 10), target.userID)
	if caseSensitive {
		rows = append(rows, [3]string{"case", "sensitive", "none; identifiers are minted lowercase"})
	} else {
		rows = append(rows, [3]string{"case", "**insensitive**",
			"identity-control must write the identifier in canonical lowercase, always"})
	}

	// A disabled user is still found. The reconciler disables rather than deletes, and quarantine is
	// a disable, so an index that hid disabled users would read a quarantined Principal as absent.
	disabled, err := newPrincipal(a, uuidV7(), false)
	if err != nil {
		t.Fatalf("creating a disabled Principal: %v", err)
	}
	if holds(searchByPrincipalID(t, a, disabled.principalID, 0, 10), disabled.userID) {
		rows = append(rows, [3]string{"disabled users", "found", "none"})
	} else {
		rows = append(rows, [3]string{"disabled users", "**not found**", "recovery would create a duplicate"})
		t.Errorf("a disabled user is invisible to attribute search: recovery would read a quarantined " +
			"Principal as absent and create a second user for it")
	}

	rows = append(rows, pagingAnswers(t, a)...)

	var b strings.Builder
	fmt.Fprintf(&b, "## Proof-of-concept question 2: attribute search semantics\n\n")
	fmt.Fprintf(&b, "Image: `%s`\n\n", imageRef())
	fmt.Fprintf(&b, "`GET /admin/realms/%s/users?q=scnehaux_principal_id:{id}&first=&max=`\n\n", realmName)
	fmt.Fprintf(&b, "| Property | Answer | Consequence for identity-control recovery |\n| :-- | :-- | :-- |\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", row[0], row[1], row[2])
	}
	publish(t, b.String())
}

// pagingAnswers creates the many-match case -- which is also the question of whether Keycloak lets
// two users hold one identifier at all -- and pages through it.
func pagingAnswers(t *testing.T, a *admin) [][3]string {
	t.Helper()
	shared := uuidV7()
	want := map[string]bool{}
	for i := 0; i < 3; i++ {
		p, err := newPrincipal(a, shared, true)
		if err != nil {
			if i == 0 {
				t.Fatalf("creating the first holder of a fresh identifier: %v", err)
			}
			// Keycloak enforcing uniqueness would make the many-match branch unreachable -- a better
			// answer than the one the design assumes, and not a failure.
			t.Logf("a user sharing an identifier was refused: %v", err)
			return [][3]string{{"duplicate identifiers", "**refused by Keycloak**",
				"the many-match branch is unreachable; the reconciler keeps it as defense in depth"}}
		}
		want[p.userID] = true
	}
	rows := [][3]string{{"duplicate identifiers", "accepted -- Keycloak does not enforce uniqueness",
		"as designed: the many-match branch and the reconciler are needed"}}

	for _, size := range []int{1, 2} {
		seen := map[string]int{}
		var pages []int
		for first := 0; first < 3+size; first += size {
			hits := searchByPrincipalID(t, a, shared, first, size)
			pages = append(pages, len(hits))
			for _, hit := range hits {
				seen[hit.ID]++
			}
			if len(hits) < size {
				break
			}
		}
		complete := len(seen) == len(want)
		for userID, n := range seen {
			if !want[userID] || n != 1 {
				complete = false
			}
		}
		if complete {
			rows = append(rows, [3]string{fmt.Sprintf("paging, max=%d", size),
				fmt.Sprintf("complete, no overlap (page sizes %v)", pages), "none"})
		} else {
			rows = append(rows, [3]string{fmt.Sprintf("paging, max=%d", size),
				fmt.Sprintf("**lossy or overlapping** (page sizes %v, seen %v)", pages, seen),
				"quarantine would miss a duplicate"})
			t.Errorf("paging three users sharing an identifier with max=%d saw %v across pages %v, want each "+
				"of %d users exactly once: the many-match branch would leave a duplicate enabled",
				size, seen, pages, len(want))
		}
	}

	// The count endpoint, reported rather than required: recovery pages the result and counts it
	// itself, and needs nothing from here.
	var count int
	query := url.Values{"q": {"scnehaux_principal_id:" + shared}}
	if err := a.getJSON("/admin/realms/"+realmName+"/users/count?"+query.Encode(), &count); err != nil {
		rows = append(rows, [3]string{"count endpoint with q", "unavailable: " + err.Error(), "none; count by paging"})
	} else if count == len(want) {
		rows = append(rows, [3]string{"count endpoint with q", "honours q", "none"})
	} else {
		rows = append(rows, [3]string{"count endpoint with q", fmt.Sprintf("**ignores q** (%d)", count),
			"never size a result with it; count by paging"})
	}
	return rows
}

func searchByPrincipalID(t *testing.T, a *admin, value string, first, max int) []searchHit {
	t.Helper()
	query := url.Values{
		"q":     {"scnehaux_principal_id:" + value},
		"first": {strconv.Itoa(first)},
		"max":   {strconv.Itoa(max)},
	}
	var hits []searchHit
	if err := a.getJSON("/admin/realms/"+realmName+"/users?"+query.Encode(), &hits); err != nil {
		t.Fatalf("searching by scnehaux_principal_id=%q: %v", value, err)
	}
	return hits
}

func holds(hits []searchHit, userID string) bool {
	for _, hit := range hits {
		if hit.ID == userID {
			return true
		}
	}
	return false
}

func hitIDs(hits []searchHit) []string {
	ids := make([]string, 0, len(hits))
	for _, hit := range hits {
		ids = append(ids, hit.ID)
	}
	return ids
}
