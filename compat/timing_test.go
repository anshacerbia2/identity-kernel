package compat

// The sign-in's timing (TDD-identity-kernel-004 §Enumeration Resistance, STD-IAM-001 §3.1): an
// unknown identifier, a wrong password and a disabled account answer with the same message and
// status (theme_test.go), and here, in times no test separates. Keycloak hashes a dummy password for
// an unknown identifier so that it costs what a wrong password costs (AuthenticatorUtils.dummyHash).
//
// The method is dudect's (Reparaz, Balasch, Verbauwhede, DATE 2017): the classes are measured
// interleaved in a random order, so drift in the runner falls on all of them alike, and each pair is
// compared with Welch's t-test on every measurement and on the fastest 90 percent, which drops the
// tail a pause or a collection adds. |t| above dudect's own threshold of 10 is a separable
// difference.
//
// Two paths the pinned kernel does not hash for an existing account are measured and recorded, not
// required: an empty password (keycloak#51887) and an account under a brute-force lockout, refused
// before its password is checked. They are STD-IAM-001's recorded gaps; the summary shows when a
// release closes them.

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

// separable is dudect's t_threshold_moderate.
const separable = 10.0

// timingSamples per class: a hash-sized difference gives |t| in the hundreds at this size, and two
// classes that hash alike stay in single digits.
const timingSamples = 30

type timedClass struct {
	name    string
	samples []float64 // milliseconds
}

func (c *timedClass) median() float64 {
	sorted := append([]float64(nil), c.samples...)
	sort.Float64s(sorted)
	return sorted[len(sorted)/2]
}

// welch is Welch's t statistic between two samples.
func welch(a, b []float64) float64 {
	mean := func(x []float64) float64 {
		s := 0.0
		for _, v := range x {
			s += v
		}
		return s / float64(len(x))
	}
	variance := func(x []float64, m float64) float64 {
		s := 0.0
		for _, v := range x {
			s += (v - m) * (v - m)
		}
		return s / float64(len(x)-1)
	}
	ma, mb := mean(a), mean(b)
	return (ma - mb) / math.Sqrt(variance(a, ma)/float64(len(a))+variance(b, mb)/float64(len(b)))
}

// fastest keeps the fastest fraction of a sample, as dudect crops its measurements.
func fastest(x []float64, fraction float64) []float64 {
	sorted := append([]float64(nil), x...)
	sort.Float64s(sorted)
	return sorted[:int(math.Ceil(float64(len(sorted))*fraction))]
}

// maxT is the larger |t| of the uncropped and the cropped comparison.
func maxT(a, b []float64) float64 {
	return math.Max(math.Abs(welch(a, b)), math.Abs(welch(fastest(a, 0.9), fastest(b, 0.9))))
}

// timedSignIn opens a login page, untimed, and times the post of one credential.
func timedSignIn(t *testing.T, a *admin, c client, username, password string) float64 {
	t.Helper()
	b := newThemeBrowser(t)
	page := b.loginPage(a, c, "en")
	start := time.Now()
	status, _ := b.signIn(page, username, password)
	elapsed := time.Since(start)
	if status != http.StatusOK && status != http.StatusBadRequest && status != http.StatusUnauthorized {
		t.Fatalf("a refused sign-in answered %d", status)
	}
	return float64(elapsed.Microseconds()) / 1000
}

// interleave runs each class's attempts in one random order.
func interleave(attempts map[*timedClass][]func() float64) {
	type job struct {
		class *timedClass
		run   func() float64
	}
	var jobs []job
	for class, runs := range attempts {
		for _, run := range runs {
			jobs = append(jobs, job{class, run})
		}
	}
	rand.Shuffle(len(jobs), func(i, j int) { jobs[i], jobs[j] = jobs[j], jobs[i] })
	for _, j := range jobs {
		j.class.samples = append(j.class.samples, j.run())
	}
}

func TestASignInFailureTakesNoTimeThatTellsAccountState(t *testing.T) {
	a := requireKeycloak(t)
	caller := providerCaller(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+caller.uuid, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", caller.id, err)
		}
	})
	people := func(n int, disabled bool) []principal {
		out := make([]principal, n)
		for i := range out {
			p := providerPrincipal(t, a)
			userID := p.userID
			t.Cleanup(func() {
				if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+userID, nil,
					http.StatusNoContent); err != nil {
					t.Errorf("deleting a user: %v", err)
				}
			})
			if disabled {
				if _, err := a.call(http.MethodPut, "/admin/realms/"+realmName+"/users/"+userID,
					map[string]any{"enabled": false}, http.StatusNoContent); err != nil {
					t.Fatalf("disabling a user: %v", err)
				}
			}
			out[i] = p
		}
		return out
	}

	// One attempt per account: a second failure within quickLoginCheckMilliSeconds would lock it,
	// and a locked account is a path of its own, measured below.
	unknown, wrong, disabledClass := &timedClass{name: "an unknown identifier"},
		&timedClass{name: "a wrong password"}, &timedClass{name: "a disabled account"}
	attempts := map[*timedClass][]func() float64{}
	for range timingSamples {
		attempts[unknown] = append(attempts[unknown], func() float64 {
			return timedSignIn(t, a, caller, "compat-nobody-"+suffix(), "Wrong-"+suffix()+"!")
		})
	}
	for _, p := range people(timingSamples, false) {
		attempts[wrong] = append(attempts[wrong], func() float64 {
			return timedSignIn(t, a, caller, p.username, "Wrong-"+suffix()+"!")
		})
	}
	for _, p := range people(timingSamples, true) {
		attempts[disabledClass] = append(attempts[disabledClass], func() float64 {
			return timedSignIn(t, a, caller, p.username, p.password)
		})
	}
	interleave(attempts)

	// The recorded gaps, against a fresh set of unknown identifiers measured alongside them.
	unknownAgain, empty, locked := &timedClass{name: "an unknown identifier"},
		&timedClass{name: "an empty password (keycloak#51887)"}, &timedClass{name: "an account under lockout"}
	gaps := map[*timedClass][]func() float64{}
	for range timingSamples {
		gaps[unknownAgain] = append(gaps[unknownAgain], func() float64 {
			return timedSignIn(t, a, caller, "compat-nobody-"+suffix(), "")
		})
	}
	for _, p := range people(timingSamples, false) {
		gaps[empty] = append(gaps[empty], func() float64 { return timedSignIn(t, a, caller, p.username, "") })
	}
	for _, p := range people(timingSamples, false) {
		gaps[locked] = append(gaps[locked], func() float64 {
			lock(t, a, caller, p)
			return timedSignIn(t, a, caller, p.username, "Wrong-"+suffix()+"!")
		})
	}
	interleave(gaps)

	var b strings.Builder
	fmt.Fprintf(&b, "### The sign-in's timing\n\nAgainst `%s`; %d attempts per class, interleaved. ", imageRef(), timingSamples)
	fmt.Fprintf(&b, "|t| is Welch's, the larger of every attempt and the fastest 90%%; above %.0f is separable.\n\n", separable)
	b.WriteString("| Class | Median ms | Against | \\|t\\| | Separable | Required |\n| :-- | --: | :-- | --: | :-- | :-- |\n")
	row := func(c, against *timedClass, required string) bool {
		tt := maxT(c.samples, against.samples)
		fmt.Fprintf(&b, "| %s | %.1f | %s (%.1f ms) | %.1f | %s | %s |\n", c.name, c.median(), against.name,
			against.median(), tt, yesNo(tt > separable), required)
		return tt > separable
	}
	for _, pair := range [][2]*timedClass{{wrong, unknown}, {disabledClass, unknown}, {disabledClass, wrong}} {
		if row(pair[0], pair[1], "no") {
			t.Errorf("%s and %s are separable by time: |t| %.1f, medians %.1f and %.1f ms", pair[0].name,
				pair[1].name, maxT(pair[0].samples, pair[1].samples), pair[0].median(), pair[1].median())
		}
	}
	row(empty, unknownAgain, "recorded")
	row(locked, unknownAgain, "recorded")
	publish(t, b.String())
}

// lock puts an account under a temporary lockout: two failures inside the realm's
// quickLoginCheckMilliSeconds, then a wait until the kernel reports it.
func lock(t *testing.T, a *admin, c client, p principal) {
	t.Helper()
	for range 2 {
		b := newThemeBrowser(t)
		b.signIn(b.loginPage(a, c, "en"), p.username, "Wrong-"+suffix()+"!")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var status struct {
			Disabled bool `json:"disabled"`
		}
		if err := a.getJSON("/admin/realms/"+realmName+"/attack-detection/brute-force/users/"+p.userID, &status); err != nil {
			t.Fatalf("reading the lockout of %s: %v", p.username, err)
		}
		if status.Disabled {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s is not under lockout after two quick failures", p.username)
}
