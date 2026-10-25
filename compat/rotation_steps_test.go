package compat

// The five key states, end to end, through the steps an operator runs (TDD-identity-kernel-002 1.5.0
// §Rotation as Built, ADR-IAM-002 §5.2 and §5.5): scripts/signing-key-ceremony.sh makes each key and
// scripts/signing-key-rotation.sh moves it, with identity-control's registry holding every approval and
// transition. The `rotation` job of compat.yml runs it, with identity-control at its identity_ref, the
// throwaway windows of a ci environment, and KERNEL_ROTATION_PROOF set. It asserts:
//
//   - a staged key is published and signs nothing;
//   - an activation waits the cache window, unless it is an emergency, and then new tokens carry the
//     new kid, while a token the old key signed still verifies against the key set;
//   - a retiring key leaves the key set only at its retirement, after the retirement window, and a
//     token it signed then fails; its files are destroyed;
//   - an abandoned key and a revoked key leave at once, and the registry records each state;
//   - at every step the key set holds RSA PS256 keys alone, and no step makes a fallback or an RS256 key;
//   - a step without its approval, or before its window, is refused.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/identity-kernel/internal/realmdef"
)

var ceremonyKid = regexp.MustCompile(`"kid": "([A-Za-z0-9_-]{43})"`)

func TestTheFiveStatesThroughTheRotationSteps(t *testing.T) {
	if os.Getenv("KERNEL_ROTATION_PROOF") == "" {
		t.Skip("KERNEL_ROTATION_PROOF is unset: the rotation job runs this, with identity-control's registry")
	}
	a := requireKeycloak(t)
	keys := os.Getenv("KERNEL_KEYS")
	cache, err := time.ParseDuration(os.Getenv("SIGNING_KEY_CACHE_WINDOW"))
	if err != nil {
		t.Fatalf("SIGNING_KEY_CACHE_WINDOW: %v", err)
	}
	retirement, err := time.ParseDuration(os.Getenv("SIGNING_KEY_RETIREMENT_WINDOW"))
	if err != nil {
		t.Fatalf("SIGNING_KEY_RETIREMENT_WINDOW: %v", err)
	}
	const (
		generator = "Ceremony Operator"
		witness   = "Ceremony Witness"
		operator  = "Step Operator"
		approver  = "Step Approver"
		ticket    = "CHG-ROTATION"
	)
	run := func(want int, script string, args ...string) string {
		t.Helper()
		cmd := exec.Command(filepath.Join("..", "scripts", script), args...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		got := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			got = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("%s %v: %v", script, args, err)
		}
		if got != want {
			t.Fatalf("%s %v exited %d, want %d:\n%s", script, args, got, want, out.String())
		}
		return out.String()
	}
	step := func(want int, args ...string) string { return run(want, "signing-key-rotation.sh", args...) }
	ceremony := func() string {
		t.Helper()
		out := run(0, "signing-key-ceremony.sh", keys, generator, witness, ticket)
		match := ceremonyKid.FindStringSubmatch(out)
		if match == nil {
			t.Fatalf("the ceremony printed no kid:\n%s", out)
		}
		return match[1]
	}
	approve := func(kid, transition string, extra ...string) {
		t.Helper()
		step(0, append([]string{"approve", kid, transition, operator, approver, "rotation proof", ticket}, extra...)...)
	}
	registered := func() map[string]string {
		t.Helper()
		states := map[string]string{}
		for _, line := range strings.Split(step(0, "state"), "\n") {
			var s struct{ Kid, State string }
			if strings.HasPrefix(line, "{") && strings.Contains(line, `"staged_at"`) &&
				json.Unmarshal([]byte(line), &s) == nil {
				states[s.Kid] = s.State
			}
		}
		return states
	}

	// The checks at every step: the key set, the active key, nothing generated.
	published := func(stage string, want []string, active string) {
		t.Helper()
		var kids []string
		for _, key := range publishedKeySet(t, a) {
			kids = append(kids, key.Kid)
			if key.Kty != "RSA" || key.Alg != "PS256" || key.Use != "sig" {
				t.Errorf("%s: the key set publishes %+v; ADR-IAM-002 §5.1 allows RSA PS256 alone", stage, key)
			}
		}
		sort.Strings(kids)
		want = append([]string(nil), want...)
		sort.Strings(want)
		if strings.Join(kids, " ") != strings.Join(want, " ") {
			t.Errorf("%s: the key set publishes %v, want %v", stage, kids, want)
		}
		var realmKeys struct {
			Active map[string]string                                     `json:"active"`
			Keys   []struct{ Kid, Algorithm, Status, ProviderID string } `json:"keys"`
		}
		if err := a.getJSON("/admin/realms/"+realmName+"/keys", &realmKeys); err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		if realmKeys.Active["PS256"] != active {
			t.Errorf("%s: the active PS256 key is %s, want %s", stage, realmKeys.Active["PS256"], active)
		}
		for _, key := range realmKeys.Keys {
			if key.Algorithm == "RS256" && key.Status != "DISABLED" {
				t.Errorf("%s: an RS256 key %s is %s", stage, key.Kid, key.Status)
			}
		}
		var components []struct{ Name string }
		if err := a.getJSON("/admin/realms/"+realmName+"/components?type=org.keycloak.keys.KeyProvider", &components); err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		for _, component := range components {
			if strings.HasPrefix(component.Name, "fallback-") {
				t.Errorf("%s: the realm generated %s in-process", stage, component.Name)
			}
		}
	}

	c := internalClient(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil, http.StatusNoContent)
	})
	p := createPrincipal(t, a)
	t.Cleanup(func() {
		_, _ = a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil, http.StatusNoContent)
	})
	token := func(want string) string {
		t.Helper()
		access := passwordGrant(t, a, c, p).AccessToken
		if kid, _ := jwtHeader(t, access)["kid"].(string); kid != want {
			t.Errorf("a new token carries kid %s, want %s", kid, want)
		}
		return access
	}
	verifies := func(token string) error {
		kid, _ := jwtHeader(t, token)["kid"].(string)
		public, err := realmKey(a, kid)
		if err != nil {
			return err
		}
		return verifyWith(public, token)
	}
	// gone reads the keys directory as root, because the keystores' directory is the kernel user's alone
	// (mode 0500): the runner's passwordless sudo, which only this CI job uses.
	gone := func(kid string) {
		t.Helper()
		for _, path := range []string{"signing/realm-signing-" + kid + ".p12", "realm-signing-" + kid + ".crt"} {
			if exec.Command("sudo", "-n", "test", "-e", filepath.Join(keys, path)).Run() == nil {
				t.Errorf("%s is still in the keys directory", path)
			}
		}
	}

	// The first key: realm-apply made it active on the empty realm. It is registered and its activation
	// recorded as it stands.
	first := certificateKid(t, "KERNEL_SIGNING_CERTIFICATE")
	published("the first key", []string{first}, first)
	step(0, "stage", first, generator, witness, "the first key", ticket)
	approve(first, "activate")
	step(0, "activate", first, operator)
	beforeRotation := token(first)

	// staged: published, signing nothing.
	second := ceremony()
	step(0, "stage", second, generator, witness, "scheduled rotation", ticket)
	stagedAt := time.Now()
	published("staged", []string{first, second}, first)
	token(first)

	// active, after the cache window; the first key retiring.
	step(2, "activate", second, operator) // no approval yet
	approve(second, "activate")
	if time.Since(stagedAt) < cache {
		step(2, "activate", second, operator) // before the cache window
	}
	time.Sleep(time.Until(stagedAt.Add(cache + time.Second)))
	step(0, "activate", second, operator)
	retiringSince := time.Now()
	published("active, the first key retiring", []string{first, second}, second)
	afterRotation := token(second)
	if err := verifies(beforeRotation); err != nil {
		t.Errorf("overlap: a token the retiring key signed does not verify against the key set: %v", err)
	}

	// retired, after the retirement window, and not before.
	approve(first, "retire")
	if time.Since(retiringSince) < retirement {
		step(2, "retire", first, operator)
		published("retiring, before its window", []string{first, second}, second)
	}
	time.Sleep(time.Until(retiringSince.Add(retirement + time.Second)))
	step(0, "retire", first, operator)
	published("retired", []string{second}, second)
	if err := verifies(beforeRotation); err == nil {
		t.Error("retired: a token the retired key signed still verifies against the key set")
	}
	gone(first)

	// abandoned: a staged key that never signed leaves at once.
	third := ceremony()
	step(0, "stage", third, generator, witness, "a key not needed", ticket)
	published("staged, to abandon", []string{second, third}, second)
	approve(third, "abandon")
	step(0, "abandon", third, operator)
	published("abandoned", []string{second}, second)
	gone(third)

	// revoked: the active key is compromised. A replacement is activated at once, which demotes it, and
	// it is revoked.
	fourth := ceremony()
	step(0, "stage", fourth, generator, witness, "compromise of "+second, ticket)
	step(2, "revoke", second, operator) // the active key is never revoked first
	approve(fourth, "activate", "--emergency")
	step(0, "activate", fourth, operator) // at once: no cache window after a compromise
	published("the replacement active, the compromised key retiring", []string{second, fourth}, fourth)
	approve(second, "revoke")
	step(0, "revoke", second, operator)
	published("revoked", []string{fourth}, fourth)
	token(fourth)
	if err := verifies(afterRotation); err == nil {
		t.Error("revoked: a token the revoked key signed still verifies against the key set")
	}
	gone(second)

	states := registered()
	for kid, want := range map[string]string{first: "retired", second: "revoked", third: "retired", fourth: "active"} {
		if states[kid] != want {
			t.Errorf("the registry has %s %s, want %s", kid, states[kid], want)
		}
	}
	summary, _ := json.Marshal(states)
	t.Logf("the five states, through the steps: %s", summary)
	publish(t, fmt.Sprintf("### Rotation through the five states\n\nThe ceremony and the rotation steps took four "+
		"keys through `staged`, `active`, `retiring`, `retired` and `revoked`, with identity-control's registry "+
		"holding each approval and transition. Old tokens verified through the overlap, new tokens carried the "+
		"new `kid`, and each key left the key set at its retirement, abandonment or revocation alone. Registry: "+
		"`%s`.\n", summary))
}

// certificateKid reads a certificate named by an environment variable and returns its RFC 7638 kid.
func certificateKid(t *testing.T, variable string) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(variable))
	if path == "" {
		t.Fatalf("%s is unset", variable)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := realmdef.SigningKeyID(content)
	if err != nil {
		t.Fatalf("%s: %v", variable, err)
	}
	return kid
}

type publishedKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// publishedKeySet reads the realm's key set as a consumer does.
func publishedKeySet(t *testing.T, a *admin) []publishedKey {
	t.Helper()
	response, err := a.http.Get(a.realmURL("/certs"))
	if err != nil {
		t.Fatalf("GET certs: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var set struct {
		Keys []publishedKey `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&set); err != nil {
		t.Fatalf("decoding certs: %v", err)
	}
	return set.Keys
}
