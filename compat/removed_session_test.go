package compat

// A removed session stays removed, found by Organization Experience's stack proof: identity-control
// ended a person's session with DELETE /admin/realms/{realm}/sessions/{id}, the kernel stopped listing
// it, and the BFF's next refresh on it, four minutes later, was granted (organization-experience runs
// 37843816015 and 37846007225, on 26.7.5 started optimized on Postgres).
//
// The cause is in Keycloak's persistent user sessions (keycloak#51127): a session is held in the
// database and cached in memory. A delete removes the cache entry before its database delete commits.
// A request that reads the session in between finds the cache empty, loads the row the delete has not
// yet committed away, and puts it back into the cache. The database then has no session, so the Admin
// API lists none, while a refresh reads the cache first and finds it. The read can be anything that
// looks the session up: listing the user's sessions, UserInfo, a refresh.
//
// The test removes sessions while each of those reads runs against them, many times, and requires that
// no refresh is granted once the removal has answered. Online and offline sessions, removed by their
// identifier; and online sessions ended by a user logout, identity-control's containment. Each
// iteration signs in, waits 1 to 1.5 s (the age the stack proof's sessions had when they were
// removed), and removes the session; workers run in parallel so the iterations fit the job.
// REMOVED_SESSION_ITERATIONS sets the iterations per variant.
//
// TestTheKernelReadsSessionsFromTheDatabase asserts the setting that closes it: the kernel image turns
// the session cache off (TDD-identity-kernel-005 §Session Store), so there is no cache entry to restore.
// With it on, the pinned image refreshed 801 of 1,800 removed sessions (ROADMAP.md, A removed session
// refreshed).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The reads a removal races. Each is something a deployed estate does to a session while it is
// removed: identity-control lists a user's sessions to confirm a removal, an API introspects, a BFF
// calls UserInfo or refreshes.
const (
	readNothing = "nothing else reading"
	readListing = "the user's sessions listed during the removal"
	readInfo    = "UserInfo called during the removal"
	readRefresh = "a refresh sent with the removal"
)

type removalVariant struct {
	offline bool
	read    string
	// logout removes the session by logging the user out (POST /users/{id}/logout, identity-control's
	// containment) instead of deleting it by its identifier.
	logout bool
}

func (v removalVariant) String() string {
	switch {
	case v.logout:
		return "online, user logout, " + v.read
	case v.offline:
		return "offline, " + v.read
	default:
		return "online, " + v.read
	}
}

type removalTally struct {
	iterations atomic.Int64
	// granted: a refresh after the removal answered was accepted. The finding.
	granted atomic.Int64
	// unlisted: of those, the Admin API no longer listed the session: the database and the cache disagree.
	unlisted atomic.Int64
	// racedGranted: the refresh sent with the removal was accepted, which is legitimate when it ran
	// before the removal committed. Recorded only.
	racedGranted atomic.Int64
}

func TestARemovedSessionIsNotRefreshed(t *testing.T) {
	a := requireKeycloak(t)
	c := internalClient(t, a)
	t.Cleanup(func() {
		if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/clients/"+c.uuid, nil,
			http.StatusNoContent); err != nil {
			t.Errorf("deleting client %s: %v", c.id, err)
		}
	})
	attachOptionalScope(t, a, c.uuid, "offline_access")

	variants := []removalVariant{
		{false, readNothing, false}, {false, readListing, false}, {false, readInfo, false},
		{false, readRefresh, false}, {true, readNothing, false}, {true, readListing, false}, {true, readInfo, false},
		{true, readRefresh, false}, {false, readListing, true}, {false, readInfo, true},
	}
	perVariant := 30
	if v, err := strconv.Atoi(os.Getenv("REMOVED_SESSION_ITERATIONS")); err == nil && v > 0 {
		perVariant = v
	}
	const workers = 8

	tallies := make([]*removalTally, len(variants))
	for i := range tallies {
		tallies[i] = &removalTally{}
	}
	type job struct{ variant, index int }
	jobs := make(chan job)
	var failures sync.Map
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		p := createPrincipal(t, a)
		t.Cleanup(func() {
			if _, err := a.call(http.MethodDelete, "/admin/realms/"+realmName+"/users/"+p.userID, nil,
				http.StatusNoContent); err != nil {
				t.Errorf("deleting user %s: %v", p.username, err)
			}
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if err := removeOnce(a, c, p, variants[j.variant], j.index, tallies[j.variant]); err != nil {
					failures.LoadOrStore(variants[j.variant].String(), err.Error())
				}
			}
		}()
	}
	started := time.Now()
	// Interleaved, so every variant meets the same load.
	for i := 0; i < perVariant; i++ {
		for v := range variants {
			jobs <- job{v, i}
		}
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(started)

	failures.Range(func(variant, err any) bool {
		t.Errorf("%s: the iteration could not run: %s", variant, err)
		return true
	})

	var b strings.Builder
	fmt.Fprintf(&b, "## A removed session is not refreshed\n\n")
	fmt.Fprintf(&b, "Image: `%s`; session cache: %s\n\n", imageRef(), sessionCacheSetting(t, a))
	fmt.Fprintf(&b, "%d iterations per variant, %d workers, %s. Each signs in, waits 1 to 1.5 s, removes "+
		"the session through the Admin API, and refreshes once the removal has answered.\n\n",
		perVariant, workers, elapsed.Round(time.Second))
	fmt.Fprintf(&b, "| Variant | Iterations | Refresh granted after the removal | Of those, not listed | "+
		"Refresh sent with the removal granted (recorded) |\n| :-- | --: | --: | --: | --: |\n")
	total, granted := int64(0), int64(0)
	for i, v := range variants {
		tally := tallies[i]
		total += tally.iterations.Load()
		granted += tally.granted.Load()
		raced := "—"
		if v.read == readRefresh {
			raced = strconv.FormatInt(tally.racedGranted.Load(), 10)
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %s |\n", v, tally.iterations.Load(), tally.granted.Load(),
			tally.unlisted.Load(), raced)
		if tally.granted.Load() > 0 {
			t.Errorf("%s: %d of %d removed sessions were refreshed after the removal answered",
				v, tally.granted.Load(), tally.iterations.Load())
		}
	}
	if granted > 0 {
		fmt.Fprintf(&b, "\n**Outcome:** %d of %d removed sessions were refreshed after their removal answered "+
			"(keycloak#51127).\n", granted, total)
	} else {
		fmt.Fprintf(&b, "\n**Outcome:** none of %d removed sessions was refreshed after its removal answered.\n", total)
	}
	publish(t, b.String())
}

// removeOnce signs p in, removes the session while v's read runs against it, and refreshes.
func removeOnce(a *admin, c client, p principal, v removalVariant, index int, tally *removalTally) error {
	scope := "openid"
	if v.offline {
		scope = "openid offline_access"
	}
	status, body := postToken(a, url.Values{
		"grant_type": {"password"}, "client_id": {c.id}, "client_secret": {c.secret},
		"username": {p.username}, "password": {p.password}, "scope": {scope},
	})
	var tokens issuedTokens
	if err := json.Unmarshal(body, &tokens); err != nil || status != http.StatusOK || tokens.RefreshToken == "" {
		return fmt.Errorf("signing in answered %d: %s", status, snippet(string(body)))
	}
	claims, err := decodeClaims(tokens.AccessToken)
	if err != nil {
		return err
	}
	sid, _ := claims["sid"].(string)
	if sid == "" {
		return fmt.Errorf("the access token carries no sid")
	}
	if v.offline {
		refresh, err := decodeClaims(tokens.RefreshToken)
		if err != nil {
			return err
		}
		if refresh["typ"] != "Offline" {
			return fmt.Errorf("an offline_access sign-in returned a %v refresh token: the user holds no "+
				"offline_access role or the client no offline_access scope", refresh["typ"])
		}
	}
	token, err := adminBearer(a)
	if err != nil {
		return err
	}

	// 1.0 to 1.5 s after the sign-in, in 37 ms steps across iterations.
	delay := time.Duration(1000+(index*37)%500) * time.Millisecond
	const lead = 150 * time.Millisecond
	time.Sleep(delay - lead)

	stop := make(chan struct{})
	var readers sync.WaitGroup
	latestRefresh := tokens.RefreshToken
	var racedMu sync.Mutex
	switch v.read {
	case readListing, readInfo:
		for r := 0; r < 4; r++ {
			readers.Add(1)
			go func() {
				defer readers.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					if v.read == readListing {
						_, _ = listedSessions(a, token, p, c, v.offline)
					} else {
						_ = userInfoStatus(a, tokens.AccessToken)
					}
				}
			}()
		}
		time.Sleep(lead)
	case readRefresh:
		time.Sleep(lead)
		readers.Add(1)
		go func() {
			defer readers.Done()
			status, body := postToken(a, url.Values{
				"grant_type": {"refresh_token"}, "client_id": {c.id}, "client_secret": {c.secret},
				"refresh_token": {tokens.RefreshToken},
			})
			if status == http.StatusOK {
				var out issuedTokens
				if json.Unmarshal(body, &out) == nil && out.RefreshToken != "" {
					racedMu.Lock()
					latestRefresh = out.RefreshToken
					racedMu.Unlock()
				}
				tally.racedGranted.Add(1)
			}
		}()
	default:
		time.Sleep(lead)
	}

	path := "/admin/realms/" + realmName + "/sessions/" + url.PathEscape(sid)
	if v.offline {
		path += "?isOffline=true"
	}
	method := http.MethodDelete
	if v.logout {
		method, path = http.MethodPost, "/admin/realms/"+realmName+"/users/"+p.userID+"/logout"
	}
	deleteStatus, deleteBody := adminRequest(a, token, method, path)
	if v.read != readRefresh {
		time.Sleep(lead)
	}
	close(stop)
	readers.Wait()
	if deleteStatus != http.StatusNoContent {
		return fmt.Errorf("the delete answered %d: %s", deleteStatus, snippet(deleteBody))
	}
	tally.iterations.Add(1)

	racedMu.Lock()
	refreshToken := latestRefresh
	racedMu.Unlock()
	status, _ = postToken(a, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {c.id}, "client_secret": {c.secret},
		"refresh_token": {refreshToken},
	})
	if status != http.StatusOK {
		return nil
	}
	tally.granted.Add(1)
	if ids, err := listedSessions(a, token, p, c, v.offline); err == nil && !containsString(ids, sid) {
		tally.unlisted.Add(1)
	}
	// What the refresh found lives in memory only; removing it again keeps it from outliving the test.
	adminRequest(a, token, method, path)
	return nil
}

// TestTheKernelReadsSessionsFromTheDatabase asserts the session store setting the kernel image makes
// (TDD-identity-kernel-005 §Session Store): persistent user sessions on, their cache off.
func TestTheKernelReadsSessionsFromTheDatabase(t *testing.T) {
	a := requireKeycloak(t)
	if got := sessionCacheSetting(t, a); got != "off" {
		t.Errorf("the user session cache is %s; the kernel image turns it off (KC_SPI_USER_SESSIONS__INFINISPAN__USE_CACHES=false)", got)
	}
}

// sessionCacheSetting reads the user session provider's useCaches from the server info: "on", "off",
// or what was found instead.
func sessionCacheSetting(t *testing.T, a *admin) string {
	t.Helper()
	var info struct {
		Providers map[string]struct {
			Providers map[string]struct {
				OperationalInfo map[string]string `json:"operationalInfo"`
			} `json:"providers"`
		} `json:"providers"`
	}
	if err := a.getJSON("/admin/serverinfo", &info); err != nil {
		return "unreadable: " + err.Error()
	}
	provider, ok := info.Providers["userSessions"].Providers["infinispan"]
	if !ok {
		return "not reported (no infinispan user session provider)"
	}
	switch provider.OperationalInfo["useCaches"] {
	case "true":
		return "on"
	case "false":
		return "off"
	default:
		return fmt.Sprintf("not reported (%v)", provider.OperationalInfo)
	}
}

// adminBearer is one administrator token, reused for the iteration's requests: the shared client
// signs in to the master realm per call, which under this test's concurrency would itself be load.
func adminBearer(a *admin) (string, error) {
	response, err := a.http.PostForm(a.base+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {envOr("KEYCLOAK_ADMIN_USER", "admin")}, "password": {envOr("KEYCLOAK_ADMIN_PASSWORD", "admin")},
	})
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("the master realm returned no administrator token (%d)", response.StatusCode)
	}
	return out.AccessToken, nil
}

func adminRequest(a *admin, token, method, path string) (int, string) {
	request, err := http.NewRequest(method, a.base+path, nil)
	if err != nil {
		return 0, err.Error()
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := a.http.Do(request)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

// listedSessions is what identity-control reads back: the user's sessions, or its offline sessions
// for the client.
func listedSessions(a *admin, token string, p principal, c client, offline bool) ([]string, error) {
	path := "/admin/realms/" + realmName + "/users/" + p.userID + "/sessions"
	if offline {
		path = "/admin/realms/" + realmName + "/users/" + p.userID + "/offline-sessions/" + c.uuid
	}
	status, body := adminRequest(a, token, http.MethodGet, path)
	if status != http.StatusOK {
		return nil, fmt.Errorf("listing answered %d", status)
	}
	var list []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(list))
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	return ids, nil
}

func userInfoStatus(a *admin, accessToken string) int {
	request, _ := http.NewRequest(http.MethodGet, a.realmURL("/userinfo"), nil)
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := a.http.Do(request)
	if err != nil {
		return 0
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

// postToken is tokenRequest without the testing.T, for the workers.
func postToken(a *admin, form url.Values) (int, []byte) {
	response, err := a.http.PostForm(a.realmURL("/token"), form)
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, body
}

func decodeClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("a token that is not a JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	return claims, json.Unmarshal(payload, &claims)
}

func containsString(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
