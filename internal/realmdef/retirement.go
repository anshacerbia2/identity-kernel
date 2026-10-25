package realmdef

// The retirement window's floor, computed from the live realm (TDD-identity-kernel-002 1.4.0
// §Retirement Window, ADR-IAM-002 §5.2).
//
// A retiring key stays in the key set for at least the longest access token lifetime, plus the
// consumers' key-set cache, plus the clock-skew allowance. The design fixes the window at 7 days and
// requires the floor to be recomputed from the live token lifetimes rather than read as a constant, so
// a lifetime raised later cannot silently push the floor past the window. Every realm-apply run
// computes it and fails when it does.
//
// The live lifetimes are the realm's access token lifespan and every client's override of it, the
// attribute access.token.lifespan that identity-control sets from a client's lifetime class
// (STD-IAM-002 §3.3). A client with the implicit flow enabled also counts the realm's implicit-flow
// lifespan, the one Keycloak gives the tokens that flow issues.

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
)

const (
	// RetirementWindow is how long a retiring key stays in the key set: TDD-identity-kernel-002
	// §Configuration's operational default.
	RetirementWindow = 7 * 24 * time.Hour
	// ConsumerKeySetCache is the key-set cache lifetime the kernel gives its consumers
	// (TDD-identity-kernel-002 §Configuration).
	ConsumerKeySetCache = 10 * time.Minute
	// ClockSkewAllowance is TDD-identity-kernel-002 §Retirement Window's skew allowance.
	ClockSkewAllowance = 60 * time.Second
)

// Floor is the computed retirement floor and the lifetime that sets it.
type Floor struct {
	LongestAccessToken time.Duration
	// From names what sets the longest lifetime: the realm, or a client by its clientId.
	From  string
	Floor time.Duration
}

// retirementFloor computes the floor from a realm representation and its clients' representations.
func retirementFloor(realm map[string]any, clients []map[string]any) Floor {
	longest, from := seconds(realm["accessTokenLifespan"]), "the realm's accessTokenLifespan"
	consider := func(lifespan time.Duration, source string) {
		if lifespan > longest {
			longest, from = lifespan, source
		}
	}
	implicit := seconds(realm["accessTokenLifespanForImplicitFlow"])
	for _, client := range clients {
		clientID, _ := client["clientId"].(string)
		attributes, _ := client["attributes"].(map[string]any)
		if override := seconds(attributes["access.token.lifespan"]); override > 0 {
			consider(override, "client "+clientID+"'s access.token.lifespan")
		}
		if enabled, _ := client["implicitFlowEnabled"].(bool); enabled {
			consider(implicit, "the realm's accessTokenLifespanForImplicitFlow, for client "+clientID)
		}
	}
	return Floor{LongestAccessToken: longest, From: from,
		Floor: longest + ConsumerKeySetCache + ClockSkewAllowance}
}

// seconds reads a lifespan Keycloak gives in seconds, as a JSON number or, in a client attribute, a
// string. A missing, unparsable or non-positive value is no lifespan.
func seconds(value any) time.Duration {
	var n float64
	switch v := value.(type) {
	case float64:
		n = v
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0
		}
		n = parsed
	}
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// checkRetirementWindow fails when the floor exceeds the window (TDD-identity-kernel-002 §Testing
// Strategy, §Rotation: "a configuration that would shorten the window below its floor fails").
func checkRetirementWindow(f Floor, window time.Duration) error {
	if f.Floor > window {
		return fmt.Errorf("the retirement floor is %s (%s is %s, plus the %s key-set cache and %s of clock "+
			"skew), longer than the %s retirement window. A retiring key would leave the key set while tokens "+
			"it signed are still valid (TDD-identity-kernel-002 §Retirement Window)", f.Floor, f.From,
			f.LongestAccessToken, ConsumerKeySetCache, ClockSkewAllowance, window)
	}
	return nil
}

// VerifyRetirementWindow computes the floor from the live realm and its clients, and fails when it
// exceeds RetirementWindow.
func VerifyRetirementWindow(ctx context.Context, c *admin.Client, d Definition) (Floor, error) {
	base := "/admin/realms/" + url.PathEscape(d.Name())
	var realm map[string]any
	if err := c.GetJSON(ctx, base, &realm); err != nil {
		return Floor{}, fmt.Errorf("reading the realm's token lifespans: %w", err)
	}
	var clients []map[string]any
	const page = 100
	for first := 0; ; first += page {
		var batch []map[string]any
		if err := c.GetJSON(ctx, fmt.Sprintf("%s/clients?first=%d&max=%d", base, first, page), &batch); err != nil {
			return Floor{}, fmt.Errorf("reading the clients' token lifespans: %w", err)
		}
		clients = append(clients, batch...)
		if len(batch) < page {
			break
		}
	}
	f := retirementFloor(realm, clients)
	return f, checkRetirementWindow(f, RetirementWindow)
}

// Windows are how long a rotation step waits: a staged key for the consumer cache before it is
// activated, and a retiring key for the retirement window before it is retired (TDD-identity-kernel-002
// §Rotation, §Retirement Window).
type Windows struct {
	Cache      time.Duration
	Retirement time.Duration
}

// The two variables a test run may shorten the windows by.
const (
	CacheWindowVariable      = "SIGNING_KEY_CACHE_WINDOW"
	RetirementWindowVariable = "SIGNING_KEY_RETIREMENT_WINDOW"
)

// StepWindows returns the windows for an environment. Only a throwaway one, local or ci, may shorten
// them, so a proof runs in minutes rather than a week: nothing outside that run verifies its tokens
// (ADR-IAM-002 §5.3). Anywhere else a variable set is refused, never ignored.
func StepWindows(env Environment, getenv func(string) string) (Windows, error) {
	windows := Windows{Cache: ConsumerKeySetCache, Retirement: RetirementWindow}
	for _, w := range []struct {
		variable string
		into     *time.Duration
	}{{CacheWindowVariable, &windows.Cache}, {RetirementWindowVariable, &windows.Retirement}} {
		value := getenv(w.variable)
		if value == "" {
			continue
		}
		if env != Local && env != CI {
			return Windows{}, fmt.Errorf("%s is set in environment %s; only a throwaway environment, local or ci, "+
				"may shorten a rotation window", w.variable, env)
		}
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed < 0 {
			return Windows{}, fmt.Errorf("%s=%q is not a duration", w.variable, value)
		}
		*w.into = parsed
	}
	return windows, nil
}
