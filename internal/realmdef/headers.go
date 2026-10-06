package realmdef

import (
	"fmt"
	"strconv"
	"strings"
)

// The browser security headers of the hosted login pages (STD-IAM-001 2.4.0 §3.9,
// TDD-identity-kernel-004 §Browser Security). Keycloak sends the realm's browserSecurityHeaders on
// every HTML page the realm renders, so the definition declares every header, and Parse refuses one
// that would weaken what the standard fixes: no framing by any origin, nothing loaded from another
// origin, no form-action, and the transport headers.

// fixedHeaders are the headers whose value the standard fixes.
var fixedHeaders = map[string]string{
	"xFrameOptions":       "DENY",
	"xContentTypeOptions": "nosniff",
	"referrerPolicy":      "no-referrer",
}

// minHSTSMaxAge is one year, the max-age STD-IAM-001 §3.9 sets.
const minHSTSMaxAge = 31536000

// requiredDirectives are the directives whose value the standard fixes.
var requiredDirectives = map[string]string{
	"default-src":     "'self'",
	"frame-ancestors": "'none'",
	"object-src":      "'none'",
	"base-uri":        "'none'",
}

// allowedSources are the source expressions a directive may name: the kernel's own origin, none,
// and inline code, the recorded gap until the kernel ships template nonces. data: is allowed for
// images alone, where the one-time-code enrolment page renders its QR code.
var allowedSources = map[string]bool{"'self'": true, "'none'": true, "'unsafe-inline'": true}

func (d Definition) validateBrowserHeaders() error {
	headers, ok := d.Realm["browserSecurityHeaders"].(map[string]any)
	if !ok {
		return fmt.Errorf("scnehaux.json declares no browserSecurityHeaders; Keycloak's defaults allow " +
			"same-origin framing and set no source policy (STD-IAM-001 §3.9)")
	}
	value := func(key string) string {
		v, _ := headers[key].(string)
		return v
	}
	for key, want := range fixedHeaders {
		if got := value(key); got != want {
			return fmt.Errorf("scnehaux.json sets browserSecurityHeaders.%s to %q, want %q (STD-IAM-001 §3.9)",
				key, got, want)
		}
	}
	if err := validateHSTS(value("strictTransportSecurity")); err != nil {
		return err
	}
	return validateCSP(value("contentSecurityPolicy"))
}

func validateHSTS(header string) error {
	maxAge, includesSubdomains := int64(-1), false
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if v, found := strings.CutPrefix(strings.ToLower(part), "max-age="); found {
			maxAge, _ = strconv.ParseInt(v, 10, 64)
		}
		if strings.EqualFold(part, "includeSubDomains") {
			includesSubdomains = true
		}
	}
	if maxAge < minHSTSMaxAge || !includesSubdomains {
		return fmt.Errorf("scnehaux.json sets browserSecurityHeaders.strictTransportSecurity to %q; it needs "+
			"max-age of at least %d and includeSubDomains (STD-IAM-001 §3.9)", header, minHSTSMaxAge)
	}
	return nil
}

// ParseCSP splits a policy into its directives, each named once, as Keycloak's own builder reads it.
func ParseCSP(policy string) map[string][]string {
	directives := map[string][]string{}
	for _, directive := range strings.Split(policy, ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		directives[name] = append(directives[name], fields[1:]...)
	}
	return directives
}

func validateCSP(policy string) error {
	directives := ParseCSP(policy)
	for name, want := range requiredDirectives {
		if got := strings.Join(directives[name], " "); got != want {
			return fmt.Errorf("scnehaux.json sets %s to %q in the login pages' policy, want %q (STD-IAM-001 §3.9)",
				name, got, want)
		}
	}
	if _, present := directives["form-action"]; present {
		return fmt.Errorf("scnehaux.json sets form-action in the login pages' policy; Chrome applies it to " +
			"the redirect back to the client after sign-in (STD-IAM-001 §3.9)")
	}
	for name, sources := range directives {
		for _, source := range sources {
			if allowedSources[source] || (name == "img-src" && source == "data:") {
				continue
			}
			return fmt.Errorf("scnehaux.json names %s in %s of the login pages' policy; the pages load nothing "+
				"from another origin and run no eval (STD-IAM-001 §3.9)", source, name)
		}
	}
	return nil
}
