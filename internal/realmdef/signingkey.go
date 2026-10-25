package realmdef

// The realm signing keys, each loaded from a keystore the kernel never generates
// (TDD-identity-kernel-002 1.5.0 §Custody as Built and §Rotation as Built, ADR-IAM-002 §5.3 and §5.5).
//
// Each key is one keystore, one vault password and one java-keystore provider, all named by the
// key's kid, its RFC 7638 thumbprint (ADR-IAM-002 §5.5 Q3): realm-signing-<kid>. realm/signing-key.json
// is the template every provider is created from, with {kid} where the kid goes.
//
// The rotation steps own the providers (ADR-IAM-002 §5.5 Q4). realm-apply never changes or removes
// one that exists. It creates the first, active, from the one keystore in custody, only when the realm
// has none, and every run checks the invariants: exactly one active PS256 key; every key the realm
// publishes is a custody key served by its own provider under its own thumbprint; and no other key,
// so no fallback-PS256 and no RS256 key.
//
// Two facts about the pinned release shape this:
//
//   - A provider's kid is a configuration value it is created with. JavaKeystoreKeyProviderFactory
//     .validateConfiguration puts a random identifier there when none is given, so a provider is always
//     created with the certificate's thumbprint. Keycloak leaves the value out of every representation
//     it returns and ignores it on an update, so an update cannot rebind it.
//   - With no active PS256 key, the next token makes Keycloak generate one, fallback-PS256
//     (DefaultKeyManager.getActiveKey). So an activation makes the new key active before it demotes the
//     old one, and no step removes the active key.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
)

// SigningAlgorithm is the one algorithm the realm signs with (ADR-IAM-002 §5.1).
const SigningAlgorithm = "PS256"

// minimumModulus is ADR-IAM-002 §5.1's floor, which foundation-platform's verifier also holds.
const minimumModulus = 3072

// SigningKeyPrefix begins every signing key's name: its provider, keystore, vault secret and
// certificate are SigningKeyPrefix + kid (ADR-IAM-002 §5.5 Q3).
const SigningKeyPrefix = "realm-signing-"

// KidPlaceholder is where realm/signing-key.json takes the kid.
const KidPlaceholder = "{kid}"

// SigningKeyName is a key's name: its provider, its keystore without .p12, its vault secret and its
// certificate without .crt.
func SigningKeyName(kid string) string { return SigningKeyPrefix + kid }

// stagedPriority is a staged key's priority. Passive keys never sign, so it only has to be a number;
// an activation raises the key above every other.
const stagedPriority = 100

// SigningKeyID returns the kid of the key a certificate carries: the RFC 7638 thumbprint of its RSA
// public key. The certificate is the public half of a keystore the ceremony made
// (scripts/signing-key-ceremony.sh); nothing secret is read.
func SigningKeyID(certificatePEM []byte) (string, error) {
	public, err := certificateKey(certificatePEM)
	if err != nil {
		return "", err
	}
	return admin.Thumbprint(public), nil
}

func certificateKey(certificatePEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the signing certificate is not a PEM CERTIFICATE")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the signing certificate: %w", err)
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the signing certificate does not carry an RSA key")
	}
	if public.N.BitLen() < minimumModulus {
		return nil, fmt.Errorf("the signing certificate carries a %d-bit key; ADR-IAM-002 §5.1 requires at least %d",
			public.N.BitLen(), minimumModulus)
	}
	return public, nil
}

// ReadCustody returns the keys in custody, by kid: each realm-signing-<kid>.crt in dir, the public half
// of a keystore the ceremony made. A certificate whose name is not its own kid is refused.
func ReadCustody(dir string) (map[string]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, SigningKeyPrefix+"*.crt"))
	if err != nil {
		return nil, err
	}
	custody := map[string]string{}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		kid, err := SigningKeyID(content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if filepath.Base(path) != SigningKeyName(kid)+".crt" {
			return nil, fmt.Errorf("%s carries the key %s, so its name is not its kid", path, kid)
		}
		custody[kid] = path
	}
	return custody, nil
}

// RenderSigningKey is the provider for one key, from the template: the kid in its name, keystore and
// vault references, and the kid itself in its configuration.
func RenderSigningKey(template map[string]any, kid string) map[string]any {
	rendered := render(template, kid).(map[string]any)
	config, _ := rendered["config"].(map[string]any)
	if config == nil {
		config = map[string]any{}
	}
	config["kid"] = []any{kid}
	rendered["config"] = config
	return rendered
}

func render(value any, kid string) any {
	switch v := value.(type) {
	case string:
		return strings.ReplaceAll(v, KidPlaceholder, kid)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = render(item, kid)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = render(item, kid)
		}
		return out
	}
	return value
}

// realmKey is one entry of GET /admin/realms/{realm}/keys.
type realmKey struct {
	Kid              string `json:"kid"`
	ProviderID       string `json:"providerId"`
	ProviderPriority int64  `json:"providerPriority"`
	Algorithm        string `json:"algorithm"`
	Type             string `json:"type"`
	Status           string `json:"status"`
	PublicKey        string `json:"publicKey"`
}

// SigningProvider is one key's provider, as the realm holds it.
type SigningProvider struct {
	ID       string
	Name     string
	Kid      string
	Active   bool
	Enabled  bool
	Priority int64
	raw      map[string]any
}

// isSigningProvider says whether a key provider is one of the realm's signing keys.
func isSigningProvider(component map[string]any) bool {
	providerID, _ := component["providerId"].(string)
	return providerID == "java-keystore" && strings.HasPrefix(name(component), SigningKeyPrefix)
}

func signingProvider(component map[string]any) SigningProvider {
	config, _ := component["config"].(map[string]any)
	priority, _ := strconv.ParseInt(single(config["priority"]), 10, 64)
	id, _ := component["id"].(string)
	return SigningProvider{ID: id, Name: name(component), Kid: strings.TrimPrefix(name(component), SigningKeyPrefix),
		Active: single(config["active"]) != "false", Enabled: single(config["enabled"]) != "false", Priority: priority,
		raw: component}
}

func keyProviders(ctx context.Context, c *admin.Client, realm string) ([]map[string]any, error) {
	var components []map[string]any
	err := c.GetJSON(ctx, "/admin/realms/"+url.PathEscape(realm)+"/components?type="+
		url.QueryEscape("org.keycloak.keys.KeyProvider"), &components)
	if err != nil {
		return nil, fmt.Errorf("reading the key providers: %w", err)
	}
	return components, nil
}

// SigningProviders are the realm's signing key providers.
func SigningProviders(ctx context.Context, c *admin.Client, d Definition) ([]SigningProvider, error) {
	components, err := keyProviders(ctx, c, d.Name())
	if err != nil {
		return nil, err
	}
	var providers []SigningProvider
	for _, component := range components {
		if isSigningProvider(component) {
			providers = append(providers, signingProvider(component))
		}
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	return providers, nil
}

// VerifySigningKey checks ADR-IAM-002 §5.5 Q4's invariants against the live realm and returns the
// active key's kid. custody, when not nil, is the keys in custody by kid (ReadCustody): every key the
// realm publishes must be one of them.
func VerifySigningKey(ctx context.Context, c *admin.Client, d Definition, custody map[string]string) (string, error) {
	components, err := keyProviders(ctx, c, d.Name())
	if err != nil {
		return "", err
	}
	var keys struct {
		Active map[string]string `json:"active"`
		Keys   []realmKey        `json:"keys"`
	}
	if err := c.GetJSON(ctx, "/admin/realms/"+url.PathEscape(d.Name())+"/keys", &keys); err != nil {
		return "", fmt.Errorf("reading the realm's keys: %w", err)
	}
	return checkSigningKey(components, keys.Active, keys.Keys, custody)
}

func checkSigningKey(components []map[string]any, active map[string]string, keys []realmKey,
	custody map[string]string) (string, error) {
	providers := map[string]SigningProvider{}
	for _, component := range components {
		if isSigningProvider(component) {
			provider := signingProvider(component)
			providers[provider.ID] = provider
		}
	}
	if len(providers) == 0 {
		return "", errors.New("the realm has no signing key provider; realm-apply creates the first from the " +
			"keystore in custody")
	}
	served := map[string]int{}
	var others, published, actives []string
	activeKid := ""
	for _, key := range keys {
		provider, ours := providers[key.ProviderID]
		switch {
		case !ours && key.Algorithm == SigningAlgorithm:
			others = append(others, fmt.Sprintf("kid %s from provider %s (%s)", key.Kid, key.ProviderID, key.Status))
			continue
		case !ours:
			if key.PublicKey != "" && key.Status != "DISABLED" {
				// The key set publishes every enabled key with a public key (JWKSServerUtils.getRealmJwks).
				published = append(published, fmt.Sprintf("%s kid %s from provider %s (%s)", key.Algorithm,
					key.Kid, key.ProviderID, key.Status))
			}
			continue
		}
		served[key.ProviderID]++
		if err := checkProviderKey(provider, key, custody); err != nil {
			return "", err
		}
		if key.Status == "ACTIVE" {
			actives = append(actives, key.Kid)
			activeKid = key.Kid
		}
	}
	for id, provider := range providers {
		if served[id] != 1 {
			return "", fmt.Errorf("the signing key provider %s serves %d keys, want 1: its keystore did not load. "+
				"The kernel logs why; see docs/runbooks/custody-outage.md", provider.Name, served[id])
		}
	}
	sort.Strings(others)
	sort.Strings(published)
	switch {
	case len(others) > 0:
		return "", fmt.Errorf("the realm holds %s keys other than the custody keys: %s. A fallback-PS256 is a key "+
			"Keycloak generated in-process because no keystore loaded; see docs/runbooks/custody-outage.md",
			SigningAlgorithm, strings.Join(others, "; "))
	case len(published) > 0:
		return "", fmt.Errorf("the realm publishes keys other than the custody keys: %s. ADR-IAM-002 §5.1 allows "+
			"PS256 alone; a fallback-RS256 is a key Keycloak generated in-process for the legacy realm endpoint "+
			"(TDD-identity-kernel-002 §The Published Key Set)", strings.Join(published, "; "))
	case len(actives) != 1:
		return "", fmt.Errorf("the realm has %d active signing keys %v, want exactly one (ADR-IAM-002 §5.2)",
			len(actives), actives)
	case active[SigningAlgorithm] != activeKid:
		return "", fmt.Errorf("the realm's active %s key is %q, not its one active signing key %s",
			SigningAlgorithm, active[SigningAlgorithm], activeKid)
	}
	return activeKid, nil
}

func checkProviderKey(provider SigningProvider, key realmKey, custody map[string]string) error {
	if key.Algorithm != SigningAlgorithm || key.Type != "RSA" {
		return fmt.Errorf("the signing key provider %s serves a %s %s key, want RSA %s", provider.Name, key.Type,
			key.Algorithm, SigningAlgorithm)
	}
	if key.Status != "ACTIVE" && key.Status != "PASSIVE" {
		return fmt.Errorf("the signing key provider %s is %s; a key is active or passive, and leaves the key set "+
			"only by its provider's removal (TDD-identity-kernel-002 §Rotation as Built)", provider.Name, key.Status)
	}
	der, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		return fmt.Errorf("the realm's key %s has a public key that is not base64: %w", key.Kid, err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("parsing the realm's public key %s: %w", key.Kid, err)
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok || public.N.BitLen() < minimumModulus {
		return fmt.Errorf("the realm's key %s is not an RSA key of at least %d bits", key.Kid, minimumModulus)
	}
	if thumbprint := admin.Thumbprint(public); key.Kid != thumbprint {
		return fmt.Errorf("the realm signs under kid %s, and its key's RFC 7638 thumbprint is %s; "+
			"TDD-identity-kernel-002 §Key Identity requires them equal. The provider was created without its kid",
			key.Kid, thumbprint)
	}
	if provider.Kid != key.Kid {
		return fmt.Errorf("the signing key provider %s serves the key %s, so its name is not its kid", provider.Name,
			key.Kid)
	}
	if custody != nil {
		if _, held := custody[key.Kid]; !held {
			return fmt.Errorf("the realm publishes the key %s, which is not in custody: no %s.crt", key.Kid,
				SigningKeyName(key.Kid))
		}
	}
	return nil
}

// StageSigningKey creates a key's provider, enabled and passive: published, signing nothing
// (TDD-identity-kernel-002 §Rotation as Built). It is idempotent, and a provider that already exists
// is left alone, as the first key's, which realm-apply created active.
func StageSigningKey(ctx context.Context, c *admin.Client, d Definition, kid string) error {
	providers, err := SigningProviders(ctx, c, d)
	if err != nil {
		return err
	}
	for _, provider := range providers {
		if provider.Kid == kid {
			return nil
		}
	}
	var realm struct {
		ID string `json:"id"`
	}
	base := "/admin/realms/" + url.PathEscape(d.Name())
	if err := c.GetJSON(ctx, base, &realm); err != nil {
		return err
	}
	body := RenderSigningKey(d.Key, kid)
	body["parentId"] = realm.ID
	config := body["config"].(map[string]any)
	config["active"] = []any{"false"}
	config["priority"] = []any{strconv.Itoa(stagedPriority)}
	_, err = c.Call(ctx, http.MethodPost, base+"/components", body, http.StatusCreated)
	return err
}

func updateProvider(ctx context.Context, c *admin.Client, d Definition, provider SigningProvider,
	config map[string]any) error {
	body := overlay(provider.raw, map[string]any{"config": config})
	_, err := c.Call(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(d.Name())+"/components/"+
		url.PathEscape(provider.ID), body, http.StatusNoContent)
	return err
}

// ActivateSigningKey makes a staged key the active one and demotes every other active key: the new key
// first, above every other key's priority, so no moment has no active key (ADR-IAM-002 §5.5 Q4, Q7).
// It returns the kids it demoted. A key already active and alone, the first key, is left as it is.
func ActivateSigningKey(ctx context.Context, c *admin.Client, d Definition, kid string) ([]string, error) {
	providers, err := SigningProviders(ctx, c, d)
	if err != nil {
		return nil, err
	}
	var target *SigningProvider
	var highest int64
	var others []SigningProvider
	for i, provider := range providers {
		if provider.Priority > highest {
			highest = provider.Priority
		}
		if provider.Kid == kid {
			target = &providers[i]
		} else if provider.Active {
			others = append(others, provider)
		}
	}
	if target == nil {
		return nil, fmt.Errorf("the realm has no provider for %s; stage it first", kid)
	}
	if target.Active && len(others) == 0 {
		return nil, nil
	}
	if !target.Active || target.Priority < highest {
		if err := updateProvider(ctx, c, d, *target, map[string]any{"active": []any{"true"},
			"priority": []any{strconv.FormatInt(highest+100, 10)}}); err != nil {
			return nil, fmt.Errorf("activating %s: %w", kid, err)
		}
	}
	var demoted []string
	for _, other := range others {
		if err := updateProvider(ctx, c, d, other, map[string]any{"active": []any{"false"}}); err != nil {
			return demoted, fmt.Errorf("demoting %s after activating %s: %w", other.Kid, kid, err)
		}
		demoted = append(demoted, other.Kid)
	}
	return demoted, nil
}

// RemoveSigningKey removes a key's provider, which takes it out of the key set (ADR-IAM-002 §5.5 Q8
// step 1). It refuses the active key: a replacement is activated first. A provider already removed is
// not an error, so an interrupted step can run again.
func RemoveSigningKey(ctx context.Context, c *admin.Client, d Definition, kid string) error {
	providers, err := SigningProviders(ctx, c, d)
	if err != nil {
		return err
	}
	for _, provider := range providers {
		if provider.Kid != kid {
			continue
		}
		if provider.Active {
			return fmt.Errorf("%s is the active key; activate a replacement first (ADR-IAM-002 §5.5 Q7)", kid)
		}
		_, err := c.Call(ctx, http.MethodDelete, "/admin/realms/"+url.PathEscape(d.Name())+"/components/"+
			url.PathEscape(provider.ID), nil, http.StatusNoContent)
		return err
	}
	return nil
}

// validateSigningKey holds the provider template to ADR-IAM-002 §5.3 and §5.5 Q3: the java-keystore
// provider, signing PS256, named, stored and vaulted by the kid, alias realm-signing, both passwords
// vault references and never literal configuration, and no kid of its own, because the kid is the
// certificate's thumbprint, rendered at creation.
func (d Definition) validateSigningKey() error {
	if providerID, _ := d.Key["providerId"].(string); providerID != "java-keystore" {
		return fmt.Errorf("signing-key.json declares provider %q; the realm signs with a key loaded from a keystore, "+
			"java-keystore, never one Keycloak generates (ADR-IAM-002 §5.3)", providerID)
	}
	if name(d.Key) != SigningKeyName(KidPlaceholder) {
		return fmt.Errorf("signing-key.json names its provider %q; each key's provider is %s", name(d.Key),
			SigningKeyName(KidPlaceholder))
	}
	config, _ := d.Key["config"].(map[string]any)
	if _, declared := config["kid"]; declared {
		return errors.New("signing-key.json declares a kid; the kid is the RFC 7638 thumbprint of the keystore's " +
			"certificate, rendered when the provider is created")
	}
	if got := single(config["algorithm"]); got != SigningAlgorithm {
		return fmt.Errorf("signing-key.json signs %q; ADR-IAM-002 §5.1 requires %s", got, SigningAlgorithm)
	}
	if got := single(config["keystore"]); got != SigningKeyName(KidPlaceholder)+".p12" {
		return fmt.Errorf("signing-key.json reads the keystore %q; each key's keystore is %s.p12", got,
			SigningKeyName(KidPlaceholder))
	}
	if got := single(config["keyAlias"]); got != "realm-signing" {
		return fmt.Errorf("signing-key.json reads the alias %q; every keystore holds its one pair as realm-signing "+
			"(ADR-IAM-002 §5.5 Q3)", got)
	}
	for _, field := range []string{"keystorePassword", "keyPassword"} {
		if value := single(config[field]); value != "${vault."+SigningKeyName(KidPlaceholder)+"}" {
			return fmt.Errorf("signing-key.json sets %s to %q; it must be the key's vault reference, "+
				"${vault.%s} (ADR-IAM-002 §5.3)", field, value, SigningKeyName(KidPlaceholder))
		}
	}
	return nil
}

// validateKeyProviders holds every other declared key provider to ADR-IAM-002 §5.1, "the enterprise JWKS
// advertises PS256 keys only": each is declared disabled, so its key leaves the published key set.
func (d Definition) validateKeyProviders() error {
	for _, provider := range d.KeyProviders {
		config, _ := provider["config"].(map[string]any)
		if single(config["enabled"]) != "false" || single(config["active"]) != "false" {
			return fmt.Errorf("key-providers.json declares %s enabled or active; a key provider other than the "+
				"signing key is declared disabled, so the key set holds the custody keys alone (ADR-IAM-002 §5.1)",
				name(provider))
		}
	}
	return nil
}

// single reads a component configuration value, which Keycloak keeps as a list of strings.
func single(value any) string {
	switch v := value.(type) {
	case []any:
		if len(v) == 1 {
			s, _ := v[0].(string)
			return s
		}
	case []string:
		if len(v) == 1 {
			return v[0]
		}
	}
	return ""
}

// PublicJWK is a certificate's key as the key set publishes it, for the registry (identity-control's
// identity-signing-key stage): the public members, the kid, PS256 and sig.
func PublicJWK(certificatePEM []byte) ([]byte, error) {
	public, err := certificateKey(certificatePEM)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		"kid": admin.Thumbprint(public),
		"alg": SigningAlgorithm,
		"use": "sig",
	})
}
