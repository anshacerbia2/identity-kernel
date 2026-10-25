// Command signing-key does the kernel's half of each realm signing key step (TDD-identity-kernel-002
// 1.5.0 §Rotation as Built, ADR-IAM-002 §5.5). scripts/signing-key-rotation.sh runs it, between the
// registry's check and its record (identity-control's identity-signing-key), and never alone.
//
//	signing-key place     -keys /keys                    the ceremony's new keystore, named by its kid (root)
//	signing-key jwk       -certificate FILE.crt           the key's public JWK, for the registry
//	signing-key stage     -kid KID                        its provider, enabled and passive
//	signing-key activate  -kid KID                        active, above every other key; then the others demoted
//	signing-key remove    -kid KID                        its provider removed: the key leaves the key set
//	signing-key destroy   -keys /keys -kid KID            its keystore, password and certificate removed (root)
//	signing-key providers                                 each provider's kid and state, as JSON lines
//	signing-key windows   -environment ENV                the cache and retirement windows the steps wait
//
// The realm commands read the definition (-definition) and reach the Admin API (-url) with the
// credentials realm-apply uses (KEYCLOAK_ADMIN_*), and check the invariants after they act, against the
// certificates in -certificates.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
	"github.com/anshacerbia2/identity-kernel/internal/realmdef"
)

const usage = "usage: signing-key place|jwk|stage|activate|remove|destroy|providers|windows [flags]"

// The kernel's user and group, which own the keystores and their passwords (TDD-identity-kernel-002
// §Custody as Built).
const (
	kernelUID = 1000
	kernelGID = 0
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 1
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	keys := flags.String("keys", "/keys", "the keys directory")
	realm := flags.String("realm", "scnehaux", "the realm, for the vault file's name")
	certificate := flags.String("certificate", "", "jwk: the key's certificate")
	kid := flags.String("kid", "", "the key's kid")
	definition := flags.String("definition", "/repo/realm", "the realm definition")
	defaultURL := os.Getenv("KEYCLOAK_URL")
	if defaultURL == "" {
		defaultURL = "http://keycloak:8080"
	}
	baseURL := flags.String("url", defaultURL, "the kernel (default $KEYCLOAK_URL, else http://keycloak:8080)")
	certificates := flags.String("certificates", "/keys", "the certificates in custody, for the invariants")
	environment := flags.String("environment", "", "windows: local, ci or development")
	if err := flags.Parse(args[1:]); err != nil {
		return 1
	}
	if err := dispatch(args[0], *keys, *realm, *certificate, *kid, *definition, *baseURL, *certificates,
		*environment, stdout); err != nil {
		fmt.Fprintf(stderr, "signing-key %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func dispatch(command, keys, realm, certificate, kid, definition, baseURL, certificates, environment string,
	stdout io.Writer) error {
	switch command {
	case "place":
		placed, err := place(keys, realm)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, placed)
		return nil
	case "jwk":
		content, err := os.ReadFile(certificate)
		if err != nil {
			return err
		}
		jwk, err := realmdef.PublicJWK(content)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(jwk))
		return nil
	case "destroy":
		evidence, err := destroy(keys, realm, kid)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, evidence)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d, err := realmdef.Load(definition)
	if err != nil {
		return err
	}
	credentials, err := admin.CredentialsFromEnv()
	if err != nil {
		return err
	}
	c, err := admin.New(baseURL, nil, credentials)
	if err != nil {
		return err
	}
	custody, err := realmdef.ReadCustody(certificates)
	if err != nil {
		return err
	}
	verify := func(want string) error {
		active, err := realmdef.VerifySigningKey(ctx, c, d, custody)
		if err != nil {
			return err
		}
		if want != "" && active != want {
			return fmt.Errorf("the realm's active key is %s, want %s", active, want)
		}
		return nil
	}
	needKid := func() error {
		if kid == "" {
			return errors.New("-kid is required")
		}
		return nil
	}

	switch command {
	case "stage":
		if err := needKid(); err != nil {
			return err
		}
		if _, held := custody[kid]; !held {
			return fmt.Errorf("%s is not in custody: no %s.crt in %s", kid, realmdef.SigningKeyName(kid), certificates)
		}
		if err := realmdef.StageSigningKey(ctx, c, d, kid); err != nil {
			return err
		}
		return verify("")
	case "activate":
		if err := needKid(); err != nil {
			return err
		}
		demoted, err := realmdef.ActivateSigningKey(ctx, c, d, kid)
		for _, other := range demoted {
			fmt.Fprintf(stdout, "demoted %s\n", other)
		}
		if err != nil {
			return err
		}
		return verify(kid)
	case "remove":
		if err := needKid(); err != nil {
			return err
		}
		if err := realmdef.RemoveSigningKey(ctx, c, d, kid); err != nil {
			return err
		}
		delete(custody, kid)
		return verifyWithout(ctx, c, d, custody, kid)
	case "providers":
		providers, err := realmdef.SigningProviders(ctx, c, d)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(stdout)
		for _, provider := range providers {
			state := "passive"
			if provider.Active {
				state = "active"
			}
			if err := encoder.Encode(map[string]string{"kid": provider.Kid, "state": state}); err != nil {
				return err
			}
		}
		return nil
	case "windows":
		env, err := realmdef.ParseEnvironment(environment)
		if err != nil {
			return err
		}
		if _, err := realmdef.VerifyRetirementWindow(ctx, c, d); err != nil {
			return err
		}
		windows, err := realmdef.StepWindows(env, os.Getenv)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "cache=%s retirement=%s\n", windows.Cache, windows.Retirement)
		return nil
	}
	return errors.New(usage)
}

// verifyWithout checks the invariants after a removal, and that the key is out of the key set. The
// key's certificate is still on disk until destroy, so custody is given without it.
func verifyWithout(ctx context.Context, c *admin.Client, d realmdef.Definition, custody map[string]string,
	kid string) error {
	providers, err := realmdef.SigningProviders(ctx, c, d)
	if err != nil {
		return err
	}
	for _, provider := range providers {
		if provider.Kid == kid {
			return fmt.Errorf("the provider of %s is still in the realm", kid)
		}
	}
	_, err = realmdef.VerifySigningKey(ctx, c, d, custody)
	return err
}

// vaultFile is a vault secret's file name: the realm, an underscore, and the secret's name, each with
// its underscores doubled (Keycloak's REALM_UNDERSCORE_KEY resolver).
func vaultFile(realm, secret string) string {
	return strings.ReplaceAll(realm, "_", "__") + "_" + strings.ReplaceAll(secret, "_", "__")
}

// place moves the keystore the ceremony's generator wrote under keys/new into place, named by its kid
// (ADR-IAM-002 §5.5 Q3), owned by the kernel's user and readable by it alone. It refuses to replace
// anything: a kid is placed once.
func place(keys, realm string) (string, error) {
	staging := filepath.Join(keys, "new")
	content, err := os.ReadFile(filepath.Join(staging, "certificate.pem"))
	if err != nil {
		return "", fmt.Errorf("the generator's certificate: %w", err)
	}
	kid, err := realmdef.SigningKeyID(content)
	if err != nil {
		return "", err
	}
	keyName := realmdef.SigningKeyName(kid)
	targets := []struct{ from, to string }{
		{filepath.Join(staging, "keystore.p12"), filepath.Join(keys, "signing", keyName+".p12")},
		{filepath.Join(staging, "password"), filepath.Join(keys, "vault", vaultFile(realm, keyName))},
		{filepath.Join(staging, "certificate.pem"), filepath.Join(keys, keyName+".crt")},
	}
	for _, target := range targets {
		if _, err := os.Lstat(target.to); err == nil {
			return "", fmt.Errorf("%s exists; a kid is placed once", target.to)
		}
	}
	for _, dir := range []string{filepath.Join(keys, "signing"), filepath.Join(keys, "vault")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", err
		}
	}
	for i, target := range targets {
		if err := os.Rename(target.from, target.to); err != nil {
			return "", err
		}
		mode, owned := os.FileMode(0o400), true
		if i == 2 {
			mode, owned = 0o644, false
		}
		if err := os.Chmod(target.to, mode); err != nil {
			return "", err
		}
		if owned {
			if err := os.Chown(target.to, kernelUID, kernelGID); err != nil {
				return "", err
			}
		}
	}
	for _, dir := range []string{filepath.Join(keys, "signing"), filepath.Join(keys, "vault")} {
		if err := os.Chown(dir, kernelUID, kernelGID); err != nil {
			return "", err
		}
		if err := os.Chmod(dir, 0o500); err != nil {
			return "", err
		}
	}
	if err := os.Remove(staging); err != nil {
		return "", err
	}
	return kid, nil
}

// destroy removes a key's keystore, password and certificate from the development keys directory, and
// reads that each is gone (ADR-IAM-002 §5.5 Q8, development server). It prints the evidence the
// registry records. The ceremony's record stays: it holds no secret.
func destroy(keys, realm, kid string) (string, error) {
	if kid == "" {
		return "", errors.New("-kid is required")
	}
	keyName := realmdef.SigningKeyName(kid)
	paths := []string{
		filepath.Join(keys, "signing", keyName+".p12"),
		filepath.Join(keys, "vault", vaultFile(realm, keyName)),
		filepath.Join(keys, keyName+".crt"),
	}
	for _, dir := range []string{filepath.Join(keys, "signing"), filepath.Join(keys, "vault")} {
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", err
		}
	}
	var removed []string
	for _, path := range paths {
		err := os.Remove(path)
		switch {
		case err == nil:
			removed = append(removed, filepath.Base(path))
		case !errors.Is(err, os.ErrNotExist):
			return "", err
		}
	}
	for _, dir := range []string{filepath.Join(keys, "signing"), filepath.Join(keys, "vault")} {
		if err := os.Chmod(dir, 0o500); err != nil {
			return "", err
		}
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%s is still there", path)
		}
	}
	return fmt.Sprintf("development keys directory, %s: removed %s; read back absent", time.Now().UTC().Format(time.RFC3339),
		strings.Join(removed, ", ")), nil
}
