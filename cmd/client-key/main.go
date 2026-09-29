// Command client-key makes and installs the key pairs confidential clients authenticate with
// (ADR-IAM-001 §5.12, STD-IAM-001 §3.2). It serves the clients a bootstrap script creates, before
// identity-control can register them: identity-control's own Admin API clients, the development
// caller, the BFFs, and realm-apply's service account.
//
//	client-key new -out keys/realm-apply.pem
//	client-key install -url http://keycloak:8080 -realm master -client realm-apply -jwk keys/realm-apply.jwk.json
//
// new writes the private key (PKCS#8 PEM, mode 0600) and, beside it, the public JWK. Only the JWK
// ever leaves the host that made the key. install sets the client to authenticate by signed JWT
// with exactly the keys given: two during a rotation, one otherwise. It then regenerates the
// client's secret without printing it, so a secret the client held before is useless even if the
// authenticator is switched back in the console. install takes the administrator from the
// environment, as realm-apply does.
package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anshacerbia2/identity-kernel/internal/admin"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: client-key new -out FILE.pem | client-key install -url URL -realm REALM -client ID -jwk FILE [-jwk FILE]")
		return 1
	}
	var err error
	switch args[0] {
	case "new":
		err = newKey(args[1:], stdout, stderr)
	case "install":
		err = install(args[1:], stdout, stderr)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintf(stderr, "client-key: %v\n", err)
		return 1
	}
	return 0
}

func newKey(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("client-key new", flag.ContinueOnError)
	flags.SetOutput(stderr)
	out := flags.String("out", "", "where to write the private key; the public JWK is written beside it as NAME.jwk.json")
	owner := flags.String("owner", "", "UID:GID to own the private key, the user of the container that reads it")
	if err := flags.Parse(args); err != nil {
		return err
	}
	uid, gid := -1, -1
	if *owner != "" {
		if _, err := fmt.Sscanf(*owner, "%d:%d", &uid, &gid); err != nil {
			return fmt.Errorf("-owner %q is not UID:GID", *owner)
		}
	}
	if !strings.HasSuffix(*out, ".pem") {
		return errors.New("-out must name a .pem file")
	}
	key, err := admin.NewClientKey()
	if err != nil {
		return err
	}
	private, err := key.PEM()
	if err != nil {
		return err
	}
	// O_EXCL: an existing key is never overwritten. Replacing a key is a rotation, which installs
	// the new one beside the old one first.
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("writing the private key: %w", err)
	}
	if _, err := file.Write(private); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// The key stays mode 0600, readable by its owner alone: the container user that signs with it.
	if uid >= 0 {
		if err := os.Chown(*out, uid, gid); err != nil {
			return fmt.Errorf("giving the private key to %s: %w", *owner, err)
		}
	}
	public, err := json.MarshalIndent(key.PublicJWK(), "", "  ")
	if err != nil {
		return err
	}
	jwkPath := strings.TrimSuffix(*out, ".pem") + ".jwk.json"
	if err := os.WriteFile(jwkPath, append(public, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing the public JWK: %w", err)
	}
	fmt.Fprintf(stdout, "private key %s (keep it on this host)\npublic JWK  %s\nkid         %s\n",
		*out, jwkPath, key.ID)
	return nil
}

type jwkFiles []string

func (f *jwkFiles) String() string     { return strings.Join(*f, ",") }
func (f *jwkFiles) Set(v string) error { *f = append(*f, v); return nil }

func install(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("client-key install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("url", os.Getenv("KEYCLOAK_URL"), "Keycloak base URL (default $KEYCLOAK_URL)")
	realm := flags.String("realm", "", "the realm the client is in")
	clientID := flags.String("client", "", "the client's clientId")
	var files jwkFiles
	flags.Var(&files, "jwk", "a public JWK file; give two during a rotation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *realm == "" || *clientID == "" || len(files) == 0 || len(files) > 2 {
		return errors.New("install needs -realm, -client, and one or two -jwk files")
	}
	keys := make([]map[string]any, 0, len(files))
	for _, path := range files {
		key, err := readPublicJWK(path)
		if err != nil {
			return err
		}
		keys = append(keys, key)
	}
	jwks, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return err
	}

	credentials, err := admin.CredentialsFromEnv()
	if err != nil {
		return err
	}
	client, err := admin.New(*baseURL, &http.Client{Timeout: 20 * time.Second}, credentials)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var found []map[string]any
	query := url.Values{"clientId": {*clientID}}
	if err := client.GetJSON(ctx, "/admin/realms/"+url.PathEscape(*realm)+"/clients?"+query.Encode(), &found); err != nil {
		return err
	}
	if len(found) != 1 {
		return fmt.Errorf("realm %s has no client %s", *realm, *clientID)
	}
	uuid, _ := found[0]["id"].(string)
	path := "/admin/realms/" + url.PathEscape(*realm) + "/clients/" + uuid
	var representation map[string]any
	if err := client.GetJSON(ctx, path, &representation); err != nil {
		return err
	}
	if public, _ := representation["publicClient"].(bool); public {
		return fmt.Errorf("%s is a public client; a public client holds no key", *clientID)
	}
	attributes, _ := representation["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	attributes["token.endpoint.auth.signing.alg"] = "PS256"
	attributes["use.jwks.url"] = "false"
	attributes["use.jwks.string"] = "true"
	attributes["jwks.string"] = string(jwks)
	representation["attributes"] = attributes
	representation["clientAuthenticatorType"] = "client-jwt"
	if _, err := client.Call(ctx, http.MethodPut, path, representation, http.StatusNoContent); err != nil {
		return err
	}
	// The response carries the new secret. It is discarded: nothing uses it, and a secret the
	// client held before this run stops working.
	if _, err := client.Call(ctx, http.MethodPost, path+"/client-secret", nil, http.StatusOK); err != nil {
		return fmt.Errorf("the keys are installed, but the old secret was not regenerated: %w", err)
	}
	kids := make([]string, 0, len(keys))
	for _, key := range keys {
		kids = append(kids, key["kid"].(string))
	}
	fmt.Fprintf(stdout, "%s in realm %s now authenticates by signed JWT with %s\n", *clientID, *realm, strings.Join(kids, " and "))
	return nil
}

// readPublicJWK accepts an RSA public JWK only: at least 3072 bits, no private member, and a kid
// equal to its RFC 7638 thumbprint, so the kid the assertion names is the kid registered.
func readPublicJWK(path string) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var key map[string]any
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, fmt.Errorf("%s is not a JWK: %w", path, err)
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := key[private]; ok {
			return nil, fmt.Errorf("%s carries private member %q; install takes the public JWK only, and that key is now exposed", path, private)
		}
	}
	n, _ := key["n"].(string)
	e, _ := key["e"].(string)
	kid, _ := key["kid"].(string)
	if key["kty"] != "RSA" || n == "" || e == "" {
		return nil, fmt.Errorf("%s is not an RSA public JWK", path)
	}
	modulus, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("%s: n is not base64url", path)
	}
	exponent, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("%s: e is not base64url", path)
	}
	public := publicKey(modulus, exponent)
	if bits := public.N.BitLen(); bits < admin.MinClientKeyBits {
		return nil, fmt.Errorf("%s is %d bits; at least %d are required", path, bits, admin.MinClientKeyBits)
	}
	if want := admin.Thumbprint(public); kid != want {
		return nil, fmt.Errorf("%s has kid %q; its RFC 7638 thumbprint is %q", path, kid, want)
	}
	return map[string]any{"kty": "RSA", "kid": kid, "use": "sig", "alg": "PS256", "n": n, "e": e}, nil
}

// publicKey builds the RSA public key a JWK's n and e describe.
func publicKey(modulus, exponent []byte) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(new(big.Int).SetBytes(exponent).Int64())}
}
