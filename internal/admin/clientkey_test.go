package admin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestAClientKeyRoundTripsThroughPEM(t *testing.T) {
	key, err := NewClientKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := key.PEM()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseClientKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != key.ID || parsed.Private.N.Cmp(key.Private.N) != 0 {
		t.Error("a key read back from its PEM is not the same key")
	}
}

func TestAShortOrForeignKeyIsRefused(t *testing.T) {
	short, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(short)
	if _, err := ParseClientKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Error("a 2048-bit key was accepted")
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0}})
	if _, err := ParseClientKey(public); err == nil {
		t.Error("a public key block was accepted as a private key")
	}
}

// The RFC 7638 example: the thumbprint of the RFC 7517 appendix A.1 key.
func TestTheThumbprintIsRFC7638(t *testing.T) {
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP" +
		"ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMic" +
		"AtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPks" +
		"INHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	modulus, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		t.Fatal(err)
	}
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: 65537}
	if got, want := Thumbprint(public), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Errorf("thumbprint %s, want %s", got, want)
	}
}

func TestAnAssertionIsASignedSingleUseClaimSet(t *testing.T) {
	key, err := NewClientKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	first, err := key.ClientAssertion("realm-apply", "https://kc.example/realms/master", now)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := key.ClientAssertion("realm-apply", "https://kc.example/realms/master", now)

	parts := strings.Split(first, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWT: %d parts", len(parts))
	}
	var header map[string]string
	var claims map[string]any
	decode(t, parts[0], &header)
	decode(t, parts[1], &claims)
	if header["alg"] != "PS256" || header["kid"] != key.ID {
		t.Errorf("header %v", header)
	}
	if claims["iss"] != "realm-apply" || claims["sub"] != "realm-apply" ||
		claims["aud"] != "https://kc.example/realms/master" || claims["exp"].(float64)-claims["iat"].(float64) != 60 {
		t.Errorf("claims %v", claims)
	}
	var again map[string]any
	decode(t, strings.Split(second, ".")[1], &again)
	if again["jti"] == claims["jti"] {
		t.Error("two assertions carry the same jti")
	}

	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPSS(&key.Private.PublicKey, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Errorf("the assertion does not verify with the public key: %v", err)
	}
}

func TestThePublicJWKCarriesNoPrivateMember(t *testing.T) {
	key, err := NewClientKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(key.PublicJWK())
	var members map[string]any
	_ = json.Unmarshal(raw, &members)
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := members[private]; ok {
			t.Errorf("the public JWK carries %q", private)
		}
	}
	if members["kid"] != key.ID || members["alg"] != "PS256" {
		t.Errorf("JWK %v", members)
	}
}

func decode(t *testing.T, segment string, into any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}
