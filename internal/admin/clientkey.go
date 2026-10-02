package admin

// A confidential client authenticates with a key pair it holds, never a shared secret
// (ADR-IAM-001 §5.12, STD-IAM-001 §3.2). This file is that half: the private key a service account
// keeps, the RFC 7523 assertion it signs with it, and the public JWK the kernel is given.
//
// The key identifier is the key's RFC 7638 thumbprint, computed from the key itself. So a deployable
// is configured with one file, its private key, and nothing that has to agree with it: the kid the
// assertion names and the kid registered on the client are the same function of the same key.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// MinClientKeyBits is the smallest RSA modulus a client key may have: the floor STD-IAM-002 §3.2.2
// sets for signing keys, which STD-IAM-001 §3.2 applies to client keys.
const MinClientKeyBits = 3072

// ClientAssertionType is the RFC 7523 client assertion type the token endpoint is told.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// assertionLifetime bounds how long a signed assertion is accepted. Keycloak refuses one presented
// twice, so the window only has to cover the request that carries it.
const assertionLifetime = time.Minute

// ClientKey is a client's private key and the identifier its public half is registered under.
type ClientKey struct {
	ID      string
	Private *rsa.PrivateKey
}

// NewClientKey generates a client key of MinClientKeyBits.
func NewClientKey() (ClientKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, MinClientKeyBits)
	if err != nil {
		return ClientKey{}, fmt.Errorf("admin: generating a client key: %w", err)
	}
	return ClientKey{ID: Thumbprint(&private.PublicKey), Private: private}, nil
}

// ParseClientKey reads an RSA private key in PKCS#8 or PKCS#1 PEM and refuses one below
// MinClientKeyBits.
func ParseClientKey(pemBytes []byte) (ClientKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return ClientKey{}, errors.New("admin: the client key is not PEM")
	}
	var private *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return ClientKey{}, fmt.Errorf("admin: the client key is not a PKCS#8 key: %w", err)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return ClientKey{}, errors.New("admin: the client key is not an RSA key")
		}
		private = rsaKey
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return ClientKey{}, fmt.Errorf("admin: the client key is not a PKCS#1 key: %w", err)
		}
		private = parsed
	default:
		return ClientKey{}, fmt.Errorf("admin: a %q PEM block is not a private key", block.Type)
	}
	if bits := private.N.BitLen(); bits < MinClientKeyBits {
		return ClientKey{}, fmt.Errorf("admin: the client key is %d bits; at least %d are required", bits, MinClientKeyBits)
	}
	return ClientKey{ID: Thumbprint(&private.PublicKey), Private: private}, nil
}

// PEM encodes the private key as PKCS#8, the form ParseClientKey reads back.
func (k ClientKey) PEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return nil, fmt.Errorf("admin: encoding the client key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// JWK is a public key as the kernel registers it on a client.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// PublicJWK is the public half, and only the public half.
func (k ClientKey) PublicJWK() JWK {
	return JWK{Kty: "RSA", Kid: k.ID, Use: "sig", Alg: "PS256",
		N: b64(k.Private.N.Bytes()), E: b64(big.NewInt(int64(k.Private.E)).Bytes())}
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of an RSA public key: the hash of its required
// members in lexicographic order, with no whitespace.
func Thumbprint(public *rsa.PublicKey) string {
	canonical := `{"e":"` + b64(big.NewInt(int64(public.E)).Bytes()) + `","kty":"RSA","n":"` + b64(public.N.Bytes()) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

// ClientAssertion signs an RFC 7523 client assertion: the client names itself as issuer and
// subject, the realm's issuer is the audience, and a fresh jti makes it single-use.
func (k ClientKey) ClientAssertion(clientID, audience string, now time.Time) (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("admin: minting a jti: %w", err)
	}
	header, err := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "kid": k.ID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"jti": b64(nonce[:]),
		"iat": now.Unix(),
		"exp": now.Add(assertionLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPSS(rand.Reader, k.Private, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", fmt.Errorf("admin: signing the client assertion: %w", err)
	}
	return input + "." + b64(signature), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
