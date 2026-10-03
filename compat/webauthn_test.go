package compat

// A software WebAuthn authenticator, so the compat suite can answer the kernel's WebAuthn pages the
// way a browser and a security key would: a P-256 key pair, a "none" attestation, and assertions
// signed over the authenticator data and the client data's hash (W3C Web Authentication Level 2,
// §6.1 authenticator data, §6.5.4 "none" attestation, §6.3.3 assertion signature).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// The kernel's pages write these as FreeMarker ${challenge?c}, a JavaScript string literal.
var (
	scriptChallenge = regexp.MustCompile(`challenge\s*:\s*["']([^"']+)["']`)
	scriptRPID      = regexp.MustCompile(`rpId\s*:\s*["']([^"']*)["']`)
)

type softKey struct {
	private      *ecdsa.PrivateKey
	credentialID []byte
	counter      uint32
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softKey{private: private, credentialID: id}
}

var b64 = base64.RawURLEncoding

func clientData(kind, challenge, origin string) []byte {
	data, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return data
}

// authData is rpIdHash | flags | signCount, plus the attested credential for a registration.
func (k *softKey) authData(rpID string, attested bool) []byte {
	hash := sha256.Sum256([]byte(rpID))
	flags := byte(0x01 | 0x04) // user present, user verified
	if attested {
		flags |= 0x40
	}
	k.counter++
	out := append([]byte{}, hash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, k.counter)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID: none
		out = binary.BigEndian.AppendUint16(out, uint16(len(k.credentialID)))
		out = append(out, k.credentialID...)
		out = append(out, k.coseKey()...)
	}
	return out
}

// coseKey is the public key as a COSE_Key: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
func (k *softKey) coseKey() []byte {
	x := k.private.PublicKey.X.FillBytes(make([]byte, 32))
	y := k.private.PublicKey.Y.FillBytes(make([]byte, 32))
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, y...)
}

// cborBytes is a CBOR byte string header and its content.
func cborBytes(b []byte) []byte {
	switch {
	case len(b) < 24:
		return append([]byte{0x40 | byte(len(b))}, b...)
	case len(b) < 256:
		return append([]byte{0x58, byte(len(b))}, b...)
	default:
		return append([]byte{0x59, byte(len(b) >> 8), byte(len(b))}, b...)
	}
}

// relyingParty is the rpId the page names, or, when it names none, the host of the origin (W3C Web
// Authentication Level 2, §5.4.2: the RP ID defaults to the origin's effective domain).
func relyingParty(t *testing.T, page, origin string) (challenge, rpID string) {
	t.Helper()
	c, r := scriptChallenge.FindStringSubmatch(page), scriptRPID.FindStringSubmatch(page)
	if c == nil {
		at := strings.Index(page, "challenge")
		t.Fatalf("the WebAuthn page names no challenge: %q", page[max(at, 0):min(max(at, 0)+200, len(page))])
	}
	if r != nil && r[1] != "" {
		return c[1], r[1]
	}
	u, _ := url.Parse(origin)
	return c[1], u.Hostname()
}

// register answers the kernel's registration page.
func (k *softKey) register(t *testing.T, page, origin string, form url.Values) {
	t.Helper()
	challenge, rpID := relyingParty(t, page, origin)
	attestation := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0,
		0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'}
	attestation = append(attestation, cborBytes(k.authData(rpID, true))...)
	form.Set("clientDataJSON", b64.EncodeToString(clientData("webauthn.create", challenge, origin)))
	form.Set("attestationObject", b64.EncodeToString(attestation))
	form.Set("publicKeyCredentialId", b64.EncodeToString(k.credentialID))
	form.Set("authenticatorLabel", "compat-key")
	form.Set("transports", "usb")
	form.Set("authenticatorAttachment", "cross-platform")
	form.Set("error", "")
}

// assert answers the kernel's authentication page.
func (k *softKey) assert(t *testing.T, page, origin string, form url.Values) {
	t.Helper()
	challenge, rpID := relyingParty(t, page, origin)
	data := clientData("webauthn.get", challenge, origin)
	authData := k.authData(rpID, false)
	digest := sha256.Sum256(data)
	signed := sha256.Sum256(append(append([]byte{}, authData...), digest[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, k.private, signed[:])
	if err != nil {
		t.Fatal(err)
	}
	form.Set("clientDataJSON", b64.EncodeToString(data))
	form.Set("authenticatorData", b64.EncodeToString(authData))
	form.Set("signature", b64.EncodeToString(signature))
	form.Set("credentialId", b64.EncodeToString(k.credentialID))
	form.Set("userHandle", "")
	form.Set("error", "")
}
