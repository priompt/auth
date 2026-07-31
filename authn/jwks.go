package authn

// The priompt-auth token format, both halves in one place: MintJWT signs a
// compact EdDSA JWT, JWKSJSON publishes the public key, and KeySet.Verify
// checks a token against a served key set. Issuer and verifier sitting in one
// package is the point — they cannot drift, and the round trip is testable.
//
// The claims contract itself is defined once in the shared proto repo
// (priomptproto/claims), so the wire payload is the same struct on both sides.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"priomptproto/claims"
)

// Claims is the payload of a priompt-auth JWT — the shared contract.
type Claims = claims.Claims

// KeyID derives a stable short identifier from the public key, so rotation is
// just "new key file, new kid" with both keys served in the JWKS while old
// tokens drain.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:8]
}

func b64(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // marshaling our own structs cannot fail
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// MintJWT signs a compact EdDSA JWT.
func MintJWT(priv ed25519.PrivateKey, kid string, c Claims) string {
	h := b64(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	p := b64(c)
	sig := ed25519.Sign(priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// JWKSJSON renders the public key(s) as an RFC 7517 key set — what the core
// server's -auth-jwks-url consumes.
func JWKSJSON(pub ed25519.PublicKey, kid string) []byte {
	return []byte(fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":%q,"x":%q}]}`,
		kid, base64.RawURLEncoding.EncodeToString(pub)))
}

// KeySet caches the Ed25519 public keys of a priompt-auth /jwks endpoint.
type KeySet struct {
	url    string
	client *http.Client

	mu      sync.Mutex
	keys    map[string]ed25519.PublicKey // kid -> key
	fetched time.Time
}

// refreshInterval is the minimum time between JWKS re-fetches, so a flood of
// bad-kid tokens cannot hammer the auth service.
const refreshInterval = 30 * time.Second

// NewKeySet points at a priompt-auth /jwks URL. The first fetch happens lazily
// on first use (and retries on unknown kid), so the server starts fine even if
// the auth service is briefly down.
func NewKeySet(url string) *KeySet {
	return &KeySet{url: url, client: &http.Client{Timeout: 5 * time.Second}, keys: map[string]ed25519.PublicKey{}}
}

// jwks is the wire shape of the /jwks document (RFC 7517, OKP/Ed25519 keys).
type jwks struct {
	Keys []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Kid string `json:"kid"`
		X   string `json:"x"`
	} `json:"keys"`
}

// key returns the public key for kid, re-fetching the JWKS (rate-limited) when
// the kid is unknown — the rotation path.
func (k *KeySet) key(kid string) (ed25519.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if pub, ok := k.keys[kid]; ok {
		return pub, nil
	}
	if time.Since(k.fetched) < refreshInterval {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	k.fetched = time.Now()
	resp, err := k.client.Get(k.url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: %s", resp.Status)
	}
	var doc jwks
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	for _, jk := range doc.Keys {
		if jk.Kty != "OKP" || jk.Crv != "Ed25519" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(jk.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		k.keys[jk.Kid] = ed25519.PublicKey(raw)
	}
	if pub, ok := k.keys[kid]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

// Verify checks an EdDSA compact JWT and returns its claims. It enforces the
// signature, the EdDSA algorithm, and a present, unexpired exp.
func (k *KeySet) Verify(raw string) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("not a compact JWT")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, err
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return Claims{}, err
	}
	if header.Alg != "EdDSA" {
		return Claims{}, fmt.Errorf("unsupported alg %q", header.Alg)
	}
	pub, err := k.key(header.Kid)
	if err != nil {
		return Claims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, err
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, errors.New("bad signature")
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Unmarshal(cb, &c); err != nil {
		return Claims{}, err
	}
	if c.Exp == 0 {
		return Claims{}, errors.New("missing exp")
	}
	if time.Now().Unix() > c.Exp {
		return Claims{}, errors.New("token expired")
	}
	return c, nil
}
