package main

// OIDC token exchange: an enterprise IdP (Okta, Azure AD, Google…) issues an
// RS256 ID token; we verify it against the IdP's published JWKS and map the
// caller's groups to a Priompt org scope. We do NOT host a login flow — the
// enterprise already has one; we only consume its result.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type idp struct {
	issuer   string
	audience string // "" = don't check aud
	jwksURI  string
	client   *http.Client

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// newIDP discovers the issuer's JWKS endpoint via OIDC discovery. Fails fast:
// a misconfigured issuer should stop `serve`, not surface per-request.
func newIDP(issuer, audience string) (*idp, error) {
	i := &idp{issuer: issuer, audience: audience,
		client: &http.Client{Timeout: 5 * time.Second}, keys: map[string]*rsa.PublicKey{}}
	resp, err := i.client.Get(strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("issuer %s: discovery document has no jwks_uri", issuer)
	}
	i.jwksURI = doc.JWKSURI
	return i, nil
}

// key returns the RSA key for kid, re-fetching the IdP JWKS (rate-limited) when
// unknown — IdPs rotate keys routinely.
func (i *idp) key(kid string) (*rsa.PublicKey, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if k, ok := i.keys[kid]; ok {
		return k, nil
	}
	if time.Since(i.fetched) < 30*time.Second {
		return nil, fmt.Errorf("unknown IdP key id %q", kid)
	}
	i.fetched = time.Now()
	resp, err := i.client.Get(i.jwksURI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	for _, jk := range doc.Keys {
		if jk.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(jk.N)
		e, err2 := base64.RawURLEncoding.DecodeString(jk.E)
		if err1 != nil || err2 != nil {
			continue
		}
		i.keys[jk.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if k, ok := i.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown IdP key id %q", kid)
}

// verify checks an RS256 ID token (signature, issuer, expiry, optional
// audience) and returns the subject and group memberships.
func (i *idp) verify(raw string) (sub string, groups []string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", nil, errors.New("not a compact JWT")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, err
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return "", nil, err
	}
	if header.Alg != "RS256" {
		return "", nil, fmt.Errorf("unsupported IdP alg %q", header.Alg)
	}
	pub, err := i.key(header.Kid)
	if err != nil {
		return "", nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return "", nil, errors.New("bad IdP signature")
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, err
	}
	var c struct {
		Sub    string          `json:"sub"`
		Iss    string          `json:"iss"`
		Aud    json.RawMessage `json:"aud"` // string or []string per spec
		Exp    int64           `json:"exp"`
		Groups []string        `json:"groups"`
	}
	if err := json.Unmarshal(cb, &c); err != nil {
		return "", nil, err
	}
	if c.Iss != i.issuer {
		return "", nil, fmt.Errorf("issuer mismatch: %q", c.Iss)
	}
	if c.Exp == 0 || time.Now().Unix() > c.Exp {
		return "", nil, errors.New("ID token expired")
	}
	if i.audience != "" && !audContains(c.Aud, i.audience) {
		return "", nil, errors.New("audience mismatch")
	}
	return c.Sub, c.Groups, nil
}

// audContains handles aud as either a JSON string or an array of strings.
func audContains(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}
