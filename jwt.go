package main

// Compact EdDSA JWT minting — the issuing half of the claims contract whose
// verifying half lives in the core server's internal/auth package:
//
//	header: {"alg":"EdDSA","typ":"JWT","kid":"<key id>"}
//	claims: sub (who), org ("" = admin, all orgs), rw (bool, may write),
//	        exp/iat (unix seconds, exp always set — tokens are short-lived),
//	        iss ("priompt-auth")
//
// Change the contract in both repos together.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Claims is the payload of an issued token.
type Claims struct {
	Sub string `json:"sub"`
	Org string `json:"org"`
	RW  bool   `json:"rw"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Iss string `json:"iss"`
}

// keyID derives a stable short identifier from the public key, so rotation is
// just "new key file, new kid" with both keys served in the JWKS while old
// tokens drain.
func keyID(pub ed25519.PublicKey) string {
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

// mintJWT signs a compact EdDSA JWT.
func mintJWT(priv ed25519.PrivateKey, kid string, c Claims) string {
	h := b64(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	p := b64(c)
	sig := ed25519.Sign(priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksJSON renders the public key(s) as an RFC 7517 key set — what the core
// server's -auth-jwks-url consumes.
func jwksJSON(pub ed25519.PublicKey, kid string) []byte {
	return []byte(fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":%q,"x":%q}]}`,
		kid, base64.RawURLEncoding.EncodeToString(pub)))
}
