package authn

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// jwksServer serves a public key exactly as priompt-auth's /jwks endpoint does
// — same renderer, so the test cannot drift from the real document.
func jwksServer(t *testing.T, kid string, pub ed25519.PublicKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(JWKSJSON(pub, kid))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestMintVerifyRoundTrip closes the loop the split repos could never test: a
// token minted by the issuer, published through the real JWKS renderer, and
// verified by the consumer — all three halves of the contract in one place.
func TestMintVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	kid := KeyID(pub)
	srv := jwksServer(t, kid, pub)

	want := Claims{Sub: "ci-bot", Org: "acme", RW: true, Iss: "priompt-auth",
		Iat: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix()}
	got, err := NewKeySet(srv.URL).Verify(MintJWT(priv, kid, want))
	if err != nil {
		t.Fatalf("minted token must verify against its own JWKS: %v", err)
	}
	if got != want {
		t.Errorf("claims must survive the round trip: got %+v want %+v", got, want)
	}
}

func TestJWKSJSON(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	var doc struct {
		Keys []struct{ Kty, Crv, Kid, X string }
	}
	if err := json.Unmarshal(JWKSJSON(pub, KeyID(pub)), &doc); err != nil || len(doc.Keys) != 1 {
		t.Fatalf("bad jwks: %v", err)
	}
	k := doc.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid != KeyID(pub) {
		t.Errorf("wrong jwks header fields: %+v", k)
	}
	x, _ := base64.RawURLEncoding.DecodeString(k.X)
	if !ed25519.PublicKey(x).Equal(pub) {
		t.Error("jwks must carry the signing public key")
	}
}

func TestVerifyJWT(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, "k1", pub)
	ks := NewKeySet(srv.URL)

	good := MintJWT(priv, "k1", Claims{Sub: "ci-bot", Org: "acme", RW: true, Exp: time.Now().Add(time.Hour).Unix()})
	c, err := ks.Verify(good)
	if err != nil || c.Org != "acme" || !c.RW {
		t.Fatalf("good token should verify with claims, got %+v err=%v", c, err)
	}

	if _, err := ks.Verify(MintJWT(priv, "k1", Claims{Exp: time.Now().Add(-time.Minute).Unix()})); err == nil {
		t.Error("expired token must fail")
	}
	if _, err := ks.Verify(MintJWT(priv, "k1", Claims{})); err == nil {
		t.Error("token without exp must fail")
	}

	_, otherPriv, _ := ed25519.GenerateKey(nil)
	if _, err := ks.Verify(MintJWT(otherPriv, "k1", Claims{Exp: time.Now().Add(time.Hour).Unix()})); err == nil {
		t.Error("wrong-key signature must fail")
	}
	if _, err := ks.Verify(MintJWT(priv, "unknown-kid", Claims{Exp: time.Now().Add(time.Hour).Unix()})); err == nil {
		t.Error("unknown kid must fail (refresh is rate-limited within the same test)")
	}
	if _, err := ks.Verify("not-a-jwt"); err == nil {
		t.Error("garbage must fail")
	}
}

// TestInterceptorJWT wires the JWT path through the real interceptor: a static
// map miss falls through to JWKS verification, and the claims land as scope.
func TestInterceptorJWT(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := jwksServer(t, "k1", pub)
	chain := Interceptor(NewStatic(map[string]Token{"static": {Org: "legacy"}}), NewJWKS(srv.URL))

	jwt := MintJWT(priv, "k1", Claims{Sub: "ci-bot", Org: "acme", RW: false, Exp: time.Now().Add(time.Hour).Unix()})
	if ok, scope, w := run(chain, "Bearer "+jwt); !ok || scope != "acme" || w {
		t.Errorf("JWT should pass scoped to acme read-only, got ok=%v scope=%q write=%v", ok, scope, w)
	}
	if ok, scope, _ := run(chain, "Bearer static"); !ok || scope != "legacy" {
		t.Errorf("static token must keep working alongside JWTs, got ok=%v scope=%q", ok, scope)
	}
	if ok, _, _ := run(chain, "Bearer bad.jwt.token"); ok {
		t.Error("malformed JWT must be rejected")
	}
}

// TestIdentityExpires: both providers report when the credential lapses, so a
// connection that authenticated once (a NATS subscriber) can be closed then.
func TestIdentityExpires(t *testing.T) {
	ctx := context.Background()
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	id, err := NewStatic(map[string]Token{"t1": {Org: "acme", Expires: exp}, "t2": {}}).Authenticate(ctx, "Bearer t1")
	if err != nil || !id.Expires.Equal(exp) {
		t.Fatalf("static: Expires = %v err=%v, want %v", id.Expires, err, exp)
	}
	if id, _ := NewStatic(map[string]Token{"t2": {}}).Authenticate(ctx, "Bearer t2"); !id.Expires.IsZero() {
		t.Fatalf("static without expiry: Expires = %v, want zero", id.Expires)
	}

	pub, priv, _ := ed25519.GenerateKey(nil)
	p := JWKSProvider{Keys: NewKeySet(jwksServer(t, "k1", pub).URL)}
	id, err = p.Authenticate(ctx, "Bearer "+MintJWT(priv, "k1", Claims{Org: "acme", Exp: exp.Unix()}))
	if err != nil || !id.Expires.Equal(exp) {
		t.Fatalf("jwt: Expires = %v err=%v, want %v", id.Expires, err, exp)
	}
}
