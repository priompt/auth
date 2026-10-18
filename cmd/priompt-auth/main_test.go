package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/priompt/auth/authn"
)

// b64 renders a value as a base64url JSON segment, for hand-building the fake
// IdP's RS256 tokens. (Issuing priompt-auth's own tokens is authn's job.)
func b64(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func testService(t *testing.T) (*service, *httptest.Server) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	secretSum := sha256.Sum256([]byte("s3cret"))
	s := &service{
		priv: priv, pub: pub, kid: authn.KeyID(pub), ttl: 15 * time.Minute,
		clients: map[string]client{
			"ci-bot": {secretHash: hex.EncodeToString(secretSum[:]), grant: grant{org: "acme", rw: true}},
		},
		audit: slog.New(slog.DiscardHandler),
	}
	srv := httptest.NewServer(s.routes())
	t.Cleanup(srv.Close)
	return s, srv
}

// getToken posts the form and returns the HTTP status and access_token.
func getToken(t *testing.T, srv *httptest.Server, form url.Values) (int, string) {
	t.Helper()
	resp, err := http.PostForm(srv.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.AccessToken
}

// decodeClaims parses (without verifying) the payload of a compact JWT.
func decodeClaims(t *testing.T, tok string) authn.Claims {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c authn.Claims
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientCredentials(t *testing.T) {
	_, srv := testService(t)

	code, tok := getToken(t, srv, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"ci-bot"}, "client_secret": {"s3cret"}})
	if code != 200 || tok == "" {
		t.Fatalf("valid credentials must issue a token, got %d %q", code, tok)
	}
	c := decodeClaims(t, tok)
	if c.Sub != "ci-bot" || c.Org != "acme" || !c.RW || c.Exp <= time.Now().Unix() {
		t.Errorf("wrong claims: %+v", c)
	}

	if code, _ := getToken(t, srv, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"ci-bot"}, "client_secret": {"wrong"}}); code != 401 {
		t.Errorf("wrong secret must 401, got %d", code)
	}
	if code, _ := getToken(t, srv, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"nobody"}, "client_secret": {"s3cret"}}); code != 401 {
		t.Errorf("unknown client must 401, got %d", code)
	}
	if code, _ := getToken(t, srv, url.Values{"grant_type": {"password"}}); code != 400 {
		t.Errorf("unsupported grant must 400, got %d", code)
	}
}

// fakeIdP is a minimal OIDC provider: discovery, an RSA JWKS, and a helper to
// mint RS256 ID tokens the way Okta/Azure AD would.
type fakeIdP struct {
	srv  *httptest.Server
	priv *rsa.PrivateKey
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{priv: priv}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"jwks_uri":%q}`, f.srv.URL+"/keys")
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := &priv.PublicKey
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":"idp1","n":%q,"e":%q}]}`,
			base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) idToken(t *testing.T, iss, sub string, groups []string, exp time.Time) string {
	t.Helper()
	h := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "idp1"})
	p := b64(map[string]any{"iss": iss, "sub": sub, "aud": "priompt", "exp": exp.Unix(), "groups": groups})
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestOIDCExchange(t *testing.T) {
	f := newFakeIdP(t)
	s, srv := testService(t)
	idp, err := newIDP(f.srv.URL, "priompt")
	if err != nil {
		t.Fatal(err)
	}
	s.idp = idp
	s.groups = []groupRule{
		{group: "prompt-admins", grant: grant{rw: true}}, // admin, all orgs
		{group: "acme-authors", grant: grant{org: "acme", rw: true}},
		{group: "acme-readers", grant: grant{org: "acme"}},
	}

	exp := time.Now().Add(time.Hour)
	code, tok := getToken(t, srv, url.Values{
		"grant_type": {"oidc"}, "id_token": {f.idToken(t, f.srv.URL, "ada@example.com", []string{"acme-authors"}, exp)}})
	if code != 200 {
		t.Fatalf("valid ID token must exchange, got %d", code)
	}
	if c := decodeClaims(t, tok); c.Sub != "ada@example.com" || c.Org != "acme" || !c.RW {
		t.Errorf("wrong mapped claims: %+v", c)
	}

	// First matching rule wins: an admin-group member gets the admin grant.
	_, tok = getToken(t, srv, url.Values{
		"grant_type": {"oidc"}, "id_token": {f.idToken(t, f.srv.URL, "root@acme.com", []string{"prompt-admins", "acme-readers"}, exp)}})
	if c := decodeClaims(t, tok); c.Org != "" || !c.RW {
		t.Errorf("admin group must map to unscoped rw, got %+v", c)
	}

	if code, _ := getToken(t, srv, url.Values{
		"grant_type": {"oidc"}, "id_token": {f.idToken(t, f.srv.URL, "guest@acme.com", []string{"unmapped"}, exp)}}); code != 403 {
		t.Errorf("unmapped groups must 403, got %d", code)
	}
	if code, _ := getToken(t, srv, url.Values{
		"grant_type": {"oidc"}, "id_token": {f.idToken(t, "https://evil.example", "x", []string{"acme-authors"}, exp)}}); code != 401 {
		t.Errorf("wrong issuer must 401, got %d", code)
	}
	if code, _ := getToken(t, srv, url.Values{
		"grant_type": {"oidc"}, "id_token": {f.idToken(t, f.srv.URL, "x", []string{"acme-authors"}, time.Now().Add(-time.Minute))}}); code != 401 {
		t.Errorf("expired ID token must 401, got %d", code)
	}
}

// Trailing # comments in clients.txt / groups.txt are not fields: the README's
// own `prompt-admins rw # platform team` must stay an admin grant (issue #2).
func TestConfigTrailingComments(t *testing.T) {
	dir := t.TempDir()
	groups := filepath.Join(dir, "groups.txt")
	os.WriteFile(groups, []byte("# header\nprompt-admins rw # platform team\nacme-readers acme # read-only\n"), 0o600)
	g := loadGroups(groups)
	if len(g) != 2 || g[0].grant != (grant{rw: true}) || g[1].grant != (grant{org: "acme"}) {
		t.Errorf("trailing comments parsed as fields: %+v", g)
	}

	clients := filepath.Join(dir, "clients.txt")
	os.WriteFile(clients, []byte("ci-bot sha256:abcd acme rw # ci runner\n"), 0o600)
	if c := loadClients(clients)["ci-bot"]; c.grant != (grant{org: "acme", rw: true}) || c.secretHash != "abcd" {
		t.Errorf("trailing comment changed the client grant: %+v", c)
	}
}

// Two org-looking fields are ambiguous; reject instead of last-wins.
func TestParseGrantRejectsExtraFields(t *testing.T) {
	if g, err := parseGrant([]string{"acme", "rw", "platform", "team"}); err == nil {
		t.Errorf("want an error for two orgs, got %+v", g)
	}
	if g, err := parseGrant([]string{"acme", "rw"}); err != nil || g != (grant{org: "acme", rw: true}) {
		t.Errorf("want acme rw, got %+v err=%v", g, err)
	}
}
