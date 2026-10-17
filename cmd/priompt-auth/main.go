// Command priompt-auth is the token issuer for Priompt. It exchanges an
// enterprise credential — a service-account secret, or an OIDC ID token from
// the corporate IdP — for a short-lived EdDSA JWT that the Priompt server
// verifies offline against this service's /jwks. Stateless by design: if this
// service is down, already-issued tokens keep working until they expire.
//
//	priompt-auth init                          generate the signing keypair
//	priompt-auth gen-secret <id> [org] [rw]    mint a service-account credential
//	priompt-auth serve                         run the issuer (POST /token, GET /jwks)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/priompt/auth/authn"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: priompt-auth <init|gen-secret|serve> [flags]")
	}
	switch os.Args[1] {
	case "init":
		initCmd(os.Args[2:])
	case "gen-secret":
		genSecretCmd(os.Args[2:])
	case "serve":
		serveCmd(os.Args[2:])
	default:
		log.Fatalf("unknown command %q (want init, gen-secret, or serve)", os.Args[1])
	}
}

// initCmd generates the Ed25519 signing keypair.
//
// ponytail: rotation is init -force + restart — outstanding tokens die early,
// bounded by the TTL (minutes). Add a -prev-key-file served in the JWKS when a
// zero-drop rotation is actually required.
func initCmd(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	keyFile := fs.String("key-file", "auth.key", "where to write the Ed25519 private key (PEM)")
	force := fs.Bool("force", false, "overwrite an existing key file")
	fs.Parse(args)

	if _, err := os.Stat(*keyFile); err == nil && !*force {
		log.Fatalf("%s exists; pass -force to overwrite (old tokens will stop verifying)", *keyFile)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s (kid %s)\n", *keyFile, authn.KeyID(pub))
	fmt.Printf("next: priompt-auth gen-secret <client-id> [org] [rw], then priompt-auth serve\n")
	fmt.Printf("point the server at it: priompt serve -auth-jwks-url http://<this-host>:8444/jwks\n")
}

// genSecretCmd mints a service-account credential: prints the secret (give it
// to the client, it is never stored) and the hashed line to add to clients.txt.
func genSecretCmd(args []string) {
	if len(args) < 1 {
		log.Fatal("usage: priompt-auth gen-secret <client-id> [org] [rw]")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Fatal(err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	fmt.Printf("client_secret (give to the client, shown once):\n  %s\n", secret)
	fmt.Printf("clients.txt line (safe to commit — it is a hash):\n  %s sha256:%s %s\n",
		args[0], hex.EncodeToString(sum[:]), strings.Join(args[1:], " "))
}

// grant is what a credential is allowed to become: an org scope ("" = admin)
// and a write flag. Same semantics as the server's static tokens.
type grant struct {
	org string
	rw  bool
}

type client struct {
	secretHash string // hex sha256 of the client_secret
	grant
}

type service struct {
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	kid     string
	ttl     time.Duration
	clients map[string]client // client_id -> credential
	groups  []groupRule       // ordered; first matching IdP group wins
	idp     *idp              // nil = OIDC exchange disabled
	audit   *slog.Logger
}

type groupRule struct {
	group string
	grant
}

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8444", "listen address")
	keyFile := fs.String("key-file", "auth.key", "Ed25519 private key (from `priompt-auth init`)")
	clientsFile := fs.String("clients-file", "", "service accounts: `client_id sha256:<hex> [org] [rw]` lines (# comments ok)")
	groupsFile := fs.String("groups-file", "", "IdP group mapping: `group [org] [rw]` lines; no org = admin; first match wins")
	oidcIssuer := fs.String("oidc-issuer", "", "OIDC issuer URL of the corporate IdP; enables grant_type=oidc")
	oidcAudience := fs.String("oidc-audience", "", "required aud claim on IdP tokens (empty = not checked)")
	ttl := fs.Duration("ttl", 15*time.Minute, "lifetime of issued tokens")
	fs.Parse(args)

	priv := loadKey(*keyFile)
	s := &service{
		priv: priv, pub: priv.Public().(ed25519.PublicKey),
		ttl:   *ttl,
		audit: slog.New(slog.NewJSONHandler(os.Stderr, nil)),
	}
	s.kid = authn.KeyID(s.pub)
	if *clientsFile != "" {
		s.clients = loadClients(*clientsFile)
	}
	if *oidcIssuer != "" {
		if *groupsFile == "" {
			log.Fatal("-oidc-issuer requires -groups-file (or every login would be denied)")
		}
		s.groups = loadGroups(*groupsFile)
		idp, err := newIDP(*oidcIssuer, *oidcAudience)
		if err != nil {
			log.Fatalf("oidc discovery: %v", err)
		}
		s.idp = idp
	}
	if len(s.clients) == 0 && s.idp == nil {
		log.Fatal("nothing to issue: pass -clients-file and/or -oidc-issuer")
	}
	log.Printf("priompt-auth on %s (kid %s, ttl %s, clients %d, oidc %v)",
		*addr, s.kid, s.ttl, len(s.clients), s.idp != nil)
	log.Fatal(http.ListenAndServe(*addr, s.routes()))
}

func (s *service) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(authn.JWKSJSON(s.pub, s.kid))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return mux
}

// token is the OAuth2-style issuance endpoint. Two grants:
//
//	grant_type=client_credentials  client_id=… client_secret=…
//	grant_type=oidc                id_token=<IdP RS256 ID token>
func (s *service) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var sub string
	var g grant
	switch r.PostForm.Get("grant_type") {
	case "client_credentials":
		id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		c, ok := s.clients[id]
		sum := sha256.Sum256([]byte(secret))
		if !ok || subtle.ConstantTimeCompare([]byte(c.secretHash), []byte(hex.EncodeToString(sum[:]))) != 1 {
			s.audit.Warn("denied", "grant", "client_credentials", "client_id", id)
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		sub, g = id, c.grant
	case "oidc":
		if s.idp == nil {
			oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
			return
		}
		idpSub, groups, err := s.idp.verify(r.PostForm.Get("id_token"))
		if err != nil {
			s.audit.Warn("denied", "grant", "oidc", "reason", err.Error())
			oauthError(w, http.StatusUnauthorized, "invalid_grant")
			return
		}
		rule, ok := s.match(groups)
		if !ok {
			s.audit.Warn("denied", "grant", "oidc", "sub", idpSub, "reason", "no group mapping")
			oauthError(w, http.StatusForbidden, "access_denied")
			return
		}
		sub, g = idpSub, rule
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	now := time.Now()
	tok := authn.MintJWT(s.priv, s.kid, authn.Claims{
		Sub: sub, Org: g.org, RW: g.rw,
		Iat: now.Unix(), Exp: now.Add(s.ttl).Unix(), Iss: "priompt-auth",
	})
	s.audit.Info("issued", "sub", sub, "org", g.org, "rw", g.rw, "ttl", s.ttl.String())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": tok, "token_type": "Bearer", "expires_in": int(s.ttl.Seconds()),
	})
}

// match returns the grant of the first groups-file rule that names one of the
// caller's IdP groups. Order in the file is precedence.
func (s *service) match(groups []string) (grant, bool) {
	for _, rule := range s.groups {
		for _, g := range groups {
			if g == rule.group {
				return rule.grant, true
			}
		}
	}
	return grant{}, false
}

func oauthError(w http.ResponseWriter, code int, kind string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`+"\n", kind)
}

func loadKey(file string) ed25519.PrivateKey {
	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("%v (run `priompt-auth init` first)", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		log.Fatalf("%s: not PEM", file)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		log.Fatalf("%s: not an Ed25519 key", file)
	}
	return priv
}

// loadClients parses `client_id sha256:<hex> [org] [rw]` lines. Keyword-style
// fields after the hash, same as the server's tokens file: `rw` grants write,
// anything else is the org; absent org = admin.
func loadClients(file string) map[string]client {
	out := map[string]client{}
	for _, fields := range configLines(file) {
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "sha256:") {
			log.Fatalf("%s: want `client_id sha256:<hex> [org] [rw]`, got %q", file, strings.Join(fields, " "))
		}
		c := client{secretHash: strings.TrimPrefix(fields[1], "sha256:")}
		c.grant = parseGrant(fields[2:])
		out[fields[0]] = c
	}
	return out
}

// loadGroups parses ordered `group [org] [rw]` lines; no org = admin.
func loadGroups(file string) []groupRule {
	var out []groupRule
	for _, fields := range configLines(file) {
		out = append(out, groupRule{group: fields[0], grant: parseGrant(fields[1:])})
	}
	return out
}

func parseGrant(fields []string) grant {
	var g grant
	for _, f := range fields {
		switch f {
		case "rw":
			g.rw = true
		case "ro": // explicit read-only (the default); no-op
		default:
			g.org = f
		}
	}
	return g
}

func configLines(file string) [][]string {
	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	var out [][]string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Fields(line))
	}
	return out
}
