package authn

// The static tokens file — the zero-infrastructure credential path, for
// deployments that do not run the priompt-auth service. Parsing lives here
// alongside JWT verification so the core server holds no credential handling
// of its own.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// GenToken returns a fresh random bearer token for the tokens file.
func GenToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// LoadTokens reads bearer tokens, their org scope, an optional expiry, and an
// optional write grant. PRIOMPT_TOKEN is an admin token (all orgs, never
// expires, may write). File lines are `token [org] [expiry] [rw]` — org scopes
// the token to priompt://org/… (blank = admin); expiry is a date (2006-01-02)
// or RFC3339 timestamp; the keyword `rw` grants write (default is read-only,
// `ro` is the explicit no-op). Fields after the token are order-independent:
// `rw`/`ro` is recognized by keyword, a date/timestamp as the expiry, anything
// else as the org. Blank lines and # comments are ignored. An empty file name
// with no PRIOMPT_TOKEN yields an empty map = auth disabled. To rotate: add the
// new token, give the old one a near-future expiry, drop it once it lapses.
func LoadTokens(file string) (map[string]Token, error) {
	tokens := map[string]Token{}
	if t := os.Getenv("PRIOMPT_TOKEN"); t != "" {
		tokens[t] = Token{Write: true} // admin, never expires
	}
	if file == "" {
		return tokens, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		tok := Token{}
		for _, f := range fields[1:] {
			switch {
			case f == "rw":
				tok.Write = true
			case f == "ro":
				// explicit read-only (the default); no-op
			case isExpiry(f):
				exp, err := parseExpiry(f)
				if err != nil {
					return nil, err
				}
				tok.Expires = exp
			default:
				tok.Org = f
			}
		}
		tokens[fields[0]] = tok
	}
	return tokens, nil
}

// isExpiry reports whether s parses as a token expiry (date or RFC3339), so the
// token-line parser can tell an expiry from an org name.
func isExpiry(s string) bool {
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return true
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

// parseExpiry accepts a bare date (2006-01-02) or an RFC3339 timestamp.
func parseExpiry(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad token expiry %q: want 2006-01-02 or RFC3339", s)
	}
	return t, nil
}
