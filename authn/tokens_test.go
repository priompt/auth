package authn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tokens.txt")
	content := `# comment
bare
scoped        acme
writer        acme   rw
expiring      acme   2026-12-31   rw
readonly      acme   ro
`
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PRIOMPT_TOKEN", "envadmin")

	tokens, err := LoadTokens(file)
	if err != nil {
		t.Fatal(err)
	}

	// PRIOMPT_TOKEN is admin (no org) and may write.
	if tok, ok := tokens["envadmin"]; !ok || tok.Org != "" || !tok.Write {
		t.Errorf("envadmin should be admin+write, got %+v ok=%v", tok, ok)
	}
	// Write is opt-in: a bare or scoped token without `rw` is read-only.
	if tokens["bare"].Write {
		t.Error("bare token must default read-only")
	}
	if tokens["scoped"].Org != "acme" || tokens["scoped"].Write {
		t.Errorf("scoped token: want org=acme read-only, got %+v", tokens["scoped"])
	}
	if !tokens["writer"].Write {
		t.Error("rw token must be writable")
	}
	// Field order is keyword-based: org, expiry, and rw parse regardless of position.
	e := tokens["expiring"]
	if e.Org != "acme" || !e.Write || e.Expires.IsZero() {
		t.Errorf("expiring token: want org=acme write=true expiry set, got %+v", e)
	}
	if tokens["readonly"].Write {
		t.Error("explicit ro must be read-only")
	}
}

// A missing file is an error the caller reports, not a process exit — the
// difference between the old in-core helper and a library.
func TestLoadTokensMissingFile(t *testing.T) {
	t.Setenv("PRIOMPT_TOKEN", "")
	if _, err := LoadTokens(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Error("missing tokens file must return an error")
	}
	tokens, err := LoadTokens("")
	if err != nil || len(tokens) != 0 {
		t.Errorf("no file and no env token = auth disabled, got %v err=%v", tokens, err)
	}
}

// A trailing # comment is not part of the line: `tok acme rw # ci runner` must
// stay scoped to acme, not be re-scoped to org "runner" (issue #2).
func TestLoadTokensTrailingComment(t *testing.T) {
	t.Setenv("PRIOMPT_TOKEN", "")
	file := filepath.Join(t.TempDir(), "tokens.txt")
	content := "scoped acme rw # ci runner\nadmin # break-glass, all orgs\nhash acme #nospace\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := LoadTokens(file)
	if err != nil {
		t.Fatal(err)
	}
	if tok := tokens["scoped"]; tok.Org != "acme" || !tok.Write {
		t.Errorf("trailing comment changed scope: want org=acme rw, got %+v", tok)
	}
	if tok := tokens["admin"]; tok.Org != "" || tok.Write {
		t.Errorf("comment-only tail: want admin read-only, got %+v", tok)
	}
	if tok := tokens["hash"]; tok.Org != "acme" {
		t.Errorf("#comment without a space: want org=acme, got %+v", tok)
	}
}

// Two org-looking fields (or two expiries) are ambiguous: reject the line
// instead of letting the last one silently win.
func TestLoadTokensRejectsExtraFields(t *testing.T) {
	t.Setenv("PRIOMPT_TOKEN", "")
	for _, line := range []string{
		"tok acme rw ci runner",
		"tok acme 2026-01-01 2027-01-01",
	} {
		file := filepath.Join(t.TempDir(), "tokens.txt")
		if err := os.WriteFile(file, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if tokens, err := LoadTokens(file); err == nil {
			t.Errorf("%q: want an error, got %+v", line, tokens)
		}
	}
}
