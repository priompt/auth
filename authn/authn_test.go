package authn

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// interceptorFor mirrors the serve wiring: a static provider only when tokens
// exist, so an empty map means "no providers" (auth disabled).
func interceptorFor(tokens map[string]Token) grpc.UnaryServerInterceptor {
	if len(tokens) == 0 {
		return Interceptor()
	}
	return Interceptor(NewStatic(tokens))
}

// run drives an interceptor chain and reports what identity reached the
// handler: whether it ran at all, the org scope, and whether writes are
// permitted (no identity = auth disabled = full access, as core's RequireWrite
// reads it).
func run(interceptor grpc.UnaryServerInterceptor, header string) (passed bool, scope string, canWrite bool) {
	ctx := context.Background()
	if header != "" {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", header))
	}
	h := func(ctx context.Context, req any) (any, error) {
		passed = true
		id, ok := FromContext(ctx)
		scope, canWrite = id.Org, !ok || id.Write
		return nil, nil
	}
	interceptor(ctx, nil, &grpc.UnaryServerInfo{}, h)
	return passed, scope, canWrite
}

func call(tokens map[string]Token, header string) (bool, string, bool) {
	return run(interceptorFor(tokens), header)
}

func TestInterceptor(t *testing.T) {
	two := map[string]Token{"alice": {}, "bob": {Org: "acme"}}
	if ok, _, _ := call(two, "Bearer alice"); !ok {
		t.Error("alice's token should authenticate")
	}
	if ok, scope, _ := call(two, "Bearer bob"); !ok || scope != "acme" {
		t.Errorf("bob's token should authenticate scoped to acme, got ok=%v scope=%q", ok, scope)
	}
	if ok, _, _ := call(two, "Bearer revoked"); ok {
		t.Error("unknown token must be rejected")
	}
	if ok, _, _ := call(two, ""); ok {
		t.Error("missing token must be rejected")
	}
	if ok, _, _ := call(map[string]Token{}, ""); !ok {
		t.Error("empty token set disables auth")
	}

	// Expiry: a past expiry is rejected, a future one passes.
	expired := map[string]Token{"old": {Expires: time.Now().Add(-time.Hour)}}
	if ok, _, _ := call(expired, "Bearer old"); ok {
		t.Error("expired token must be rejected")
	}
	valid := map[string]Token{"new": {Expires: time.Now().Add(time.Hour)}}
	if ok, _, _ := call(valid, "Bearer new"); !ok {
		t.Error("unexpired token must authenticate")
	}
}

func TestWriteGrant(t *testing.T) {
	tokens := map[string]Token{
		"reader": {Org: "acme"},              // read-only
		"author": {Org: "acme", Write: true}, // may write
		"admin":  {Write: true},
	}
	if _, _, w := call(tokens, "Bearer reader"); w {
		t.Error("read-only token must not carry the write grant")
	}
	if ok, _, w := call(tokens, "Bearer author"); !ok || !w {
		t.Error("rw token must carry the write grant")
	}
	if _, _, w := call(tokens, "Bearer admin"); !w {
		t.Error("admin rw token must carry the write grant")
	}
	// Auth disabled (no providers) leaves no identity on the context — full access.
	if ok, _, w := call(map[string]Token{}, ""); !ok || !w {
		t.Error("auth-disabled must permit writes")
	}
}
