package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/capability"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/did"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/store"
	"testing"
	"time"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	p, s, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return p, s
}
func doc(id string, p ed25519.PublicKey) did.Document {
	return did.Document{ID: id, PublicKey: base64.RawURLEncoding.EncodeToString(p)}
}

func TestDelegationAndAttenuation(t *testing.T) {
	r := did.NewMemoryResolver()
	rev := store.NewMemoryRevocations()
	up, us := key(t)
	ap, as := key(t)
	bp, _ := key(t)
	u := "did:agent:user"
	a := "did:agent:a"
	b := "did:agent:b"
	r.Put(doc(u, up))
	r.Put(doc(a, ap))
	r.Put(doc(b, bp))
	exp := time.Now().Add(time.Hour).Unix()
	root, _ := capability.Sign(capability.Token{ID: "c0", IssuerDID: u, SubjectDID: a, RootUserDID: u, Depth: 0, Scope: capability.Scope{Resource: "db://prod/*", Actions: []string{"read", "write"}, Audience: "mcp.db", MaxCalls: 10, ExpiresAt: exp}}, us)
	child, _ := capability.Sign(capability.Token{ID: "c1", IssuerDID: a, SubjectDID: b, RootUserDID: u, ParentID: "c0", Depth: 1, Scope: capability.Scope{Resource: "db://prod/orders", Actions: []string{"read"}, Audience: "mcp.db", MaxCalls: 2, ExpiresAt: exp}}, as)
	e := Engine{Resolver: r, Revocations: rev, MaxDepth: 4}
	d := e.Verify(capability.VerifyRequest{Chain: []capability.Token{root, child}, CallerDID: b, Tool: "mcp.db", Resource: "db://prod/orders", Action: "read"})
	if !d.Allowed {
		t.Fatalf("expected allow: %+v", d)
	}
}
func TestEscalationDenied(t *testing.T) {
	r := did.NewMemoryResolver()
	up, us := key(t)
	ap, as := key(t)
	bp, _ := key(t)
	u := "did:agent:user"
	a := "did:agent:a"
	b := "did:agent:b"
	r.Put(doc(u, up))
	r.Put(doc(a, ap))
	r.Put(doc(b, bp))
	exp := time.Now().Add(time.Hour).Unix()
	root, _ := capability.Sign(capability.Token{ID: "c0", IssuerDID: u, SubjectDID: a, RootUserDID: u, Depth: 0, Scope: capability.Scope{Resource: "db://prod/orders", Actions: []string{"read"}, Audience: "mcp.db", ExpiresAt: exp}}, us)
	child, _ := capability.Sign(capability.Token{ID: "c1", IssuerDID: a, SubjectDID: b, RootUserDID: u, ParentID: "c0", Depth: 1, Scope: capability.Scope{Resource: "db://prod/orders", Actions: []string{"read", "delete"}, Audience: "mcp.db", ExpiresAt: exp}}, as)
	d := (&Engine{Resolver: r, Revocations: store.NewMemoryRevocations(), MaxDepth: 4}).Verify(capability.VerifyRequest{Chain: []capability.Token{root, child}, CallerDID: b, Tool: "mcp.db", Resource: "db://prod/orders", Action: "delete"})
	if d.Allowed {
		t.Fatal("escalation must be denied")
	}
}
func TestRevocationDenied(t *testing.T) {
	r := did.NewMemoryResolver()
	rev := store.NewMemoryRevocations()
	up, us := key(t)
	ap, _ := key(t)
	u := "did:agent:user"
	a := "did:agent:a"
	r.Put(doc(u, up))
	r.Put(doc(a, ap))
	exp := time.Now().Add(time.Hour).Unix()
	root, _ := capability.Sign(capability.Token{ID: "c0", IssuerDID: u, SubjectDID: a, RootUserDID: u, Depth: 0, Scope: capability.Scope{Resource: "mail://inbox", Actions: []string{"read"}, Audience: "mcp.mail", ExpiresAt: exp}}, us)
	rev.Revoke("c0")
	d := (&Engine{Resolver: r, Revocations: rev}).Verify(capability.VerifyRequest{Chain: []capability.Token{root}, CallerDID: a, Tool: "mcp.mail", Resource: "mail://inbox", Action: "read"})
	if d.Allowed {
		t.Fatal("revoked capability must be denied")
	}
}
