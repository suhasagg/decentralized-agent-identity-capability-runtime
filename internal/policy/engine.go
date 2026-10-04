package policy

import (
	"errors"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/audit"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/capability"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/did"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/store"
	"time"
)

type Engine struct {
	Resolver    did.Resolver
	Revocations store.Revocations
	Audit       audit.Sink
	MaxDepth    int
}

func (e *Engine) Verify(req capability.VerifyRequest) capability.Decision {
	d := capability.Decision{Allowed: false, ChainDepth: len(req.Chain)}
	fail := func(code string) capability.Decision {
		d.ReasonCodes = append(d.ReasonCodes, code)
		if e.Audit != nil {
			e.Audit.Write(audit.Event{Type: "capability.decision", RootUserDID: d.RootUserDID, CallerDID: req.CallerDID, CapabilityID: d.CapabilityID, Allowed: false, Reasons: d.ReasonCodes})
		}
		return d
	}
	if len(req.Chain) == 0 {
		return fail("EMPTY_CHAIN")
	}
	if e.MaxDepth > 0 && len(req.Chain)-1 > e.MaxDepth {
		return fail("MAX_DELEGATION_DEPTH")
	}
	now := req.Now
	if now == 0 {
		now = time.Now().Unix()
	}

	for i, tok := range req.Chain {
		if tok.ID == "" || tok.SubjectDID == "" || tok.IssuerDID == "" {
			return fail("MALFORMED_CAPABILITY")
		}
		if e.Revocations != nil && e.Revocations.IsRevoked(tok.ID) {
			return fail("REVOKED_CAPABILITY")
		}
		if now < tok.Scope.NotBefore || now >= tok.Scope.ExpiresAt {
			return fail("CAPABILITY_EXPIRED_OR_NOT_YET_VALID")
		}
		doc, err := e.Resolver.Resolve(tok.IssuerDID)
		if err != nil {
			return fail("ISSUER_DID_UNRESOLVED")
		}
		pk, err := did.ParseEd25519PublicKey(doc)
		if err != nil {
			return fail("ISSUER_KEY_INVALID")
		}
		if capability.VerifySignature(tok, pk) != nil {
			return fail("INVALID_SIGNATURE")
		}

		if i == 0 {
			d.RootUserDID = tok.RootUserDID
			if tok.IssuerDID != tok.RootUserDID {
				return fail("ROOT_ISSUER_NOT_USER")
			}
			if tok.Depth != 0 || tok.ParentID != "" {
				return fail("INVALID_ROOT_CAPABILITY")
			}
		} else if !capability.IsAttenuation(req.Chain[i-1], tok) {
			return fail("AUTHORITY_ESCALATION")
		}
	}
	leaf := req.Chain[len(req.Chain)-1]
	d.CapabilityID = leaf.ID
	d.EffectiveDID = leaf.SubjectDID
	if leaf.SubjectDID != req.CallerDID {
		return fail("CALLER_NOT_CAPABILITY_SUBJECT")
	}
	if leaf.Scope.Audience != "*" && leaf.Scope.Audience != req.Tool {
		return fail("AUDIENCE_MISMATCH")
	}
	if !resourceAllowed(leaf.Scope.Resource, req.Resource) {
		return fail("RESOURCE_OUT_OF_SCOPE")
	}
	if !actionAllowed(leaf.Scope.Actions, req.Action) {
		return fail("ACTION_OUT_OF_SCOPE")
	}

	d.Allowed = true
	d.ReasonCodes = []string{"VALID_PROVENANCE", "VALID_DELEGATION_CHAIN", "CAPABILITY_WITHIN_SCOPE"}
	if e.Audit != nil {
		e.Audit.Write(audit.Event{Type: "capability.decision", RootUserDID: d.RootUserDID, CallerDID: req.CallerDID, CapabilityID: d.CapabilityID, Allowed: true, Reasons: d.ReasonCodes})
	}
	return d
}

func resourceAllowed(scope, resource string) bool {
	if scope == resource {
		return true
	}
	if len(scope) > 1 && scope[len(scope)-1] == '*' {
		return len(resource) >= len(scope)-1 && resource[:len(scope)-1] == scope[:len(scope)-1]
	}
	return false
}
func actionAllowed(xs []string, x string) bool {
	for _, a := range xs {
		if a == x {
			return true
		}
	}
	return false
}

var ErrDenied = errors.New("capability denied")
