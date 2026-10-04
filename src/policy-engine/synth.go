package main

import "context"

// Synthesizer is the policy-synthesis interface seam: the deterministic stub
// below is the only implementation today. An LLM-backed implementation
// (planned but not built here) would satisfy the same interface, reading
// TaskContext to reason about intent instead of computing a pure set
// intersection.
//
// TODO: attach an LLM-backed Synthesizer here when that work is
// picked up. Nothing about the HTTP layer, the OPA read-back or the Rego
// renderer in this package needs to change — they are written against this
// interface, not against deterministicSynthesizer directly.
type Synthesizer interface {
	Synthesize(ctx context.Context, req SynthesisRequest) (SynthesisResult, error)
}

// SynthesisRequest is what a Synthesizer implementation sees. Note what is
// NOT here as a caller-supplied value: ParentScopes is filled in by the
// caller of Synthesize (main.go's handler), which derives it itself from OPA
// and the bootstrap table. A Synthesizer never receives
// scopes the HTTP client asserted.
type SynthesisRequest struct {
	ChainID        string
	ParentSpiffeID string
	ChildSpiffeID  string
	// ParentScopes is Π(P), derived server-side. See deriveParentScopes.
	ParentScopes []string
	// RequestedScopes is what the child is asking for. It may exceed
	// ParentScopes; the Synthesizer's job is to attenuate, not to validate.
	RequestedScopes []string
	// TaskContext is accepted and logged but does not influence the
	// deterministic stub's output. It exists because the deferred LLM
	// backend's signature needs it — its inertness
	// here is a documented seam, not an unimplemented feature.
	TaskContext string
	TTLSeconds  int64
}

// SynthesisResult is what a Synthesizer returns. Only ChildScopes today; the
// caller (main.go) is responsible for rendering it into Rego and picking an
// expiry, since those are policy-plane concerns, not synthesis concerns.
type SynthesisResult struct {
	ChildScopes []string
}

// deterministicSynthesizer is the stub: Π(C) = requested ∩ Π(P).
// Nothing else. Scope-monotonicity (Π(C) ⊆ Π(P)) holds by construction: an
// intersection can never produce an element absent from either operand, so a
// requested scope the parent does not hold is silently dropped rather than
// granted. There is no path through this function that returns a superset of
// req.ParentScopes.
type deterministicSynthesizer struct{}

func (deterministicSynthesizer) Synthesize(_ context.Context, req SynthesisRequest) (SynthesisResult, error) {
	return SynthesisResult{ChildScopes: intersectScopes(req.RequestedScopes, req.ParentScopes)}, nil
}

// intersectScopes returns the elements of requested that also appear in
// parent, deduplicated, in the order they first appear in requested. Order is
// irrelevant to the security property but stable output makes the rendered
// Rego and the tests deterministic.
func intersectScopes(requested, parent []string) []string {
	held := make(map[string]bool, len(parent))
	for _, s := range parent {
		held[s] = true
	}
	seen := make(map[string]bool, len(requested))
	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if held[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
