package main

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Audit event stages this service emits, per the lab-wide audit schema
// (`timestamp, stage, chain_id, actor_spiffe_id, outcome, detail`). The
// policy engine is the synthesis half of the "vend" stage — it does not
// create the SPIRE registration entry (the vending service does) — and the whole of "dispose"'s
// policy-removal half.
const (
	stageVend    = "vend"
	stageDispose = "dispose"
)

// auditEvent mirrors src/resource/audit.go's shape exactly: the schema is
// normative and shared across every component that emits it, not something
// each service is free to reinvent.
type auditEvent struct {
	Timestamp string `json:"timestamp"`
	Stage     string `json:"stage"`
	ChainID   string `json:"chain_id"`
	// ActorSpiffeID is the AUTHENTICATED caller — the SPIFFE ID this service's
	// mTLS listener authorized on the client certificate's URI SAN. Never a
	// value taken from the request body.
	ActorSpiffeID string `json:"actor_spiffe_id"`
	Outcome       string `json:"outcome"`
	Detail        detail `json:"detail"`
}

type detail struct {
	ParentSpiffeID string `json:"parent_spiffe_id,omitempty"`
	ChildSpiffeID  string `json:"child_spiffe_id,omitempty"`
	// RequestedScopes is what the child asked for. ChildScopes is what it was
	// actually granted, after intersection with Π(P) — the gap between the
	// two, if any, is the attenuation the whole lab exists to demonstrate.
	RequestedScopes []string `json:"requested_scopes,omitempty"`
	ChildScopes     []string `json:"child_scopes,omitempty"`
	// ParentScopes is Π(P) as this service derived it (OPA read-back plus the
	// bootstrap table), logged so an auditor can verify the intersection by
	// hand rather than trusting the arithmetic.
	ParentScopes []string `json:"parent_scopes,omitempty"`
	PolicyID     string   `json:"policy_id,omitempty"`
	ExpiresAt    *int64   `json:"expires_at,omitempty"`
	// TaskContext is accepted and logged but inert — see synth.go's doc
	// comment on SynthesisRequest.TaskContext.
	TaskContext string `json:"task_context,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// auditor writes JSON-lines audit events, serialized like the resource's, so
// concurrent requests cannot interleave partial lines in the evidence trail.
type auditor struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newAuditor(w io.Writer) *auditor {
	return &auditor{enc: json.NewEncoder(w)}
}

func (a *auditor) emit(ev auditEvent) {
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.enc.Encode(ev)
}
