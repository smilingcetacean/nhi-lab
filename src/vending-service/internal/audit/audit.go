// Package audit implements the lab-wide audit event schema, shared shape
// with src/resource/audit.go and src/policy-engine/audit.go: JSON Lines,
// serialized so concurrent requests cannot interleave partial lines.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Stages this service emits. The vending service is the "vend" half of the
// pipeline and the "dispose" half of teardown; it
// does not itself emit "spawn" (the parent agent's own act), "operate" (the
// resource) or "log" (the audit pipeline as a concept, not an event stage).
const (
	StageAttest  = "attest"
	StageVend    = "vend"
	StageDispose = "dispose"
)

const (
	OutcomeAllow = "allow"
	OutcomeDeny  = "deny"
	OutcomeError = "error"
)

// Event mirrors src/resource/audit.go's and src/policy-engine/audit.go's
// shape exactly: the schema is fixed and shared across
// every component that emits it. ChainID in particular is declared
// UNCONDITIONALLY (no `omitempty`), matching those two components exactly
// — a pre-vend denial (e.g. a bad signature,
// before a chain_id has been minted) legitimately has no chain to report,
// and that is represented the same way everywhere: the key is always
// present, carrying "" rather than being absent. A JSON Lines consumer
// reading all three components' logs as one stream would otherwise see an
// absent key from this component and an empty string from the other two for
// the same situation.
type Event struct {
	Timestamp string `json:"timestamp"`
	Stage     string `json:"stage"`
	ChainID   string `json:"chain_id"`
	// ActorSpiffeID is the AUTHENTICATED caller — the SPIFFE ID validated off
	// the caller's JWT-SVID (ingress) or, for the reaper, this service's own
	// identity. Never a value copied uninspected from the request body.
	ActorSpiffeID string `json:"actor_spiffe_id"`
	Outcome       string `json:"outcome"`
	Detail        Detail `json:"detail"`
}

type Detail struct {
	ParentSpiffeID  string   `json:"parent_spiffe_id,omitempty"`
	ChildSpiffeID   string   `json:"child_spiffe_id,omitempty"`
	RequestedScopes []string `json:"requested_scopes,omitempty"`
	ChildScopes     []string `json:"child_scopes,omitempty"`
	PolicyID        string   `json:"policy_id,omitempty"`
	EntryID         string   `json:"entry_id,omitempty"`
	ExpiresAt       *int64   `json:"expires_at,omitempty"`
	TaskContext     string   `json:"task_context,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

// Auditor writes JSON-lines audit events.
type Auditor struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func New(w io.Writer) *Auditor {
	return &Auditor{enc: json.NewEncoder(w)}
}

func (a *Auditor) Emit(ev Event) {
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.enc.Encode(ev)
}
