package main

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Audit event stages, per the lab-wide audit schema. The resource only
// ever emits `operate` — it is the "operate" stage of the lifecycle. The other
// stages belong to the vending service and the agent harness.
const stageOperate = "operate"

// chain_id provenance: how much an event's chain_id is worth.
const (
	// No X-NHI-Chain-Id header was present.
	chainSourceAbsent = "absent"
	// The header was present and is recorded verbatim. It is a HINT: nothing
	// has verified that this caller belongs to this chain.
	chainSourceClientAsserted = "client-asserted"
	// Reserved: the chain looked up from the delegation records by the
	// authenticated SPIFFE ID, rather than taken from the request. Not
	// currently emitted — the resource has no access to the delegation store.
	chainSourceResolved = "resolved"
)

// auditEvent is the lab-wide JSON-lines audit record. The field names and the
// `stage` vocabulary are shared by every component and parsed by the
// experiments; changing either is a design change, not a patch.
type auditEvent struct {
	Timestamp string `json:"timestamp"`
	Stage     string `json:"stage"`
	ChainID   string `json:"chain_id"`
	// ActorSpiffeID is the AUTHENTICATED caller, taken from the validated
	// JWT-SVID's subject. This is the attribution anchor and the only identity
	// claim in the event that anything was verified about.
	ActorSpiffeID string `json:"actor_spiffe_id"`
	Outcome       string `json:"outcome"`
	Detail        detail `json:"detail"`
}

type detail struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	// RequiredScopes is what the endpoint demanded — server-derived, never
	// caller-asserted. See requiredScopesFor.
	RequiredScopes []string `json:"required_scopes,omitempty"`
	// ChainIDSource records how much the chain_id above is worth. An auditor
	// reading `client-asserted` knows the value is a correlation hint and not
	// evidence; reading `resolved` knows it was derived from the
	// delegation record for the authenticated identity.
	ChainIDSource string `json:"chain_id_source"`
	// Reason is why a deny happened, for the negative tests, which must
	// show both the denial and the audit event that recorded it.
	Reason string `json:"reason,omitempty"`
	// PolicyDecision is OPA's raw answer, present only when OPA was actually
	// consulted. Absent on an authentication failure, which never reaches OPA.
	PolicyDecision *bool `json:"policy_decision,omitempty"`
	// DecisionLatencyMs is the time spent in the OPA round trip. The experiments'
	// per-stage latency collection reads this rather than re-instrumenting.
	DecisionLatencyMs *float64 `json:"decision_latency_ms,omitempty"`
}

// auditor writes JSON-lines audit events. Writes are serialized: the events are
// the evidence for the negative tests, and interleaved partial lines from
// concurrent requests would corrupt exactly the records the tests read back.
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
	if ev.Stage == "" {
		ev.Stage = stageOperate
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// A failure to write an audit event is not worth failing the request over,
	// but it must not be silent either — the encoder writes to stderr-backed
	// stdout in the pod, and a broken pipe there is a deployment problem.
	_ = a.enc.Encode(ev)
}
