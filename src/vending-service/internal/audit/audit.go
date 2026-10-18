// Package audit implements the lab-wide audit event schema, shared shape
// with src/resource/audit.go and src/policy-engine/audit.go: JSON Lines,
// serialized so concurrent requests cannot interleave partial lines.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
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

// Auditor writes JSON-lines audit events: always to its primary writer
// (stdout in the service), and, when constructed with NewWithFile, to a
// second sink afterwards.
type Auditor struct {
	mu  sync.Mutex
	out io.Writer
	// file is the optional second sink; nil means stdout only. errOut is
	// where a failed file write is reported (stderr in the service).
	file   io.Writer
	errOut io.Writer
}

// New returns an Auditor that writes to w only.
func New(w io.Writer) *Auditor {
	return &Auditor{out: w}
}

// NewWithFile returns an Auditor that writes every event to w and then
// appends the identical bytes to file. A failed write to file is reported on
// errOut and otherwise ignored: it neither suppresses the line already
// written to w nor changes the outcome of the request being audited, which
// matches the best-effort behaviour of Emit to w. The two writes are
// sequential rather than an io.MultiWriter, because a MultiWriter stops at
// the first failing writer and would let a bad file starve the other sink.
func NewWithFile(w, file, errOut io.Writer) *Auditor {
	return &Auditor{out: w, file: file, errOut: errOut}
}

// OpenFile opens path as an audit file sink: append-only, created if absent,
// mode 0640 (subject to the process umask). The caller owns closing it.
func OpenFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
}

func (a *Auditor) Emit(ev Event) {
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	// Encode once; both sinks receive these exact bytes, each in a single
	// Write of the whole line.
	var line bytes.Buffer
	if err := json.NewEncoder(&line).Encode(ev); err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.out.Write(line.Bytes())
	if a.file == nil {
		return
	}
	if _, err := a.file.Write(line.Bytes()); err != nil && a.errOut != nil {
		fmt.Fprintf(a.errOut, "vending-service: audit file write failed (event still written to stdout): %v\n", err)
	}
}
