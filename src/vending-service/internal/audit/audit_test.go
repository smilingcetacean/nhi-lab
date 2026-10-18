package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// failingWriter stands in for a file sink whose volume is full or gone.
type failingWriter struct{ calls int }

func (f *failingWriter) Write([]byte) (int, error) {
	f.calls++
	return 0, errors.New("no space left on device")
}

func sampleEvent(chainID string) Event {
	exp := int64(1_800_000_600)
	return Event{
		Timestamp:     "2026-10-18T12:00:00.123456789Z",
		Stage:         StageVend,
		ChainID:       chainID,
		ActorSpiffeID: "spiffe://lab.local/agent/parent/t1",
		Outcome:       OutcomeAllow,
		Detail: Detail{
			ParentSpiffeID:  "spiffe://lab.local/agent/parent/t1",
			ChildSpiffeID:   "spiffe://lab.local/agent/parent/t1/child/c1",
			RequestedScopes: []string{"resource:read:datasetA"},
			ChildScopes:     []string{"resource:read:datasetA"},
			PolicyID:        "nhi_grants_" + chainID,
			EntryID:         "entry-1",
			ExpiresAt:       &exp,
			TaskContext:     "unit test",
			Reason:          "because",
		},
	}
}

func keysOf(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not a JSON object: %v: %s", err, raw)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestEmitWritesIdenticalLineToBothSinks(t *testing.T) {
	var stdout, file, stderr bytes.Buffer
	a := NewWithFile(&stdout, &file, &stderr)

	a.Emit(sampleEvent("c_aaa"))
	a.Emit(Event{Stage: StageDispose, ChainID: "c_aaa", Outcome: OutcomeAllow}) // no Timestamp: Emit fills it

	if stdout.Len() == 0 {
		t.Fatal("stdout sink received nothing")
	}
	if !bytes.Equal(stdout.Bytes(), file.Bytes()) {
		t.Fatalf("sinks differ\nstdout: %q\nfile:   %q", stdout.String(), file.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), stdout.String())
	}
	for _, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Fatalf("line is not valid JSON: %q", l)
		}
	}
}

func TestFileSinkMatchesFileFreeAuditor(t *testing.T) {
	// With no file sink the bytes written to the primary writer are exactly
	// what they were before the second sink existed, and adding a file sink
	// does not change them.
	var plain, withFile, file bytes.Buffer
	New(&plain).Emit(sampleEvent("c_bbb"))
	NewWithFile(&withFile, &file, &bytes.Buffer{}).Emit(sampleEvent("c_bbb"))
	if !bytes.Equal(plain.Bytes(), withFile.Bytes()) {
		t.Fatalf("stdout bytes changed by the file sink\nplain: %q\nwith:  %q", plain.String(), withFile.String())
	}
}

func TestFailingFileSinkDoesNotStopStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	bad := &failingWriter{}
	a := NewWithFile(&stdout, bad, &stderr)

	a.Emit(sampleEvent("c_ccc"))
	a.Emit(sampleEvent("c_ddd"))

	if bad.calls != 2 {
		t.Fatalf("file sink should have been attempted for every event, got %d calls", bad.calls)
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "c_ccc") || !strings.Contains(lines[1], "c_ddd") {
		t.Fatalf("stdout must still receive every event when the file sink fails: %q", stdout.String())
	}
	if got := stderr.String(); !strings.Contains(got, "audit file write failed") || !strings.Contains(got, "no space left on device") {
		t.Fatalf("file write error should be reported on the error writer, got %q", got)
	}
}

func TestEmitSchemaKeysAreExactlyTheExistingSchema(t *testing.T) {
	wantTop := []string{"actor_spiffe_id", "chain_id", "detail", "outcome", "stage", "timestamp"}
	wantDetail := []string{
		"child_scopes", "child_spiffe_id", "entry_id", "expires_at", "parent_spiffe_id",
		"policy_id", "reason", "requested_scopes", "task_context",
	}

	var stdout, file bytes.Buffer
	a := NewWithFile(&stdout, &file, &bytes.Buffer{})
	a.Emit(sampleEvent("c_eee"))
	// A pre-vend denial has no chain: chain_id stays present, as "".
	a.Emit(Event{Stage: StageAttest, Outcome: OutcomeDeny, Detail: Detail{Reason: "no auth"}})

	for name, buf := range map[string]*bytes.Buffer{"stdout": &stdout, "file": &file} {
		lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("%s: want 2 lines, got %d", name, len(lines))
		}
		for i, l := range lines {
			if got := keysOf(t, []byte(l)); strings.Join(got, ",") != strings.Join(wantTop, ",") {
				t.Fatalf("%s line %d top-level keys = %v, want %v", name, i, got, wantTop)
			}
		}
		var full struct {
			Detail json.RawMessage `json:"detail"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &full); err != nil {
			t.Fatal(err)
		}
		if got := keysOf(t, full.Detail); strings.Join(got, ",") != strings.Join(wantDetail, ",") {
			t.Fatalf("%s detail keys = %v, want %v", name, got, wantDetail)
		}
		var denied struct {
			ChainID *string `json:"chain_id"`
		}
		if err := json.Unmarshal([]byte(lines[1]), &denied); err != nil {
			t.Fatal(err)
		}
		if denied.ChainID == nil || *denied.ChainID != "" {
			t.Fatalf("%s: chain_id must be present and empty on a pre-vend denial, got %v", name, denied.ChainID)
		}
	}
}

func TestConcurrentEmitKeepsLinesWholeAndSinksInStep(t *testing.T) {
	var stdout, file bytes.Buffer
	a := NewWithFile(&stdout, &file, &bytes.Buffer{})

	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Emit(sampleEvent("c_fff"))
		}()
	}
	wg.Wait()

	if !bytes.Equal(stdout.Bytes(), file.Bytes()) {
		t.Fatal("sinks diverged under concurrent Emit")
	}
	lines := strings.Split(strings.TrimSuffix(file.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("want %d lines, got %d", n, len(lines))
	}
	for _, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Fatalf("interleaved or truncated line: %q", l)
		}
	}
}

func TestOpenFileAppendsCreatesAndIsNotWorldAccessible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	f1, err := OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile (create): %v", err)
	}
	NewWithFile(&bytes.Buffer{}, f1, &bytes.Buffer{}).Emit(sampleEvent("c_one"))
	if err := f1.Close(); err != nil {
		t.Fatal(err)
	}

	// A second open (a restarted pod) must append, never truncate.
	f2, err := OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile (reopen): %v", err)
	}
	NewWithFile(&bytes.Buffer{}, f2, &bytes.Buffer{}).Emit(sampleEvent("c_two"))
	if err := f2.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "c_one") || !strings.Contains(lines[1], "c_two") {
		t.Fatalf("reopen must append to the existing trail, got %q", raw)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// 0640 requested; the umask may only remove bits, never add them.
	if perm := st.Mode().Perm(); perm&^0o640 != 0 {
		t.Fatalf("audit file mode = %o, want no more permissive than 0640", perm)
	}
}

func TestOpenFileFailsWhenPathIsNotWritable(t *testing.T) {
	// A parent directory that does not exist stands in for a missing or
	// read-only volume; the service turns this error into a non-zero exit.
	_, err := OpenFile(filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl"))
	if err == nil {
		t.Fatal("OpenFile should fail when the directory does not exist")
	}
}
