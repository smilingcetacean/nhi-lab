package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const wantID = "spiffe://lab.local/agent/parent/exp-root/child/c1"

var errNoIdentity = errors.New("rpc error: code = PermissionDenied desc = no identity issued")

func decodeWaitEvents(t *testing.T, b []byte) []svidWaitEvent {
	t.Helper()
	var evs []svidWaitEvent
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var ev svidWaitEvent
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("decode %q: %v", b, err)
		}
		evs = append(evs, ev)
	}
	return evs
}

// identityAfter misses n times (no identity, then another ID only) and then
// returns the expected identity alongside another one.
func identityAfter(n int32, calls *atomic.Int32) svidFetcher {
	return func(ctx context.Context) ([]heldSVID, error) {
		c := calls.Add(1)
		switch {
		case c <= n-1:
			return nil, errNoIdentity
		case c == n:
			return []heldSVID{{ID: "spiffe://lab.local/other"}}, nil
		default:
			return []heldSVID{{ID: "spiffe://lab.local/other"}, {ID: wantID, NotAfter: time.Unix(1_800_000_000, 0)}}, nil
		}
	}
}

func TestRunSVIDWaitReportsFirstFetchWithTheIdentity(t *testing.T) {
	var calls atomic.Int32
	var out bytes.Buffer
	ev, err := runSVIDWait(context.Background(), identityAfter(4, &calls),
		svidWaitConfig{ExpectID: wantID, Interval: 2 * time.Millisecond, Timeout: 5 * time.Second},
		&out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "obtained" {
		t.Fatalf("final event = %+v, want obtained", ev)
	}
	if ev.Attempts != 5 || ev.Misses != 4 {
		t.Errorf("attempts/misses = %d/%d, want 5/4", ev.Attempts, ev.Misses)
	}
	if ev.MissReasons[errNoIdentity.Error()] != 3 || ev.MissReasons["held other identities only"] != 1 {
		t.Errorf("miss reasons = %v", ev.MissReasons)
	}
	if len(ev.SPIFFEIDs) != 2 || ev.NotAfter != "2027-01-15T08:00:00Z" {
		t.Errorf("ids/not_after = %v %q", ev.SPIFFEIDs, ev.NotAfter)
	}
	if !(ev.LastMissSendNs < ev.SendNs && ev.LastMissRecvNs <= ev.SendNs && ev.SendNs <= ev.RecvNs) {
		t.Errorf("timestamps out of order: %+v", ev)
	}
	if ev.GapMeanNs < int64(2*time.Millisecond) {
		t.Errorf("mean gap %d ns is below the 2 ms interval", ev.GapMeanNs)
	}

	evs := decodeWaitEvents(t, out.Bytes())
	if len(evs) != 2 || evs[0].Event != "ready" || evs[1].Event != "obtained" {
		t.Fatalf("output events = %+v, want ready then obtained", evs)
	}
	if evs[0].MissReason != errNoIdentity.Error() {
		t.Errorf("ready miss reason = %q", evs[0].MissReason)
	}
}

func TestRunSVIDWaitRejectsAnIdentityHeldBeforeTheStart(t *testing.T) {
	var out bytes.Buffer
	fetch := func(ctx context.Context) ([]heldSVID, error) { return []heldSVID{{ID: wantID}}, nil }
	ev, err := runSVIDWait(context.Background(), fetch,
		svidWaitConfig{ExpectID: wantID, Interval: time.Millisecond, Timeout: time.Second}, &out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "unexpected" || ev.Attempts != 1 {
		t.Fatalf("final event = %+v, want unexpected after one fetch", ev)
	}
	if evs := decodeWaitEvents(t, out.Bytes()); len(evs) != 1 {
		t.Errorf("output events = %+v, want only the final one (no ready)", evs)
	}
}

func TestRunSVIDWaitTimesOut(t *testing.T) {
	var out bytes.Buffer
	fetch := func(ctx context.Context) ([]heldSVID, error) { return nil, errNoIdentity }
	ev, err := runSVIDWait(context.Background(), fetch,
		svidWaitConfig{ExpectID: wantID, Interval: 5 * time.Millisecond, Timeout: 60 * time.Millisecond}, &out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "timeout" || ev.Attempts == 0 || ev.Misses != ev.Attempts {
		t.Fatalf("final event = %+v, want timeout with every attempt a miss", ev)
	}
}

func TestRunSVIDWaitBoundsEachFetch(t *testing.T) {
	// A fetch that hangs until its context ends must count as a miss and let
	// the loop go on, not stall the wait.
	var calls atomic.Int32
	fetch := func(ctx context.Context) ([]heldSVID, error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []heldSVID{{ID: wantID}}, nil
	}
	ev, err := runSVIDWait(context.Background(), fetch,
		svidWaitConfig{ExpectID: wantID, Interval: time.Millisecond, Timeout: 2 * time.Second, AttemptTimeout: 20 * time.Millisecond},
		io.Discard, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "obtained" || ev.Attempts != 2 || ev.MissReasons[context.DeadlineExceeded.Error()] != 1 {
		t.Fatalf("final event = %+v, want obtained on the second fetch after one timed-out miss", ev)
	}
}

func TestRunSVIDWaitRequiresAnExpectedID(t *testing.T) {
	fetch := func(ctx context.Context) ([]heldSVID, error) { return nil, nil }
	if _, err := runSVIDWait(context.Background(), fetch, svidWaitConfig{Interval: time.Millisecond, Timeout: time.Second}, io.Discard, time.Now); err == nil {
		t.Fatal("want an error without -expect-id")
	}
}

func TestTimedRequestSendsBodyAsJSON(t *testing.T) {
	var method, ctype, body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method.Store(r.Method)
		ctype.Store(r.Header.Get("Content-Type"))
		b, _ := io.ReadAll(r.Body)
		body.Store(string(b))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"chain_id":"x"}`))
	}))
	defer srv.Close()

	res, err := timedRequest(context.Background(), srv.Client(), http.MethodPost, srv.URL+"/delegations", "tok", []byte(`{"m":1}`), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if method.Load() != "POST" || ctype.Load() != "application/json" || body.Load() != `{"m":1}` {
		t.Errorf("server saw %v %v %v", method.Load(), ctype.Load(), body.Load())
	}
	if res.Status != 201 || res.Response != `{"chain_id":"x"}` || res.RecvNs < res.SendNs {
		t.Errorf("result = %+v", res)
	}
}
