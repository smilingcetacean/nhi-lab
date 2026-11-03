package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func decodeEvents(t *testing.T, b []byte) []pollEvent {
	t.Helper()
	var evs []pollEvent
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var ev pollEvent
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("decode %q: %v", b, err)
		}
		evs = append(evs, ev)
	}
	return evs
}

// statusAfter serves 200 for the first n requests and `then` afterwards.
func statusAfter(n int32, then int, seen *atomic.Int32, gotAuth *atomic.Value) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		if seen.Add(1) <= n {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(then)
	})
}

func TestRunPollReportsFirstDenial(t *testing.T) {
	var seen atomic.Int32
	var auth atomic.Value
	srv := httptest.NewServer(statusAfter(5, http.StatusForbidden, &seen, &auth))
	defer srv.Close()

	var out bytes.Buffer
	ev, err := runPoll(context.Background(), srv.Client(),
		pollConfig{URL: srv.URL, Bearer: "tok", Interval: 2 * time.Millisecond, Timeout: 5 * time.Second},
		&out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "denied" || ev.Status != 403 {
		t.Fatalf("final event = %+v, want denied/403", ev)
	}
	if ev.Polls != 6 {
		t.Errorf("polls = %d, want 6 (five allowed, one denied)", ev.Polls)
	}
	if got := auth.Load(); got != "Bearer tok" {
		t.Errorf("Authorization = %v, want the supplied bearer token", got)
	}
	if !(ev.LastAllowedRecvNs <= ev.SendNs+int64(time.Millisecond) && ev.LastAllowedSendNs < ev.SendNs && ev.SendNs <= ev.RecvNs) {
		t.Errorf("timestamps out of order: %+v", ev)
	}
	// The loop must keep to its interval: gaps are send-to-send and cannot be
	// shorter than the target.
	if ev.GapMeanNs < int64(2*time.Millisecond) {
		t.Errorf("mean gap %d ns is below the 2 ms interval", ev.GapMeanNs)
	}

	evs := decodeEvents(t, out.Bytes())
	if len(evs) != 2 || evs[0].Event != "ready" || evs[1].Event != "denied" {
		t.Fatalf("output events = %+v, want ready then denied", evs)
	}
	if evs[0].Status != 200 {
		t.Errorf("ready status = %d, want 200", evs[0].Status)
	}
}

func TestRunPollDeniedImmediatelyHasNoReady(t *testing.T) {
	var seen atomic.Int32
	var auth atomic.Value
	srv := httptest.NewServer(statusAfter(0, http.StatusForbidden, &seen, &auth))
	defer srv.Close()

	var out bytes.Buffer
	ev, err := runPoll(context.Background(), srv.Client(),
		pollConfig{URL: srv.URL, Bearer: "tok", Interval: time.Millisecond, Timeout: 5 * time.Second}, &out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "denied" || ev.LastAllowedSendNs != 0 {
		t.Fatalf("event = %+v, want denied with no allowed response before it", ev)
	}
	if evs := decodeEvents(t, out.Bytes()); len(evs) != 1 {
		t.Fatalf("events = %+v, want only the final line", evs)
	}
}

// A 401 means the token was refused before policy was asked. It must not be
// mistaken for a revocation.
func TestRunPollTreatsOtherStatusesAsUnexpected(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusBadGateway} {
		var seen atomic.Int32
		var auth atomic.Value
		srv := httptest.NewServer(statusAfter(2, code, &seen, &auth))
		var out bytes.Buffer
		ev, err := runPoll(context.Background(), srv.Client(),
			pollConfig{URL: srv.URL, Bearer: "tok", Interval: time.Millisecond, Timeout: 5 * time.Second}, &out, time.Now)
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if ev.Event != "unexpected" || ev.Status != code {
			t.Errorf("status %d: event = %+v, want unexpected/%d", code, ev, code)
		}
	}
}

func TestRunPollTimesOutWhenNeverDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	var out bytes.Buffer
	start := time.Now()
	ev, err := runPoll(context.Background(), srv.Client(),
		pollConfig{URL: srv.URL, Bearer: "tok", Interval: 5 * time.Millisecond, Timeout: 100 * time.Millisecond}, &out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "timeout" || ev.Polls < 2 {
		t.Fatalf("event = %+v, want timeout after several polls", ev)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v, the 100 ms timeout was not honoured", el)
	}
}

func TestRunPollCountsTransportErrorsAndKeepsGoing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening any more

	var out bytes.Buffer
	ev, err := runPoll(context.Background(), &http.Client{Timeout: time.Second},
		pollConfig{URL: url, Bearer: "tok", Interval: 5 * time.Millisecond, Timeout: 100 * time.Millisecond}, &out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "timeout" || ev.TransportErrs == 0 || ev.TransportErrs != ev.Polls {
		t.Fatalf("event = %+v, want a timeout in which every poll was a transport error", ev)
	}
}

func TestRunPollRejectsNonPositiveInterval(t *testing.T) {
	_, err := runPoll(context.Background(), http.DefaultClient,
		pollConfig{URL: "http://127.0.0.1:1", Interval: 0, Timeout: time.Second}, &bytes.Buffer{}, time.Now)
	if err == nil || !strings.Contains(err.Error(), "interval") {
		t.Fatalf("err = %v, want an interval error", err)
	}
}

// With a slow server the loop must not pile up requests: the next one goes out
// when the previous answer arrives, so the achieved gap grows past the target
// and is reported as such.
func TestRunPollReportsAchievedGapWhenServerIsSlow(t *testing.T) {
	var seen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		if seen.Add(1) > 3 {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()

	ev, err := runPoll(context.Background(), srv.Client(),
		pollConfig{URL: srv.URL, Bearer: "t", Interval: time.Millisecond, Timeout: 5 * time.Second}, &bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.GapMaxNs < int64(20*time.Millisecond) || ev.LatencyMaxNs < int64(20*time.Millisecond) {
		t.Errorf("gap max %d ns / latency max %d ns: both should reflect the 20 ms server delay", ev.GapMaxNs, ev.LatencyMaxNs)
	}
}

func TestTimedDeleteRecordsBothInstants(t *testing.T) {
	var method, auth, path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method.Store(r.Method)
		auth.Store(r.Header.Get("Authorization"))
		path.Store(r.URL.Path)
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	res, err := timedRequest(context.Background(), srv.Client(), http.MethodDelete, srv.URL+"/delegations/abc", "tok", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if method.Load() != "DELETE" || auth.Load() != "Bearer tok" || path.Load() != "/delegations/abc" {
		t.Errorf("server saw %v %v %v", method.Load(), path.Load(), auth.Load())
	}
	if res.Status != 200 || res.Response != `{"ok":true}` {
		t.Errorf("result = %+v", res)
	}
	if res.RecvNs <= res.SendNs || res.RoundNs != res.RecvNs-res.SendNs || res.RoundNs < int64(10*time.Millisecond) {
		t.Errorf("send/recv/round trip inconsistent: %+v", res)
	}
}

func TestTimedDeleteReportsErrorStatusWithoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	res, err := timedRequest(context.Background(), srv.Client(), http.MethodDelete, srv.URL, "tok", nil, time.Now)
	if err != nil || res.Status != 403 {
		t.Fatalf("res=%+v err=%v, want status 403 and no error", res, err)
	}
}
