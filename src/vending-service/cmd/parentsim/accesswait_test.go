package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func decodeAccessEvents(t *testing.T, b []byte) []accessWaitEvent {
	t.Helper()
	var evs []accessWaitEvent
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var ev accessWaitEvent
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("decode %q: %v", b, err)
		}
		evs = append(evs, ev)
	}
	return evs
}

// jwtAfter fails n-1 times with "no identity issued" and then returns a token
// for subject.
func jwtAfter(n int32, subject string, calls *atomic.Int32) jwtFetcher {
	return func(ctx context.Context) (string, string, error) {
		if calls.Add(1) < n {
			return "", "", errNoIdentity
		}
		return "token-" + subject, subject, nil
	}
}

func x509After(n int32, calls *atomic.Int32) x509IDFetcher {
	return func(ctx context.Context) (string, error) {
		if calls.Add(1) < n {
			return "", errNoIdentity
		}
		return wantID, nil
	}
}

// statuses answers the i-th call with codes[i] (the last code repeats) and
// records the tokens it was given.
func statuses(calls *atomic.Int32, tokens *[]string, codes ...int) resourceCaller {
	return func(ctx context.Context, token string) (int, error) {
		i := int(calls.Add(1)) - 1
		*tokens = append(*tokens, token)
		if i >= len(codes) {
			i = len(codes) - 1
		}
		return codes[i], nil
	}
}

func noX509(ctx context.Context) (string, error) {
	return "", errors.New("poll must not fetch an X.509-SVID")
}

func TestAccessWaitPollGrantsAtTheFirst200(t *testing.T) {
	var jwtCalls, resCalls atomic.Int32
	var tokens []string
	var out bytes.Buffer
	ev, err := runAccessWait(context.Background(), noX509, jwtAfter(4, wantID, &jwtCalls), statuses(&resCalls, &tokens, 403, 200),
		accessWaitConfig{Style: "poll", ExpectID: wantID, Interval: 2 * time.Millisecond, Timeout: 5 * time.Second},
		&out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "granted" || ev.Status != 200 {
		t.Fatalf("final event = %+v, want granted 200", ev)
	}
	// 3 JWT misses, then the token (and a 403 in the same tick), then a 200.
	if ev.JWTAttempts != 4 || ev.ResourceAttempts != 2 || ev.Attempts != 5 || ev.Misses != 4 {
		t.Fatalf("counts: jwt %d resource %d attempts %d misses %d, want 4 2 5 4",
			ev.JWTAttempts, ev.ResourceAttempts, ev.Attempts, ev.Misses)
	}
	if ev.MissReasons["resource: HTTP 403"] != 1 || ev.MissReasons["jwt: "+errNoIdentity.Error()] != 3 {
		t.Fatalf("miss reasons = %v", ev.MissReasons)
	}
	for _, tok := range tokens {
		if tok != "token-"+wantID {
			t.Fatalf("resource got token %q, want the child's", tok)
		}
	}
	if !(ev.FirstSendNs < ev.JWTSendNs && ev.JWTSendNs <= ev.JWTRecvNs && ev.JWTRecvNs <= ev.SendNs && ev.SendNs <= ev.RecvNs) {
		t.Fatalf("timestamps out of order: %+v", ev)
	}
	if ev.LastMissSendNs == 0 || ev.LastMissSendNs >= ev.SendNs {
		t.Fatalf("last miss %d should precede the granting request %d", ev.LastMissSendNs, ev.SendNs)
	}
	evs := decodeAccessEvents(t, out.Bytes())
	if len(evs) != 2 || evs[0].Event != "ready" || evs[1].Event != "granted" {
		t.Fatalf("events = %+v, want ready then granted", evs)
	}
}

func TestAccessWaitPollTreatsAnotherSubjectAsAMiss(t *testing.T) {
	var calls, resCalls atomic.Int32
	var tokens []string
	fetch := func(ctx context.Context) (string, string, error) {
		if calls.Add(1) <= 2 {
			return "token-other", "spiffe://lab.local/other", nil
		}
		return "token-" + wantID, wantID, nil
	}
	ev, err := runAccessWait(context.Background(), noX509, fetch, statuses(&resCalls, &tokens, 200),
		accessWaitConfig{Style: "poll", ExpectID: wantID, Interval: 2 * time.Millisecond, Timeout: 5 * time.Second},
		&bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "granted" || ev.Misses != 2 || len(tokens) != 1 || tokens[0] != "token-"+wantID {
		t.Fatalf("event %+v tokens %v: want granted after 2 misses, the child's token only", ev, tokens)
	}
}

func TestAccessWaitPollRejectsAnIdentityHeldBeforeTheStart(t *testing.T) {
	var calls, resCalls atomic.Int32
	var tokens []string
	ev, err := runAccessWait(context.Background(), noX509, jwtAfter(1, wantID, &calls), statuses(&resCalls, &tokens, 200),
		accessWaitConfig{Style: "poll", ExpectID: wantID, Interval: 2 * time.Millisecond, Timeout: 5 * time.Second},
		&bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "unexpected" || len(tokens) != 0 {
		t.Fatalf("event %+v, resource calls %d: want unexpected and no resource call", ev, len(tokens))
	}
}

func TestAccessWaitPollTimesOut(t *testing.T) {
	var calls, resCalls atomic.Int32
	var tokens []string
	ev, err := runAccessWait(context.Background(), noX509, jwtAfter(1<<30, wantID, &calls), statuses(&resCalls, &tokens, 200),
		accessWaitConfig{Style: "poll", ExpectID: wantID, Interval: 5 * time.Millisecond, Timeout: 40 * time.Millisecond},
		&bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "timeout" || ev.Attempts == 0 {
		t.Fatalf("event = %+v, want timeout after some attempts", ev)
	}
}

func TestAccessWaitChildPyRetriesLikeChildPy(t *testing.T) {
	var xCalls, jCalls, resCalls atomic.Int32
	var tokens []string
	delay := 15 * time.Millisecond
	var out bytes.Buffer
	ev, err := runAccessWait(context.Background(), x509After(3, &xCalls), jwtAfter(2, wantID, &jCalls), statuses(&resCalls, &tokens, 200),
		accessWaitConfig{Style: "child-py", ExpectID: wantID, RetryDelay: delay, RetryAttempts: 30, Timeout: 5 * time.Second},
		&out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "granted" || ev.Status != 200 || ev.Subject != wantID {
		t.Fatalf("final event = %+v, want granted 200 for the child", ev)
	}
	if ev.X509Attempts != 3 || ev.JWTAttempts != 2 || ev.ResourceAttempts != 1 || ev.Misses != 3 || ev.Attempts != 6 {
		t.Fatalf("counts: x509 %d jwt %d resource %d misses %d attempts %d, want 3 2 1 3 6",
			ev.X509Attempts, ev.JWTAttempts, ev.ResourceAttempts, ev.Misses, ev.Attempts)
	}
	// Each failed fetch is followed by the retry delay, so the X.509-SVID
	// arrives no sooner than two delays after the first attempt.
	if got := time.Duration(ev.X509SendNs - ev.FirstSendNs); got < 2*delay {
		t.Fatalf("x509 obtained %v after the first attempt, want >= %v", got, 2*delay)
	}
	if got := time.Duration(ev.JWTSendNs - ev.X509RecvNs); got < delay {
		t.Fatalf("jwt obtained %v after the x509, want >= %v (one failed fetch)", got, delay)
	}
	if !(ev.X509RecvNs <= ev.JWTSendNs && ev.JWTRecvNs <= ev.SendNs && ev.SendNs <= ev.RecvNs) {
		t.Fatalf("timestamps out of order: %+v", ev)
	}
	if evs := decodeAccessEvents(t, out.Bytes()); len(evs) != 1 || evs[0].Event != "granted" {
		t.Fatalf("events = %+v, want only the final granted (no ready in child-py)", evs)
	}
}

func TestAccessWaitChildPySendsOneRequestAndReportsARefusal(t *testing.T) {
	var xCalls, jCalls, resCalls atomic.Int32
	var tokens []string
	ev, err := runAccessWait(context.Background(), x509After(1, &xCalls), jwtAfter(1, wantID, &jCalls), statuses(&resCalls, &tokens, 403, 200),
		accessWaitConfig{Style: "child-py", ExpectID: wantID, RetryDelay: time.Millisecond, RetryAttempts: 30, Timeout: 5 * time.Second},
		&bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "refused" || ev.Status != 403 || len(tokens) != 1 {
		t.Fatalf("event %+v after %d requests, want refused 403 after exactly one", ev, len(tokens))
	}
}

func TestAccessWaitChildPyGivesUpAfterItsAttempts(t *testing.T) {
	var xCalls, jCalls, resCalls atomic.Int32
	var tokens []string
	ev, err := runAccessWait(context.Background(), x509After(1<<30, &xCalls), jwtAfter(1, wantID, &jCalls), statuses(&resCalls, &tokens, 200),
		accessWaitConfig{Style: "child-py", ExpectID: wantID, RetryDelay: time.Millisecond, RetryAttempts: 4, Timeout: 5 * time.Second},
		&bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "gave_up" || ev.X509Attempts != 4 || jCalls.Load() != 0 || len(tokens) != 0 {
		t.Fatalf("event %+v (jwt calls %d, resource calls %d), want gave_up after 4 x509 attempts and nothing else",
			ev, jCalls.Load(), len(tokens))
	}
	if !strings.Contains(ev.Error, "all 4 attempts") {
		t.Fatalf("error = %q", ev.Error)
	}
}

func TestAccessWaitValidatesItsConfig(t *testing.T) {
	var calls, resCalls atomic.Int32
	var tokens []string
	for name, cfg := range map[string]accessWaitConfig{
		"no expected id":   {Style: "poll", Interval: time.Millisecond, Timeout: time.Second},
		"unknown style":    {Style: "watch", ExpectID: wantID, Timeout: time.Second},
		"no poll interval": {Style: "poll", ExpectID: wantID, Timeout: time.Second},
		"no retry delay":   {Style: "child-py", ExpectID: wantID, RetryAttempts: 3, Timeout: time.Second},
	} {
		if _, err := runAccessWait(context.Background(), noX509, jwtAfter(1, wantID, &calls), statuses(&resCalls, &tokens, 200),
			cfg, &bytes.Buffer{}, time.Now); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
