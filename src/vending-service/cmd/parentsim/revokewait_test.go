package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func decodeRevokeEvents(t *testing.T, b []byte) []revokeWaitEvent {
	t.Helper()
	var evs []revokeWaitEvent
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var ev revokeWaitEvent
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("decode %q: %v", b, err)
		}
		evs = append(evs, ev)
	}
	return evs
}

// scriptedFetch answers the i-th fetch with steps[i]; the last step repeats. An
// empty token means "fail with no identity issued".
type fetchStep struct {
	token   string
	subject string
}

func scriptedFetch(calls *atomic.Int32, steps ...fetchStep) jwtFetcher {
	return func(ctx context.Context) (string, string, error) {
		i := int(calls.Add(1)) - 1
		if i >= len(steps) {
			i = len(steps) - 1
		}
		if steps[i].token == "" {
			return "", "", errNoIdentity
		}
		return steps[i].token, steps[i].subject, nil
	}
}

func good(token string) fetchStep { return fetchStep{token: token, subject: wantID} }

var gone = fetchStep{}

// repeat returns n copies of s.
func repeat(s fetchStep, n int) []fetchStep {
	out := make([]fetchStep, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func revokeCfg() revokeWaitConfig {
	return revokeWaitConfig{ExpectID: wantID, Interval: 2 * time.Millisecond, Timeout: 5 * time.Second}
}

func TestRevokeWaitReportsTheFirst403ThenTheFailedFetch(t *testing.T) {
	var fCalls, rCalls atomic.Int32
	var tokens []string
	// 3 ticks answered 200, 2 answered 403, then the fetch fails. The token
	// changes once, after the first 403.
	steps := append(repeat(good("tok-a"), 5), good("tok-b"), gone)
	var out bytes.Buffer
	ev, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, steps...),
		statuses(&rCalls, &tokens, 200, 200, 200, 403, 403, 403), revokeCfg(), &out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "identity_gone" || ev.Error != "" {
		t.Fatalf("final event = %+v, want identity_gone", ev)
	}
	// Fetches: 5 + 1 succeeded; the 7th failed and sent no request.
	if fCalls.Load() != 7 || len(tokens) != 6 {
		t.Fatalf("fetch calls %d, resource calls %d, want 7 and 6 (no request after the failed fetch)", fCalls.Load(), len(tokens))
	}
	if ev.Polls != 7 || ev.Denials != 3 || ev.TransportErrs != 0 || len(ev.OtherStatuses) != 0 {
		t.Fatalf("polls %d denials %d transport %d other %v, want 7 3 0 none", ev.Polls, ev.Denials, ev.TransportErrs, ev.OtherStatuses)
	}
	if ev.DistinctTokens != 2 {
		t.Fatalf("distinct tokens = %d, want 2", ev.DistinctTokens)
	}
	if ev.First403TokenIsReadyToken == nil || !*ev.First403TokenIsReadyToken {
		t.Fatalf("first 403 token is the ready token: %v, want true (tok-a throughout until the 6th tick)", ev.First403TokenIsReadyToken)
	}
	if ev.ReadyTokenSHA256 != tokenDigest("tok-a") || ev.First403TokenSHA256 != tokenDigest("tok-a") {
		t.Fatalf("digests ready %q first403 %q, want the digest of tok-a", ev.ReadyTokenSHA256, ev.First403TokenSHA256)
	}
	if strings.Contains(out.String(), "tok-a") || strings.Contains(out.String(), "tok-b") {
		t.Fatalf("output contains a token: %s", out.String())
	}
	if ev.FailedFetchError != errNoIdentity.Error() {
		t.Fatalf("failed fetch error = %q", ev.FailedFetchError)
	}
	// Stamps: the 403's fetch precedes the 403's request, the last 200 precedes the
	// first 403, the last good fetch precedes the failed one.
	if !(ev.Last200SendNs <= ev.Last200RecvNs && ev.Last200RecvNs <= ev.First403JWTSendNs &&
		ev.First403JWTSendNs <= ev.First403JWTRecvNs && ev.First403JWTRecvNs <= ev.First403SendNs &&
		ev.First403SendNs <= ev.First403RecvNs) {
		t.Fatalf("timestamps out of order: %+v", ev)
	}
	if !(ev.LastFetchOKSendNs <= ev.LastFetchOKRecvNs && ev.LastFetchOKRecvNs <= ev.FailedFetchSendNs &&
		ev.FailedFetchSendNs <= ev.FailedFetchRecvNs && ev.First403RecvNs <= ev.FailedFetchRecvNs) {
		t.Fatalf("fetch timestamps out of order: %+v", ev)
	}
	if ev.GapMeanNs <= 0 || ev.GapMaxNs < ev.GapMeanNs || ev.FetchLatencyMaxNs < ev.FetchLatencyMeanNs || ev.CallLatencyMaxNs < ev.CallLatencyMeanNs {
		t.Fatalf("statistics not populated: %+v", ev)
	}
	evs := decodeRevokeEvents(t, out.Bytes())
	if len(evs) != 2 || evs[0].Event != "ready" || evs[1].Event != "identity_gone" {
		t.Fatalf("events = %+v, want ready then identity_gone", evs)
	}
	r := evs[0]
	if r.Status != 200 || r.TokenSHA256 != tokenDigest("tok-a") ||
		!(r.JWTSendNs <= r.JWTRecvNs && r.JWTRecvNs <= r.SendNs && r.SendNs <= r.RecvNs) {
		t.Fatalf("ready event = %+v", r)
	}
}

func TestRevokeWaitFlagsADifferentTokenAtTheFirst403(t *testing.T) {
	var fCalls, rCalls atomic.Int32
	var tokens []string
	steps := []fetchStep{good("tok-a"), good("tok-b"), gone}
	ev, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, steps...),
		statuses(&rCalls, &tokens, 200, 403), revokeCfg(), &bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "identity_gone" || ev.First403TokenIsReadyToken == nil || *ev.First403TokenIsReadyToken || ev.DistinctTokens != 2 {
		t.Fatalf("event %+v: want identity_gone, first 403 on a different token, 2 distinct tokens", ev)
	}
}

func TestRevokeWaitFetchFailureBeforeAny403(t *testing.T) {
	var fCalls, rCalls atomic.Int32
	var tokens []string
	out := &bytes.Buffer{}
	ev, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, good("tok-a"), good("tok-a"), gone),
		statuses(&rCalls, &tokens, 200), revokeCfg(), out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "no_deny_before_identity_gone" || ev.Denials != 0 || ev.First403RecvNs != 0 || ev.FailedFetchRecvNs == 0 {
		t.Fatalf("event = %+v, want no_deny_before_identity_gone with the failed fetch stamped and no 403", ev)
	}
	if ev.Last200SendNs == 0 || ev.FailedFetchError == "" || len(tokens) != 2 {
		t.Fatalf("event = %+v, requests %d", ev, len(tokens))
	}
}

func TestRevokeWaitWaitsForTheFirst200BeforeReady(t *testing.T) {
	var fCalls, rCalls atomic.Int32
	var tokens []string
	// no identity yet, another subject, a 403 before the grant is in, then 200, then gone.
	steps := []fetchStep{gone, {token: "tok-x", subject: "spiffe://lab.local/other"}, good("tok-a"), good("tok-a"), good("tok-a"), gone}
	var out bytes.Buffer
	ev, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, steps...),
		statuses(&rCalls, &tokens, 403, 200, 403), revokeCfg(), &out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "identity_gone" || ev.PreReadyFetchFails != 2 || ev.PreReadyDenials != 1 || ev.Denials != 1 {
		t.Fatalf("event = %+v, want identity_gone after 2 pre-ready fetch misses, 1 pre-ready 403 and 1 later 403", ev)
	}
	if len(tokens) != 3 || tokens[0] != "tok-a" {
		t.Fatalf("resource tokens = %v, want only the child's", tokens)
	}
	if evs := decodeRevokeEvents(t, out.Bytes()); len(evs) != 2 || evs[0].Event != "ready" {
		t.Fatalf("events = %+v", evs)
	}
}

func TestRevokeWaitUnexpectedStatus(t *testing.T) {
	for _, status := range []int{401, 404, 503} {
		var fCalls, rCalls atomic.Int32
		var tokens []string
		ev, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, good("tok-a")),
			statuses(&rCalls, &tokens, 200, status), revokeCfg(), &bytes.Buffer{}, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Event != "unexpected" || ev.Status != status || ev.OtherStatuses[strconv.Itoa(status)] != 1 {
			t.Fatalf("status %d: event = %+v, want unexpected with the status recorded", status, ev)
		}
		if len(tokens) != 2 || fCalls.Load() != 2 {
			t.Fatalf("status %d: the run went on after an unexpected status (%d requests)", status, len(tokens))
		}
	}
}

func TestRevokeWaitA200After403IsUnexpected(t *testing.T) {
	var fCalls, rCalls atomic.Int32
	var tokens []string
	ev, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, good("tok-a")),
		statuses(&rCalls, &tokens, 200, 403, 200), revokeCfg(), &bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "unexpected" || ev.Status != 200 || ev.Denials != 1 {
		t.Fatalf("event = %+v, want unexpected: 200 after a 403", ev)
	}
}

func TestRevokeWaitAnotherSubjectAfterReadyIsUnexpected(t *testing.T) {
	var fCalls, rCalls atomic.Int32
	var tokens []string
	other := "spiffe://lab.local/other"
	ev, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, good("tok-a"), fetchStep{token: "tok-x", subject: other}),
		statuses(&rCalls, &tokens, 200), revokeCfg(), &bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "unexpected" || ev.Subject != other || len(tokens) != 1 {
		t.Fatalf("event %+v, requests %d: want unexpected naming the subject, no request with its token", ev, len(tokens))
	}
}

func TestRevokeWaitCountsTransportErrorsAndCarriesOn(t *testing.T) {
	var fCalls, rCalls atomic.Int32
	call := func(ctx context.Context, token string) (int, error) {
		switch rCalls.Add(1) {
		case 2:
			return 0, errors.New("connection reset")
		case 1:
			return 200, nil
		}
		return 403, nil
	}
	ev, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, append(repeat(good("tok-a"), 4), gone)...),
		call, revokeCfg(), &bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "identity_gone" || ev.TransportErrs != 1 || ev.Denials != 2 {
		t.Fatalf("event = %+v, want identity_gone with 1 transport error and 2 denials", ev)
	}
}

func TestRevokeWaitTimesOut(t *testing.T) {
	var fCalls, rCalls atomic.Int32
	var tokens []string
	cfg := revokeWaitConfig{ExpectID: wantID, Interval: 5 * time.Millisecond, Timeout: 40 * time.Millisecond}

	// Allowed throughout: the identity never goes.
	ev, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, good("tok-a")),
		statuses(&rCalls, &tokens, 200), cfg, &bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "timeout" || ev.Polls == 0 || ev.Last200SendNs == 0 {
		t.Fatalf("event = %+v, want timeout after some ticks", ev)
	}

	// Never allowed: not_ready.
	fCalls.Store(0)
	rCalls.Store(0)
	tokens = nil
	ev, err = runRevokeWait(context.Background(), scriptedFetch(&fCalls, good("tok-a")),
		statuses(&rCalls, &tokens, 403), cfg, &bytes.Buffer{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "not_ready" || ev.PreReadyDenials == 0 {
		t.Fatalf("event = %+v, want not_ready", ev)
	}
}

func TestRevokeWaitValidatesItsConfig(t *testing.T) {
	var fCalls, rCalls atomic.Int32
	var tokens []string
	for name, cfg := range map[string]revokeWaitConfig{
		"no expected id":   {Interval: time.Millisecond, Timeout: time.Second},
		"no poll interval": {ExpectID: wantID, Timeout: time.Second},
	} {
		if _, err := runRevokeWait(context.Background(), scriptedFetch(&fCalls, good("tok-a")), statuses(&rCalls, &tokens, 200),
			cfg, &bytes.Buffer{}, time.Now); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
