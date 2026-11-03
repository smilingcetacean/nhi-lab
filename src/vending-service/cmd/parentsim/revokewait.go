package main

// revoke-wait is the revoked child's side of the revoke-to-deny measurement: how
// long after its parent sends DELETE /delegations/{chain_id} does the child first
// see a refusal, and how long until it can no longer obtain a credential at all?
//
// It runs in the child's pod. The parent's side is dispose-timed (poll.go), which
// stamps the instant just before it writes the DELETE. Both use the wall clock in
// Unix nanoseconds, under the same single-host clock assumption as poll.go.
//
// Every tick (-poll-interval) the child fetches a fresh JWT-SVID for the
// resource's audience from its SPIRE agent, through one long-lived Workload API
// client as a go-spiffe JWT source does on each call, and in the same tick sends
// the request to the resource with it:
//
//   - 200: the child is allowed. The first one is reported as "ready", so the
//     caller can revoke from a running loop.
//   - 403: the resource accepted the token (the agent still hands out a valid
//     JWT-SVID until it has synced) and policy refused the child. This is the
//     denial the revocation produces. The loop carries on.
//   - the fetch fails: the agent no longer issues the child an identity
//     ("no identity issued"). The loop stops, and the request is NOT sent: a
//     client with no token has nothing to present.
//
// A revoked child's JWT-SVID stays cryptographically valid until it expires, so
// the resource answers 401 only for a missing, malformed, expired or otherwise
// invalid token. No 401 is expected, and none is produced here: any status other
// than 200 and 403 ends the run as "unexpected".

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// revokeWaitConfig describes one run.
type revokeWaitConfig struct {
	ExpectID       string        // the SPIFFE ID the child holds before the revoke
	Interval       time.Duration // target gap between ticks
	Timeout        time.Duration // give up after this long
	AttemptTimeout time.Duration // bound on a single fetch or request
}

// revokeWaitEvent is one line of revoke-wait's output (JSON lines, on stdout).
//
// "ready" follows the first 200. The final line is "identity_gone" (a fetch
// failed after at least one 403), "no_deny_before_identity_gone" (a fetch failed
// before any 403), "unexpected" (a status other than 200 or 403, a 200 after a
// 403, or another subject), "not_ready" (the deadline passed before the first
// 200) or "timeout" (it passed after "ready" without the identity going).
type revokeWaitEvent struct {
	Event string `json:"event"`

	// Status is the HTTP status that ended an "unexpected" run, or that of the
	// first 200 for "ready".
	Status int `json:"status,omitempty"`

	// For "ready": the first 200's request, the fetch that supplied its token in
	// the same tick, and a short digest of that token. Tokens are never printed.
	SendNs      int64  `json:"send_ns,omitempty"`
	RecvNs      int64  `json:"recv_ns,omitempty"`
	JWTSendNs   int64  `json:"jwt_send_ns,omitempty"`
	JWTRecvNs   int64  `json:"jwt_recv_ns,omitempty"`
	TokenSHA256 string `json:"token_sha256_prefix,omitempty"`

	// Final line. First403*: the first 403's request, and the fetch in its tick.
	// Last200*: the last request answered 200. LastFetchOK*: the last fetch that
	// returned a token. FailedFetch*: the fetch that failed, and why.
	First403SendNs      int64  `json:"first_403_send_ns,omitempty"`
	First403RecvNs      int64  `json:"first_403_recv_ns,omitempty"`
	First403JWTSendNs   int64  `json:"first_403_jwt_send_ns,omitempty"`
	First403JWTRecvNs   int64  `json:"first_403_jwt_recv_ns,omitempty"`
	Last200SendNs       int64  `json:"last_200_send_ns,omitempty"`
	Last200RecvNs       int64  `json:"last_200_recv_ns,omitempty"`
	LastFetchOKSendNs   int64  `json:"last_fetch_ok_send_ns,omitempty"`
	LastFetchOKRecvNs   int64  `json:"last_fetch_ok_recv_ns,omitempty"`
	FailedFetchSendNs   int64  `json:"failed_fetch_send_ns,omitempty"`
	FailedFetchRecvNs   int64  `json:"failed_fetch_recv_ns,omitempty"`
	FailedFetchError    string `json:"failed_fetch_error,omitempty"`
	ReadyTokenSHA256    string `json:"ready_token_sha256_prefix,omitempty"`
	First403TokenSHA256 string `json:"first_403_token_sha256_prefix,omitempty"`

	// First403TokenIsReadyToken: the token sent with the first 403 is byte-for-byte
	// the one sent with the first 200 (compared by digest). DistinctTokens counts
	// the different tokens sent to the resource.
	First403TokenIsReadyToken *bool `json:"first_403_token_is_ready_token,omitempty"`
	DistinctTokens            int   `json:"distinct_tokens,omitempty"`

	// Denials counts the 403s before the run ended. OtherStatuses counts every
	// status other than 200 and 403, by code.
	Denials       int            `json:"denials,omitempty"`
	OtherStatuses map[string]int `json:"other_statuses,omitempty"`

	// Subject is the JWT-SVID subject seen when the run ended "unexpected"
	// because of it.
	Subject string `json:"subject,omitempty"`

	// Run statistics, final line only. Polls counts ticks. Gaps are between
	// consecutive tick starts; fetch and call latencies are per completed fetch
	// and per answered request. Before "ready", PreReady* count ticks that did not
	// yet reach the resource with a 200.
	Polls              int   `json:"polls,omitempty"`
	TransportErrs      int   `json:"transport_errors,omitempty"`
	PreReadyFetchFails int   `json:"pre_ready_fetch_failures,omitempty"`
	PreReadyDenials    int   `json:"pre_ready_denials,omitempty"`
	GapMeanNs          int64 `json:"gap_mean_ns,omitempty"`
	GapMaxNs           int64 `json:"gap_max_ns,omitempty"`
	FetchLatencyMeanNs int64 `json:"fetch_latency_mean_ns,omitempty"`
	FetchLatencyMaxNs  int64 `json:"fetch_latency_max_ns,omitempty"`
	CallLatencyMeanNs  int64 `json:"call_latency_mean_ns,omitempty"`
	CallLatencyMaxNs   int64 `json:"call_latency_max_ns,omitempty"`

	Error string `json:"error,omitempty"`
}

// tokenDigest is a short sha256 prefix, enough to tell tokens apart without
// printing one.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:6])
}

// revokeWait carries one run's counters and output.
type revokeWait struct {
	cfg revokeWaitConfig
	enc *json.Encoder
	now func() time.Time
	ev  revokeWaitEvent // accumulates the final event's fields

	ready       bool
	seen403     bool
	readyDigest string
	digests     map[string]bool
	other       map[string]int

	prevSend       time.Time
	gapSum, gapMax time.Duration
	gaps           int
	fetchSum       time.Duration
	fetchMax       time.Duration
	fetches        int
	callSum        time.Duration
	callMax        time.Duration
	calls          int
}

func (w *revokeWait) final(event, errText string) (revokeWaitEvent, error) {
	ev := w.ev
	ev.Event, ev.Error = event, errText
	ev.DistinctTokens = len(w.digests)
	if len(w.other) > 0 {
		ev.OtherStatuses = w.other
	}
	ev.ReadyTokenSHA256 = w.readyDigest
	if w.gaps > 0 {
		ev.GapMeanNs = int64(w.gapSum) / int64(w.gaps)
	}
	ev.GapMaxNs = int64(w.gapMax)
	if w.fetches > 0 {
		ev.FetchLatencyMeanNs = int64(w.fetchSum) / int64(w.fetches)
	}
	ev.FetchLatencyMaxNs = int64(w.fetchMax)
	if w.calls > 0 {
		ev.CallLatencyMeanNs = int64(w.callSum) / int64(w.calls)
	}
	ev.CallLatencyMaxNs = int64(w.callMax)
	return ev, w.enc.Encode(ev)
}

func (w *revokeWait) timeout() (revokeWaitEvent, error) {
	if !w.ready {
		return w.final("not_ready", "no 200 within "+w.cfg.Timeout.String())
	}
	return w.final("timeout", "the identity was not withdrawn within "+w.cfg.Timeout.String())
}

// runRevokeWait runs the loop described above, writing revokeWaitEvents to out.
// At most one tick is in flight: the next starts Interval after the previous
// tick's start, or as soon as the previous one finishes if that took longer.
// The returned event is the final one.
func runRevokeWait(ctx context.Context, fetchJWT jwtFetcher, call resourceCaller, cfg revokeWaitConfig,
	out io.Writer, now func() time.Time) (revokeWaitEvent, error) {
	if cfg.ExpectID == "" {
		return revokeWaitEvent{}, fmt.Errorf("the expected SPIFFE ID is required")
	}
	if cfg.Interval <= 0 {
		return revokeWaitEvent{}, fmt.Errorf("poll interval must be positive")
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	w := &revokeWait{cfg: cfg, enc: json.NewEncoder(out), now: now, digests: map[string]bool{}, other: map[string]int{}}
	return w.loop(ctx, fetchJWT, call)
}

func (w *revokeWait) loop(ctx context.Context, fetchJWT jwtFetcher, call resourceCaller) (revokeWaitEvent, error) {
	next := w.now()
	for {
		if d := next.Sub(w.now()); d > 0 {
			select {
			case <-ctx.Done():
				return w.timeout()
			case <-time.After(d):
			}
		}
		if ctx.Err() != nil {
			return w.timeout()
		}
		tick := w.now()
		if !w.prevSend.IsZero() {
			gap := tick.Sub(w.prevSend)
			w.gapSum += gap
			w.gaps++
			if gap > w.gapMax {
				w.gapMax = gap
			}
		}
		w.prevSend = tick
		next = tick.Add(w.cfg.Interval)
		w.ev.Polls++

		// --- a fresh token from the agent, for every request ------------------
		fsend := tick
		actx, acancel := context.WithTimeout(ctx, w.cfg.AttemptTimeout)
		token, subject, err := fetchJWT(actx)
		acancel()
		frecv := w.now()
		if err != nil && ctx.Err() != nil {
			return w.timeout()
		}
		if err != nil {
			if !w.ready {
				w.ev.PreReadyFetchFails++
				continue
			}
			w.ev.FailedFetchSendNs, w.ev.FailedFetchRecvNs, w.ev.FailedFetchError = fsend.UnixNano(), frecv.UnixNano(), err.Error()
			if !w.seen403 {
				return w.final("no_deny_before_identity_gone", "the token fetch failed before any 403")
			}
			return w.final("identity_gone", "")
		}
		lat := frecv.Sub(fsend)
		w.fetchSum += lat
		w.fetches++
		if lat > w.fetchMax {
			w.fetchMax = lat
		}
		w.ev.LastFetchOKSendNs, w.ev.LastFetchOKRecvNs = fsend.UnixNano(), frecv.UnixNano()
		if subject != w.cfg.ExpectID {
			if !w.ready {
				w.ev.PreReadyFetchFails++
				continue
			}
			w.ev.Subject = subject
			return w.final("unexpected", "the agent issued a token for another identity: "+subject)
		}
		digest := tokenDigest(token)
		w.digests[digest] = true

		// --- the request goes out in the same tick, as soon as the token is held
		send := w.now()
		cctx, ccancel := context.WithTimeout(ctx, w.cfg.AttemptTimeout)
		status, err := call(cctx, token)
		ccancel()
		recv := w.now()
		if err != nil {
			if ctx.Err() != nil {
				return w.timeout()
			}
			w.ev.TransportErrs++
			continue
		}
		clat := recv.Sub(send)
		w.callSum += clat
		w.calls++
		if clat > w.callMax {
			w.callMax = clat
		}

		switch status {
		case http.StatusOK:
			if w.seen403 {
				w.ev.Status = status
				return w.final("unexpected", "the resource answered 200 after a 403")
			}
			w.ev.Last200SendNs, w.ev.Last200RecvNs = send.UnixNano(), recv.UnixNano()
			if !w.ready {
				w.ready, w.readyDigest = true, digest
				if err := w.enc.Encode(revokeWaitEvent{Event: "ready", Status: status, SendNs: send.UnixNano(), RecvNs: recv.UnixNano(),
					JWTSendNs: fsend.UnixNano(), JWTRecvNs: frecv.UnixNano(), TokenSHA256: digest}); err != nil {
					return revokeWaitEvent{}, err
				}
			}
		case http.StatusForbidden:
			if !w.ready {
				w.ev.PreReadyDenials++
				continue
			}
			w.ev.Denials++
			if !w.seen403 {
				w.seen403 = true
				same := digest == w.readyDigest
				w.ev.First403SendNs, w.ev.First403RecvNs = send.UnixNano(), recv.UnixNano()
				w.ev.First403JWTSendNs, w.ev.First403JWTRecvNs = fsend.UnixNano(), frecv.UnixNano()
				w.ev.First403TokenSHA256, w.ev.First403TokenIsReadyToken = digest, &same
			}
		default:
			w.other[fmt.Sprint(status)]++
			w.ev.Status = status
			return w.final("unexpected", fmt.Sprintf("status %d is neither 200 (allowed) nor 403 (denied by policy)", status))
		}
	}
}
