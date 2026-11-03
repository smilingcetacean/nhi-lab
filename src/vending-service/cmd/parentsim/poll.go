package main

// poll and dispose-timed exist to measure how long a revocation takes to bite,
// from inside the cluster. vend-timed and svid-wait (svidwait.go) measure the
// other direction: how long a vended identity takes to reach the child.
//
// A measurement driven through `kubectl exec` cannot resolve this: one exec
// costs 50-70 ms, which is the same order as the interval being measured. So
// the request loop runs here, in the pod of the workload being revoked, and
// the revoking parent takes its own send timestamp in its own pod.
//
// Clock assumption. Every timestamp below is the wall clock (CLOCK_REALTIME)
// in Unix nanoseconds, because timestamps from two different pods have to be
// subtracted. All kind nodes are containers on one host and share that host's
// kernel clock, so the parent's pod, the polling pod and the resource's audit
// log are on the same clock to well under a millisecond. This does NOT hold
// for a cluster whose nodes are separate machines; do not reuse the numbers
// there without a clock-sync bound.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// pollConfig describes one polling run.
type pollConfig struct {
	URL      string
	Method   string
	Bearer   string
	Interval time.Duration // target gap between request sends
	Timeout  time.Duration // give up if no denial arrives in this long
}

// pollEvent is one line of poll's output (JSON lines, on stdout).
//
// "ready" is printed as soon as the first request is answered 200, so the
// caller knows the loop is live and the caller is allowed before it revokes.
// The final line is "denied" (the first 403), or "unexpected" (any other
// non-200 status) or "timeout".
type pollEvent struct {
	Event string `json:"event"`

	// Status is the HTTP status of the response that ended the run (or of the
	// first 200 for "ready").
	Status int `json:"status,omitempty"`

	// Wall-clock Unix nanoseconds. For "denied", SendNs/RecvNs bracket the
	// first non-200 response; LastAllowedSendNs/LastAllowedRecvNs bracket the
	// last 200 before it.
	SendNs            int64 `json:"send_ns,omitempty"`
	RecvNs            int64 `json:"recv_ns,omitempty"`
	LastAllowedSendNs int64 `json:"last_allowed_send_ns,omitempty"`
	LastAllowedRecvNs int64 `json:"last_allowed_recv_ns,omitempty"`

	// Run statistics, final line only. Gaps are between consecutive request
	// SENDS, so they measure how often G actually asked, not the target.
	Polls         int   `json:"polls,omitempty"`
	TransportErrs int   `json:"transport_errors,omitempty"`
	GapMeanNs     int64 `json:"gap_mean_ns,omitempty"`
	GapMaxNs      int64 `json:"gap_max_ns,omitempty"`
	LatencyMeanNs int64 `json:"latency_mean_ns,omitempty"`
	LatencyMaxNs  int64 `json:"latency_max_ns,omitempty"`

	Error string `json:"error,omitempty"`
}

// runPoll sends cfg.Method requests to cfg.URL with the bearer token until one
// is answered with something other than 200, writing pollEvents to out. At most
// one request is in flight; the next is sent Interval after the previous send,
// or as soon as the previous response arrives if that took longer.
//
// The returned event is the final one. Its Event is "denied" only for a 403:
// a 401 means the token was refused before policy was asked, which says nothing
// about revocation, so it is reported as "unexpected".
func runPoll(ctx context.Context, client *http.Client, cfg pollConfig, out io.Writer, now func() time.Time) (pollEvent, error) {
	if cfg.Interval <= 0 {
		return pollEvent{}, fmt.Errorf("poll interval must be positive")
	}
	if cfg.Method == "" {
		cfg.Method = http.MethodGet
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	enc := json.NewEncoder(out)

	var (
		polls, errs           int
		sentReady             bool
		prevSend              time.Time
		gapSum, gapMax        time.Duration
		latSum, latMax        time.Duration
		lastOKSend, lastOKRcv time.Time
	)
	final := func(ev pollEvent) (pollEvent, error) {
		ev.Polls, ev.TransportErrs = polls, errs
		if polls > 1 {
			ev.GapMeanNs = int64(gapSum) / int64(polls-1)
		}
		ev.GapMaxNs = int64(gapMax)
		if answered := polls - errs; answered > 0 {
			ev.LatencyMeanNs = int64(latSum) / int64(answered)
		}
		ev.LatencyMaxNs = int64(latMax)
		if !lastOKSend.IsZero() {
			ev.LastAllowedSendNs, ev.LastAllowedRecvNs = lastOKSend.UnixNano(), lastOKRcv.UnixNano()
		}
		return ev, enc.Encode(ev)
	}

	next := now()
	for {
		// Wait for the next tick unless it has already passed.
		if d := next.Sub(now()); d > 0 {
			select {
			case <-ctx.Done():
				return final(pollEvent{Event: "timeout", Error: "no denial within " + cfg.Timeout.String()})
			case <-time.After(d):
			}
		}
		if ctx.Err() != nil {
			return final(pollEvent{Event: "timeout", Error: "no denial within " + cfg.Timeout.String()})
		}

		send := now()
		if !prevSend.IsZero() {
			gap := send.Sub(prevSend)
			gapSum += gap
			if gap > gapMax {
				gapMax = gap
			}
		}
		prevSend = send
		next = send.Add(cfg.Interval)
		polls++

		req, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.URL, nil)
		if err != nil {
			return pollEvent{}, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Bearer)
		resp, err := client.Do(req)
		recv := now()
		if err != nil {
			if ctx.Err() == nil {
				errs++
				continue
			}
			polls-- // the request cut off by the deadline never completed; do not count it
			return final(pollEvent{Event: "timeout", Error: "no denial within " + cfg.Timeout.String()})
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		lat := recv.Sub(send)
		latSum += lat
		if lat > latMax {
			latMax = lat
		}

		switch resp.StatusCode {
		case http.StatusOK:
			lastOKSend, lastOKRcv = send, recv
			if !sentReady {
				sentReady = true
				if err := enc.Encode(pollEvent{Event: "ready", Status: resp.StatusCode, SendNs: send.UnixNano(), RecvNs: recv.UnixNano()}); err != nil {
					return pollEvent{}, err
				}
			}
		case http.StatusForbidden:
			return final(pollEvent{Event: "denied", Status: resp.StatusCode, SendNs: send.UnixNano(), RecvNs: recv.UnixNano()})
		default:
			return final(pollEvent{Event: "unexpected", Status: resp.StatusCode, SendNs: send.UnixNano(), RecvNs: recv.UnixNano(),
				Error: fmt.Sprintf("status %d is neither 200 (allowed) nor 403 (denied by policy)", resp.StatusCode)})
		}
	}
}

// timedResult is what dispose-timed and vend-timed print.
type timedResult struct {
	Status   int    `json:"status"`
	SendNs   int64  `json:"send_ns"`
	RecvNs   int64  `json:"recv_ns"`
	RoundNs  int64  `json:"round_trip_ns"`
	Response string `json:"response"`
}

// timedRequest sends one request to the vending service and reports the
// wall-clock instants just before the request is written and just after the
// response headers are read, plus the status. The caller does all setup (SVID
// fetch, manifest signing) before calling it, so the interval covers only the
// request. dispose-timed (the revoking parent) sends a DELETE with no body;
// vend-timed sends the signed manifest as a POST.
func timedRequest(ctx context.Context, client *http.Client, method, url, bearer string, body []byte, now func() time.Time) (timedResult, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return timedResult{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	send := now()
	resp, err := client.Do(req)
	recv := now()
	if err != nil {
		return timedResult{}, fmt.Errorf("call vending service: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return timedResult{}, fmt.Errorf("read response: %w", err)
	}
	return timedResult{
		Status:   resp.StatusCode,
		SendNs:   send.UnixNano(),
		RecvNs:   recv.UnixNano(),
		RoundNs:  recv.UnixNano() - send.UnixNano(),
		Response: string(raw),
	}, nil
}
