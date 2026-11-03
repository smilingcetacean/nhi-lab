package main

// svid-wait is the child's side of the vend-to-identity measurement: how long
// after a parent sends POST /delegations can the child obtain the X.509-SVID
// that vend registered for it?
//
// It runs in the child's pod and asks the local SPIRE agent's Workload API for
// the pod's X.509-SVIDs every -poll-interval, until one answer contains the
// expected SPIFFE ID. The parent's side is vend-timed, which stamps the instant
// just before it writes the POST. Both use the wall clock in Unix nanoseconds,
// under the same single-host clock assumption as poll.go.
//
// One-shot fetches, not a watch: while the pod has no registration entry the
// agent answers a fetch with PermissionDenied ("no identity issued") and ends
// the stream, and go-spiffe's watch then retries with a backoff of its own.
// A fixed-interval loop of one-shot fetches keeps the resolution at the
// interval rather than at the library's backoff.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// heldSVID is the part of a fetched X.509-SVID the wait needs.
type heldSVID struct {
	ID       string
	NotAfter time.Time
}

// svidFetcher asks the Workload API for every X.509-SVID the caller holds.
type svidFetcher func(ctx context.Context) ([]heldSVID, error)

// svidWaitConfig describes one wait.
type svidWaitConfig struct {
	ExpectID       string
	Interval       time.Duration // target gap between fetch sends
	Timeout        time.Duration // give up if the identity has not arrived in this long
	AttemptTimeout time.Duration // bound on a single fetch
}

// maxMissReasons bounds the distinct miss reasons kept in the final event.
const maxMissReasons = 8

// svidWaitEvent is one line of svid-wait's output (JSON lines, on stdout).
//
// "ready" is printed after the first fetch that is answered WITHOUT the
// expected identity, so the caller knows the loop is live and the start is
// clean before it vends. The final line is "obtained" (the first fetch whose
// answer contains the expected SPIFFE ID), "unexpected" (the expected identity
// was already held at the first fetch) or "timeout".
type svidWaitEvent struct {
	Event string `json:"event"`

	// Wall-clock Unix nanoseconds. For "obtained", SendNs/RecvNs bracket the
	// first fetch that returned the expected identity; LastMissSendNs/
	// LastMissRecvNs bracket the last fetch before it.
	SendNs         int64 `json:"send_ns,omitempty"`
	RecvNs         int64 `json:"recv_ns,omitempty"`
	LastMissSendNs int64 `json:"last_miss_send_ns,omitempty"`
	LastMissRecvNs int64 `json:"last_miss_recv_ns,omitempty"`

	// The identities in the answer that ended the wait, and the expected
	// SVID's expiry (RFC 3339).
	SPIFFEIDs []string `json:"spiffe_ids,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`

	// MissReason is the "ready" fetch's answer. MissReasons counts every
	// miss by reason (an error text, or "held other identities only"), on the
	// final line only.
	MissReason  string         `json:"miss_reason,omitempty"`
	MissReasons map[string]int `json:"miss_reasons,omitempty"`

	// Run statistics, final line only. Gaps are between consecutive fetch
	// SENDS, so they measure how often the child actually asked.
	Attempts      int   `json:"attempts,omitempty"`
	Misses        int   `json:"misses,omitempty"`
	GapMeanNs     int64 `json:"gap_mean_ns,omitempty"`
	GapMaxNs      int64 `json:"gap_max_ns,omitempty"`
	LatencyMeanNs int64 `json:"latency_mean_ns,omitempty"`
	LatencyMaxNs  int64 `json:"latency_max_ns,omitempty"`

	Error string `json:"error,omitempty"`
}

// runSVIDWait fetches with fetch until an answer contains cfg.ExpectID,
// writing svidWaitEvents to out. At most one fetch is in flight; the next is
// sent Interval after the previous send, or as soon as the previous answer
// arrives if that took longer. Every fetch that does not return the expected
// identity, error or not, is a miss.
func runSVIDWait(ctx context.Context, fetch svidFetcher, cfg svidWaitConfig, out io.Writer, now func() time.Time) (svidWaitEvent, error) {
	if cfg.Interval <= 0 {
		return svidWaitEvent{}, fmt.Errorf("poll interval must be positive")
	}
	if cfg.ExpectID == "" {
		return svidWaitEvent{}, fmt.Errorf("the expected SPIFFE ID is required")
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	enc := json.NewEncoder(out)

	var (
		attempts, misses           int
		missReasons                = map[string]int{}
		sentReady                  bool
		prevSend                   time.Time
		gapSum, gapMax             time.Duration
		latSum, latMax             time.Duration
		lastMissSend, lastMissRecv time.Time
	)
	final := func(ev svidWaitEvent) (svidWaitEvent, error) {
		ev.Attempts, ev.Misses = attempts, misses
		if len(missReasons) > 0 {
			ev.MissReasons = missReasons
		}
		if attempts > 1 {
			ev.GapMeanNs = int64(gapSum) / int64(attempts-1)
		}
		ev.GapMaxNs = int64(gapMax)
		if attempts > 0 {
			ev.LatencyMeanNs = int64(latSum) / int64(attempts)
		}
		ev.LatencyMaxNs = int64(latMax)
		if !lastMissSend.IsZero() {
			ev.LastMissSendNs, ev.LastMissRecvNs = lastMissSend.UnixNano(), lastMissRecv.UnixNano()
		}
		return ev, enc.Encode(ev)
	}
	timeout := func() (svidWaitEvent, error) {
		return final(svidWaitEvent{Event: "timeout", Error: "expected identity not obtained within " + cfg.Timeout.String()})
	}

	next := now()
	for {
		// Wait for the next tick unless it has already passed.
		if d := next.Sub(now()); d > 0 {
			select {
			case <-ctx.Done():
				return timeout()
			case <-time.After(d):
			}
		}
		if ctx.Err() != nil {
			return timeout()
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
		attempts++

		actx, acancel := context.WithTimeout(ctx, cfg.AttemptTimeout)
		held, err := fetch(actx)
		acancel()
		recv := now()
		if err != nil && ctx.Err() != nil {
			attempts-- // the fetch cut off by the overall deadline never completed; do not count it
			return timeout()
		}
		lat := recv.Sub(send)
		latSum += lat
		if lat > latMax {
			latMax = lat
		}

		ids := make([]string, 0, len(held))
		var match *heldSVID
		for i := range held {
			ids = append(ids, held[i].ID)
			if held[i].ID == cfg.ExpectID {
				match = &held[i]
			}
		}
		if match != nil {
			ev := svidWaitEvent{SendNs: send.UnixNano(), RecvNs: recv.UnixNano(), SPIFFEIDs: ids,
				NotAfter: match.NotAfter.UTC().Format(time.RFC3339)}
			if !sentReady {
				ev.Event = "unexpected"
				ev.Error = "the expected identity was already held at the first fetch, so there is no clean start to measure from"
				return final(ev)
			}
			ev.Event = "obtained"
			return final(ev)
		}

		misses++
		reason := "held other identities only"
		switch {
		case err != nil:
			reason = err.Error()
		case len(held) == 0:
			reason = "empty answer"
		}
		if _, seen := missReasons[reason]; seen || len(missReasons) < maxMissReasons {
			missReasons[reason]++
		}
		lastMissSend, lastMissRecv = send, recv
		if !sentReady {
			sentReady = true
			if err := enc.Encode(svidWaitEvent{Event: "ready", SendNs: send.UnixNano(), RecvNs: recv.UnixNano(), MissReason: reason}); err != nil {
				return svidWaitEvent{}, err
			}
		}
	}
}
