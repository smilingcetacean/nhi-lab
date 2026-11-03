package main

// access-wait is the child's side of the vend-to-access measurement: how long
// after a parent sends POST /delegations can the child read the protected
// resource with its own credential?
//
// It runs in the child's pod. The parent's side is vend-timed, which stamps the
// instant just before it writes the POST. Both use the wall clock in Unix
// nanoseconds, under the same single-host clock assumption as poll.go.
//
// Two styles:
//
//   - "poll": a fixed-interval loop. Each tick fetches a JWT-SVID for the
//     resource's audience (one-shot) and, once one with the expected subject
//     arrives, sends GET to the resource with it in the same tick; later ticks
//     reuse that token until the resource answers 200. It reports "ready" after
//     its first miss, so the caller can vend from a clean start. This measures
//     when access first becomes possible, at the interval's resolution.
//
//   - "child-py": the same steps, in the same order and with the same retries,
//     as the lab's real child (src/agents/child.py): fetch the X.509-SVID,
//     retrying up to -retry-attempts times with -retry-delay between attempts;
//     then fetch a JWT-SVID for the resource the same way; then send one GET.
//     The caller starts it after the vend returns, as parent.py starts a child
//     only after its vend succeeds. This measures what that child sees.
//
// Every fetch is a one-shot Workload API call: while the pod has no
// registration entry the agent answers with PermissionDenied ("no identity
// issued").

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// jwtFetcher fetches a JWT-SVID for the resource's audience and returns the
// token and its subject.
type jwtFetcher func(ctx context.Context) (token, subject string, err error)

// x509IDFetcher fetches the caller's default X.509-SVID and returns its SPIFFE ID.
type x509IDFetcher func(ctx context.Context) (string, error)

// resourceCaller sends one request to the protected resource with the bearer
// token and returns the HTTP status.
type resourceCaller func(ctx context.Context, token string) (int, error)

// accessWaitConfig describes one wait.
type accessWaitConfig struct {
	Style          string        // "poll" or "child-py"
	ExpectID       string        // the SPIFFE ID the parent is vending to this pod
	Interval       time.Duration // poll: target gap between attempt sends
	RetryDelay     time.Duration // child-py: pause after a failed fetch (child.py: 2 s)
	RetryAttempts  int           // child-py: attempts per fetch (child.py: 30)
	Timeout        time.Duration // give up after this long
	AttemptTimeout time.Duration // bound on a single fetch or request
}

// accessWaitEvent is one line of access-wait's output (JSON lines, on stdout).
//
// "ready" (poll only) follows the first miss. The final line is "granted" (the
// resource answered 200), "refused" (child-py: the single GET was answered with
// another status), "unexpected" (poll: the expected identity was already held at
// the first attempt), "gave_up" (child-py: a fetch failed on every attempt) or
// "timeout".
type accessWaitEvent struct {
	Event string `json:"event"`
	Style string `json:"style,omitempty"`

	// Wall-clock Unix nanoseconds. For "granted"/"refused", SendNs/RecvNs
	// bracket the resource request that ended the wait and Status is its HTTP
	// status. JWT* bracket the fetch that returned the JWT-SVID used, and X509*
	// (child-py) the fetch that returned the X.509-SVID. FirstSendNs is the
	// first attempt of any kind; LastMiss* bracket the last failed attempt.
	SendNs         int64 `json:"send_ns,omitempty"`
	RecvNs         int64 `json:"recv_ns,omitempty"`
	Status         int   `json:"status,omitempty"`
	JWTSendNs      int64 `json:"jwt_send_ns,omitempty"`
	JWTRecvNs      int64 `json:"jwt_recv_ns,omitempty"`
	X509SendNs     int64 `json:"x509_send_ns,omitempty"`
	X509RecvNs     int64 `json:"x509_recv_ns,omitempty"`
	FirstSendNs    int64 `json:"first_send_ns,omitempty"`
	LastMissSendNs int64 `json:"last_miss_send_ns,omitempty"`
	LastMissRecvNs int64 `json:"last_miss_recv_ns,omitempty"`

	// Subject is the JWT-SVID's subject (poll) or the X.509-SVID's ID (child-py).
	Subject string `json:"subject,omitempty"`

	// MissReason is the "ready" attempt's answer. MissReasons counts every miss
	// by step and reason, on the final line only.
	MissReason  string         `json:"miss_reason,omitempty"`
	MissReasons map[string]int `json:"miss_reasons,omitempty"`

	// Run statistics, final line only. Attempts counts ticks (poll) or calls
	// (child-py); the per-step counts are calls of each kind. Gaps are between
	// consecutive attempt sends.
	Attempts         int   `json:"attempts,omitempty"`
	Misses           int   `json:"misses,omitempty"`
	X509Attempts     int   `json:"x509_attempts,omitempty"`
	JWTAttempts      int   `json:"jwt_attempts,omitempty"`
	ResourceAttempts int   `json:"resource_attempts,omitempty"`
	GapMeanNs        int64 `json:"gap_mean_ns,omitempty"`
	GapMaxNs         int64 `json:"gap_max_ns,omitempty"`

	Error string `json:"error,omitempty"`
}

// accessWait carries one run's counters and output.
type accessWait struct {
	cfg  accessWaitConfig
	enc  *json.Encoder
	now  func() time.Time
	ev   accessWaitEvent // accumulates the final event's fields
	miss map[string]int

	prevSend       time.Time
	gapSum, gapMax time.Duration
	gaps           int
}

func (w *accessWait) stamp() time.Time {
	t := w.now()
	if w.ev.FirstSendNs == 0 {
		w.ev.FirstSendNs = t.UnixNano()
	}
	return t
}

// tick records an attempt's send for the gap statistics.
func (w *accessWait) tick(send time.Time) {
	if !w.prevSend.IsZero() {
		gap := send.Sub(w.prevSend)
		w.gapSum += gap
		w.gaps++
		if gap > w.gapMax {
			w.gapMax = gap
		}
	}
	w.prevSend = send
	w.ev.Attempts++
}

func (w *accessWait) missed(reason string, send, recv time.Time) {
	w.ev.Misses++
	if _, seen := w.miss[reason]; seen || len(w.miss) < maxMissReasons {
		w.miss[reason]++
	}
	w.ev.LastMissSendNs, w.ev.LastMissRecvNs = send.UnixNano(), recv.UnixNano()
}

func (w *accessWait) final(event, errText string) (accessWaitEvent, error) {
	ev := w.ev
	ev.Event, ev.Style, ev.Error = event, w.cfg.Style, errText
	if len(w.miss) > 0 {
		ev.MissReasons = w.miss
	}
	if w.gaps > 0 {
		ev.GapMeanNs = int64(w.gapSum) / int64(w.gaps)
	}
	ev.GapMaxNs = int64(w.gapMax)
	return ev, w.enc.Encode(ev)
}

// runAccessWait runs one wait in cfg.Style, writing accessWaitEvents to out.
func runAccessWait(ctx context.Context, fetchX509 x509IDFetcher, fetchJWT jwtFetcher, call resourceCaller,
	cfg accessWaitConfig, out io.Writer, now func() time.Time) (accessWaitEvent, error) {
	if cfg.ExpectID == "" {
		return accessWaitEvent{}, fmt.Errorf("the expected SPIFFE ID is required")
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	w := &accessWait{cfg: cfg, enc: json.NewEncoder(out), now: now, miss: map[string]int{}}
	switch cfg.Style {
	case "poll":
		if cfg.Interval <= 0 {
			return accessWaitEvent{}, fmt.Errorf("poll interval must be positive")
		}
		return w.poll(ctx, fetchJWT, call)
	case "child-py":
		if cfg.RetryDelay <= 0 || cfg.RetryAttempts <= 0 {
			return accessWaitEvent{}, fmt.Errorf("retry delay and attempts must be positive")
		}
		return w.childPy(ctx, fetchX509, fetchJWT, call)
	default:
		return accessWaitEvent{}, fmt.Errorf("unknown access style %q (want poll or child-py)", cfg.Style)
	}
}

func (w *accessWait) timeout() (accessWaitEvent, error) {
	return w.final("timeout", "no access within "+w.cfg.Timeout.String())
}

func (w *accessWait) poll(ctx context.Context, fetchJWT jwtFetcher, call resourceCaller) (accessWaitEvent, error) {
	var token string
	sentReady := false
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
		send := w.stamp()
		w.tick(send)
		next = send.Add(w.cfg.Interval)

		if token == "" {
			w.ev.JWTAttempts++
			actx, acancel := context.WithTimeout(ctx, w.cfg.AttemptTimeout)
			tok, sub, err := fetchJWT(actx)
			acancel()
			recv := w.now()
			if err != nil && ctx.Err() != nil {
				return w.timeout()
			}
			reason := ""
			switch {
			case err != nil:
				reason = "jwt: " + err.Error()
			case sub != w.cfg.ExpectID:
				reason = "jwt: subject " + sub
			}
			if reason != "" {
				w.missed(reason, send, recv)
				if !sentReady {
					sentReady = true
					if err := w.enc.Encode(accessWaitEvent{Event: "ready", Style: w.cfg.Style, SendNs: send.UnixNano(),
						RecvNs: recv.UnixNano(), MissReason: reason}); err != nil {
						return accessWaitEvent{}, err
					}
				}
				continue
			}
			w.ev.Subject = sub
			if !sentReady {
				w.ev.JWTSendNs, w.ev.JWTRecvNs = send.UnixNano(), recv.UnixNano()
				return w.final("unexpected", "the expected identity was already held at the first attempt, so there is no clean start to measure from")
			}
			token = tok
			w.ev.JWTSendNs, w.ev.JWTRecvNs = send.UnixNano(), recv.UnixNano()
			send = w.now() // the request goes out in the same tick, as soon as the token is held
		}

		w.ev.ResourceAttempts++
		actx, acancel := context.WithTimeout(ctx, w.cfg.AttemptTimeout)
		status, err := call(actx, token)
		acancel()
		recv := w.now()
		if err != nil && ctx.Err() != nil {
			return w.timeout()
		}
		if err == nil && status == http.StatusOK {
			w.ev.SendNs, w.ev.RecvNs, w.ev.Status = send.UnixNano(), recv.UnixNano(), status
			return w.final("granted", "")
		}
		reason := fmt.Sprintf("resource: HTTP %d", status)
		if err != nil {
			reason = "resource: " + err.Error()
		}
		w.missed(reason, send, recv)
	}
}

// retrying calls attempt up to RetryAttempts times, pausing RetryDelay after
// each failure, as src/agents/common.py's *_retrying helpers do.
func (w *accessWait) retrying(ctx context.Context, step string, counter *int, attempt func(context.Context) error) (time.Time, time.Time, error) {
	var lastErr error
	for i := 1; i <= w.cfg.RetryAttempts; i++ {
		if ctx.Err() != nil {
			return time.Time{}, time.Time{}, ctx.Err()
		}
		send := w.stamp()
		w.tick(send)
		*counter++
		actx, acancel := context.WithTimeout(ctx, w.cfg.AttemptTimeout)
		err := attempt(actx)
		acancel()
		recv := w.now()
		if err == nil {
			return send, recv, nil
		}
		if ctx.Err() != nil {
			return time.Time{}, time.Time{}, ctx.Err()
		}
		lastErr = err
		w.missed(step+": "+err.Error(), send, recv)
		select {
		case <-ctx.Done():
			return time.Time{}, time.Time{}, ctx.Err()
		case <-time.After(w.cfg.RetryDelay):
		}
	}
	return time.Time{}, time.Time{}, fmt.Errorf("%s failed on all %d attempts: %w", step, w.cfg.RetryAttempts, lastErr)
}

func (w *accessWait) childPy(ctx context.Context, fetchX509 x509IDFetcher, fetchJWT jwtFetcher, call resourceCaller) (accessWaitEvent, error) {
	var id string
	send, recv, err := w.retrying(ctx, "x509", &w.ev.X509Attempts, func(actx context.Context) error {
		var ferr error
		id, ferr = fetchX509(actx)
		return ferr
	})
	if err != nil {
		if ctx.Err() != nil {
			return w.timeout()
		}
		return w.final("gave_up", err.Error())
	}
	w.ev.X509SendNs, w.ev.X509RecvNs, w.ev.Subject = send.UnixNano(), recv.UnixNano(), id

	var token string
	send, recv, err = w.retrying(ctx, "jwt", &w.ev.JWTAttempts, func(actx context.Context) error {
		var ferr error
		token, _, ferr = fetchJWT(actx)
		return ferr
	})
	if err != nil {
		if ctx.Err() != nil {
			return w.timeout()
		}
		return w.final("gave_up", err.Error())
	}
	w.ev.JWTSendNs, w.ev.JWTRecvNs = send.UnixNano(), recv.UnixNano()

	// child.py sends exactly one GET and reports whatever it gets.
	send = w.stamp()
	w.tick(send)
	w.ev.ResourceAttempts++
	actx, acancel := context.WithTimeout(ctx, w.cfg.AttemptTimeout)
	status, err := call(actx, token)
	acancel()
	recv = w.now()
	w.ev.SendNs, w.ev.RecvNs, w.ev.Status = send.UnixNano(), recv.UnixNano(), status
	if err != nil {
		return w.final("refused", "resource: "+err.Error())
	}
	if status != http.StatusOK {
		return w.final("refused", fmt.Sprintf("resource answered HTTP %d", status))
	}
	return w.final("granted", "")
}
