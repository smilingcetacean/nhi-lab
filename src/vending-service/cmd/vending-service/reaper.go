package main

import (
	"context"
	"log"
	"time"

	"nhi-lab/vending-service/internal/audit"
)

// runReaper sweeps for delegations past their TTL and past their nonce
// retention window, on cfg.reaperInterval, until ctx is cancelled. This is
// what catches the orphaned child: a parent that dies (or never calls
// disposal) leaves its child's delegation record with revoked_at IS NULL and
// expires_at in the past — exactly ListExpiredUnrevoked's query — and the
// reaper reaps it through the same disposeChain path handleDispose uses, so
// there is exactly one disposal code path, not two that could drift apart.
//
// A reaper-initiated disposal is attributed in the audit trail to this
// service's own identity (cfg.audience), not a caller's, since no caller is
// involved.
func (s *server) runReaper(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reapOnce(ctx)
		}
	}
}

func (s *server) reapOnce(ctx context.Context) {
	now := s.now().Unix()

	expired, err := s.store.ListExpiredUnrevoked(ctx, now)
	if err != nil {
		log.Printf("vending-service: reaper: list expired delegations: %v", err)
	}
	for _, rec := range expired {
		if err := s.disposeChain(ctx, rec, s.cfg.audience, "ttl_expired"); err != nil {
			log.Printf("vending-service: reaper: dispose %s: %v", rec.ChainID, err)
			s.audit.Emit(audit.Event{
				Stage: audit.StageDispose, ActorSpiffeID: s.cfg.audience, ChainID: rec.ChainID, Outcome: audit.OutcomeError,
				Detail: audit.Detail{
					ParentSpiffeID: rec.ParentSpiffeID, ChildSpiffeID: rec.ChildSpiffeID,
					EntryID: rec.EntryID, PolicyID: rec.PolicyID,
					Reason: "reaper: " + err.Error(),
				},
			})
			continue
		}
		log.Printf("vending-service: reaper: expired delegation %s (child %s) reaped", rec.ChainID, rec.ChildSpiffeID)
	}

	if n, err := s.store.PruneExpiredNonces(ctx, now); err != nil {
		log.Printf("vending-service: reaper: prune nonces: %v", err)
	} else if n > 0 {
		log.Printf("vending-service: reaper: pruned %d expired nonce record(s)", n)
	}
}
