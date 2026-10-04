# Negative-test falsification

For each of the 5 negative tests in `negative_tests.py`, the guard it depends
on was located, mutated on a **scratch copy** of `src/vending-service`
(never the working tree — confirmed with `git status --short
src/vending-service` after the whole exercise, clean), and the **existing unit test that exercises that
guard** was run before and after the mutation. Unit-test level, not a live
in-cluster rebuild+redeploy: the guards already have dedicated Go tests in
`cmd/vending-service/main_test.go`, so mutating and testing at that level
exercises the actual guard code path this suite's live/in-cluster assertions
depend on, without rebuilding and redeploying the vending-service image five
times against a shared, non-isolated cluster.

All five: baseline green -> mutated red (for the specific reason named) ->
reverted green.

## 1. Forged parent signature

Guard: `signature.Verify(...)` call in `handleVend` (main.go, step 2a).
Test: `TestHandleVendRejectsForgedSignature`.

- Baseline: PASS.
- Mutated (signature check short-circuited, verify call discarded): **FAIL**
  — `status = 502, want 401; body={"error":"Bad Gateway","reason":"policy
  engine synthesis failed: test stub not configured for this call"}`. The
  request no longer stops at signature verification at all; it falls through
  to the next stage (which then fails for an unrelated reason in the test
  harness), proving the 401 the live test observes is this specific check.
- Reverted: PASS.

## 2. Scope-escalation manifest (Π(requested) ∩ Π(parent) = ∅)

Guard: `if len(synth.ChildScopes) == 0 { ... 403 ... }` in `handleVend`
Test: `TestHandleVendRejectsEmptyAttenuationResult`.

- Baseline: PASS.
- Mutated (`if false && len(synth.ChildScopes) == 0`): **FAIL** — `status =
  201, want 403`, response body shows a delegation was actually created:
  `"child_scopes":null,"entry_id":"entry-should-not-happen",...`. Without the
  guard the service mints a real, scopeless SPIRE entry for a fully-escalated
  request — exactly the gap this guard closes.
- Reverted: PASS.

## 3. Replay (nonce reuse)

Guard: `errors.Is(err, store.ErrNonceReused)` classification in `handleVend`
(maps the store's replay error to `409` + `"nonce has already been used..."`
audit reason, vs. falling through to the generic error path). Test:
`TestHandleVendRejectsReplayedNonce`.

- Baseline: PASS.
- Mutated (`if false && errors.Is(...)`): **FAIL** — `status = 500, want 409
  (nonce replay refused); body={"error":"Internal Server Error","reason":
  "could not record nonce: nonce already used"}`. The store's own uniqueness
  constraint still blocks the second write (defence in depth at the
  persistence layer), but the classification this negative test's audit
  assertion depends on — a `409` with `detail.reason` containing "already
  been used" — is entirely produced by this guard, not by the store error
  alone.
- Reverted: PASS.

## 4. Use of child credential after revocation

Guard: `s.policyEngine.Dispose(ctx, rec.ChainID)` call inside `disposeChain`
— the OPA grant-module removal that is what actually makes a
still-cryptographically-valid captured JWT-SVID start being denied (the
SPIRE entry deletion alone does not invalidate an already-issued token; only
removing its OPA grant does). Test:
`TestHandleDisposeByParentRevokesAndDeletesEntry`.

- Baseline: PASS.
- Mutated (call removed entirely): **FAIL** — `policy engine dispose was not
  called with the right chain_id: got ""`. Disposal would silently strand
  the OPA grant module (`nhi_grants_<chain_id>`) forever, so a captured
  pre-disposal token would keep working after "disposal" — precisely the gap
  the live `credential_use_after_revocation` test's final 403 assertion
  depends on not existing.
- Reverted: PASS.

## 5. Orphaned child (reaper)

Guard: the reaper's own read of `ListExpiredUnrevoked` in `reapOnce`
(reaper.go) — the thing that finds an abandoned delegation in the first
place. Test: `TestReaperReapsExpiredDelegation`.

- Baseline: PASS (log line: "reaper: expired delegation c_orphan ... reaped").
- Mutated (`expired = nil` immediately after the store read, so the reaper's
  sweep sees zero candidates every tick): **FAIL** — `reaper did not dispose
  the orphaned child: deleted=false disposed=false`. An abandoned delegation
  would never be revoked, its SPIRE entry would never be deleted, and its
  OPA grant would live forever — the parent-dies-before-disposal case.
- Reverted: PASS.

All five mutations and reversions were applied only to a scratch copy;
`git status --short src/vending-service` on the real working tree is clean.
