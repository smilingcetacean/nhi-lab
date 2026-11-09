# Negative-test falsification

Each of the five tests in `negative_tests.py` depends on one guard in the
vending service. This record shows, for every guard, that its test fails when
the guard is broken and passes again once the guard is back. The evidence
comes from two levels. The unit level runs the Go test that exercises the
guard. The live level runs `negative_tests.py` against a vending-service
image that carries the mutation, deployed to an isolated throwaway kind
cluster. Every mutation went into a scratch copy of `src/vending-service`,
and `git status --short src/vending-service` on the working tree printed
nothing after each exercise.

## Guards and mutations

| # | Negative test | Guard | Mutation | Unit test |
|---|---|---|---|---|
| 1 | Forged parent signature | `signature.Verify(...)` in `handleVend`, `cmd/vending-service/main.go:390` | `if err := signature.Verify(...); false && err != nil {`: Verify still runs and its result is ignored | `TestHandleVendRejectsForgedSignature` |
| 2 | Scope-escalation manifest | `if len(synth.ChildScopes) == 0 {` in `handleVend`, `main.go:575` | `if false && len(synth.ChildScopes) == 0 {` | `TestHandleVendRejectsEmptyAttenuationResult` |
| 3 | Replay (nonce reuse) | `if errors.Is(err, store.ErrNonceReused) {` in `handleVend`, `main.go:517` | `if false && errors.Is(err, store.ErrNonceReused) {` | `TestHandleVendRejectsReplayedNonce` |
| 4 | Credential use after revocation | `s.policyEngine.Dispose(ctx, rec.ChainID)` in `disposeChain`, `main.go:864` | `if err := error(nil); err != nil {`: the grant removal never runs, and the rest of disposal still does | `TestHandleDisposeByParentRevokesAndDeletesEntry` |
| 5 | Orphaned child (reaper) | `expired, err := s.store.ListExpiredUnrevoked(ctx, now)` in `reapOnce`, `cmd/vending-service/reaper.go:38` | `expired = nil` on the next line | `TestReaperReapsExpiredDelegation` |

The unified diffs are `g1.diff` to `g5.diff` in
`benchmarks/tests/20261109T020524Z/falsification/`, with paths relative to
`src/vending-service`. Both live runs below applied exactly these diffs.

## Unit level

Every guard went green, red, and green again: its test passed on the clean
copy, failed on the mutated copy for the reason below, and passed once the
mutation was reverted. The first record of this exercise and the rerun in
`benchmarks/tests/20261109T020524Z/falsification/` (`unit-*.log`) produced the
same failure lines word for word.

1. Forged parent signature. The mutated handler fails with `status = 502,
   want 401; body={"error":"Bad Gateway","reason":"policy engine synthesis
   failed: test stub not configured for this call"}`. The request no longer
   stops at signature verification and falls through to the next stage, which
   fails for an unrelated reason in the test harness. The 401 the live test
   observes therefore comes from this check and no other.
2. Scope-escalation manifest. The mutated handler returns `status = 201, want
   403`, and the response body shows a delegation with `"child_scopes":null`.
   Without the guard, the service mints a real, scopeless SPIRE entry for a
   fully escalated request, which is the gap this guard closes.
3. Replay. The mutated handler returns `status = 500, want 409 (nonce replay
   refused)` with the reason `could not record nonce: nonce already used`.
   The store's uniqueness constraint still blocks the second write, so the
   persistence layer gives defence in depth, but only this guard produces the
   409 and the "already been used" audit reason the negative test asserts.
4. Credential use after revocation. The test fails with `policy engine
   dispose was not called with the right chain_id: got ""`. Disposal would
   leave the `nhi_grants_<chain_id>` OPA module in place, so a JWT-SVID
   captured before disposal would keep working. Deleting the SPIRE entry alone
   does not invalidate a token already issued; removing the grant does.
5. Orphaned child. The test fails with `reaper did not dispose the orphaned
   child: deleted=false disposed=false`. An abandoned delegation would never
   be revoked, its SPIRE entry never deleted, and its OPA grant never removed.

The tests added with cascade revocation, the TTL cap, and the creation limits
also catch two of the mutations. Mutation 4 fails eight more tests:
`TestDisposeCascadesToLiveDescendantsBreadthFirst`,
`TestDisposeOfALeafDisposesOnlyThatChain`,
`TestDisposeChainRemovesGrantBeforeEntryBeforeRow`,
`TestDisposeChainStopsWhenTheGrantCannotBeRemoved`,
`TestDisposeDoesNotCascadeWhenTheTargetFails`,
`TestDisposeCascadePartialFailureNamesTheDescendant`,
`TestReaperDoesNotCascade`, and `TestReaperReapsExpiredDelegation`. Mutation
5 fails two more, `TestDisposeCascadePartialFailureNamesTheDescendant` and
`TestReaperDoesNotCascade`. Mutations 1 to 3 fail only their named test.

## Live level

For each guard, the run builds `nhi-lab/vending-service` from the mutated
copy under a tag of its own (never `:dev`, which other clusters on the same
docker daemon load), loads it into the throwaway cluster's nodes with `kind
load image-archive`, and swaps it into the `vending-service` Deployment with
`kubectl set image`. The Deployment uses the Recreate strategy, so the old and
new pods never overlap, and the new pod's imageID confirms the swap.
`negative_tests.py` then runs against the broken service. The clean `:dev`
image, loaded at bring-up, goes back the same way, its imageID matches the
baseline, and the suite runs again. The lab configuration stays as shipped,
including `REAPER_INTERVAL=15s` and `MAX_LIVE_CHILDREN=8`.

### The original suite

`benchmarks/tests/20261109T020524Z/falsification/` holds this run. The clean
image passed 5/5 before the first mutation.

| # | Tests that failed with the guard broken | What the broken service did | First run after restoring |
|---|---|---|---|
| 1 | forged signature, credential after revocation | answered 201 instead of 401 and minted a child with a datasetA grant from a corrupted signature | 4/5, then 5/5 after the minted delegation was disposed by hand |
| 2 | scope escalation | answered 201 instead of 403 and minted a child with no scopes | 4/5, then 5/5 after the minted delegation was disposed by hand |
| 3 | replay | answered 500 instead of 409 (`could not record nonce: nonce already used`); the store still refused the replay | 5/5 |
| 4 | credential after revocation | answered 200 to the dispose, then the resource answered 200 to the captured JWT-SVID, because the OPA grant module was never removed | 5/5 |
| 5 | orphaned child | never reaped the orphan and emitted no dispose event; the clean reaper reaped it on its first tick after the restore | 5/5 |

Every mutation was caught, but the live level exposed two defects in the
suite itself that the unit level cannot see.

The first defect was shared selectors. All five tests vended children for
`experiments-child`'s service account. With guard 1 or 2 broken, the
forged-signature or escalation test minted an entry, `experiments-child` then
held two SVIDs, and the credential-after-revocation test captured whichever
JWT-SVID the Workload API listed first, because `parentsim fetch-jwt` names
no subject. That test therefore failed as collateral, which is why guard 1
broke two tests, and the first runs after restoring guards 1 and 2 failed it
again until the leftover delegations were disposed by hand.

The second defect was uncorrelated audit matching. The forged-signature and
replay tests took the newest attest/deny event in the log tail, whatever
request had produced it. With guard 3 broken, the replay test matched the
event the forged-signature test had produced earlier in the same run. It
still failed, but on the status code and reason text rather than on its own
event, which is the vacuous-assertion failure mode the suite exists to avoid.

One further observation concerns the audit trail rather than the suite. With
guard 1 broken, the attest/allow event still read `JWT-SVID, manifest
signature, nonce and child_selectors all verified` for a corrupted signature.
The service writes that reason as fixed text once the checks pass, so the
reason records that the handler reached that point, not that each check ran.

### The corrected suite

`negative_tests.py` now vends for a service account no pod runs as in every
test except the credential-after-revocation test, checks that the captured
JWT-SVID belongs to that test's own child, disposes any delegation a refusal
test unexpectedly receives, and matches each audit event to the test's own
request. `src/experiments/README.md` describes the rules in full.

The same five mutations ran against the corrected suite on two separate
throwaway clusters. The second cluster rebuilt the mutated copies from the
committed diffs on its own. On each cluster, the clean image passed 5/5 twice
back to back, and the second run matched only its own events. Both clusters
gave the same outcome for every guard.

| # | Tests that failed with the guard broken | Decisive evidence | First run after restoring |
|---|---|---|---|
| 1 | forged signature only | 201, no new attest/deny event, entry created and then disposed by the test | 5/5 |
| 2 | scope escalation only | 201, no vend/deny event for its child, entry created and then disposed by the test | 5/5 |
| 3 | replay only | 201 then 500; the only new event from `exp-root` was its own attest/error, so no candidate matched | 5/5 |
| 4 | credential after revocation only | the captured JWT-SVID belonged to the test's own child; after a 200 dispose the resource still answered 200 | 5/5 |
| 5 | orphaned child only | entry not reaped within the test's 40 s window | 5/5 |

In all 24 runs, the credential-after-revocation test captured a JWT-SVID
whose `sub` was its own child's SPIFFE ID. No run needed manual cleanup.

## Evidence

| Path | Contents |
|---|---|
| `benchmarks/tests/20261109T020524Z/falsification/` | unit level (`unit-*.log`) and the live run of the original suite, with the mutation diffs |
| `benchmarks/tests/20261109T024542Z/primary/` | the corrected suite on the first cluster |
| `benchmarks/tests/20261109T024542Z/replication/` | the corrected suite on the second cluster |
| `src/experiments/results/20261109T025203Z/` | `run_all.py --skip-performance` with the corrected suite: negative, multi-hop, and functional all pass |
