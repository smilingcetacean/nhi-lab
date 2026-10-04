# src/experiments — experiments and data collection

Python (`uv`), driven against the **real, live** deployment — no
mocks — via `kubectl exec` of `cmd/parentsim` (the vending service's Go
test-harness parent, reused rather than forked: every knob these suites need — a corrupted
signature, a fixed nonce, a claimed-parent override, a raw manifest relay —
is already a flag on it). Same pattern `src/deploy/scripts/verify-vending.sh`
uses, just in Python and repeated at volume with results captured as
CSV/JSON.

## Running

```
make experiments               # from the repo root, or:
make -C src/deploy experiments
```

This brings up the vending service, the resource, and the experiments' own
dedicated fixtures (`src/deploy/manifests/experiments/`), then runs all four
suites in order and writes `src/experiments/results/<run-id>/` plus a copy at
`src/experiments/results/latest/` (gitignored).

### The committed reference run

`results/reference-run/` is one complete run of all four suites (100
performance iterations), kept so the numbers can be inspected without a
cluster. It has been anonymized: every absolute timestamp (`generated_at`,
audit-event `timestamp`, and the `issued_at`/`expires_at` Unix times inside
recorded response bodies) was shifted back by the same constant so the run
appears to start on 2000-01-01. All relative intervals — every latency and
TTL — are unchanged. The SPIFFE IDs in it use the same names as the current
code and manifests.

Run an individual suite directly (fixtures must already be up — `make -C
src/deploy experiments-fixtures-up`):

```
cd src/experiments
uv run python3 negative_tests.py
uv run python3 multi_hop.py
uv run python3 functional_tests.py
uv run python3 performance.py 100      # arg = number of runs, default 100
uv run python3 run_all.py              # everything, in the order below
uv run python3 run_all.py --skip-performance --performance-runs 20
```

Constraint honoured throughout: **no `-j`**. Nothing here forks concurrent
kubectl calls against the shared cluster; every suite runs its iterations
sequentially, same discipline as every other verify script in this repo.

## Fixtures (`src/deploy/manifests/experiments/`)

Four pods in namespace `agents`, applied independently of the verify/demo
fixtures so an experiment run never collides with a concurrent `make
verify-vending`/`make demo`:

| Pod | Identity | Role |
|---|---|---|
| `experiments-parent` | `spiffe://lab.local/agent/parent/exp-root` (registered; bootstrap Π(P) = **all three** resource scopes — see below) | root parent for functional/multi-hop/performance |
| `experiments-child` | unregistered at apply time | recipient of P→C; also plays parent for C→G (multi-hop) |
| `experiments-grandchild` | unregistered at apply time | recipient of C→G only |
| `experiments-attacker` | `spiffe://lab.local/svc/test-workload` (reused, already registered) | unrelated authenticated identity for the relayed-manifest scenario |

**Why a new root parent instead of reusing `vend-verify`/`demo`:** both of
those are deliberately limited to a single scope
(`resource:read:datasetA`) in `manifests/policy-engine/
36-policy-engine-bootstrap.yaml`, which is enough to demonstrate
attenuation once but makes "randomized scope sets" degenerate to `{}` vs
`{A}`. `exp-root` holds all three scopes the resource actually defines
(`resource:read:datasetA`, `resource:read:datasetB`,
`resource:write:jobs` — `src/resource/scopes.go`), so the functional suite's
randomized subsets are a meaningful containment check, and the multi-hop
suite's hop 2 has a real escalation attempt to attenuate (`jobs`, present in
Π(P) but not in the attenuated Π(C)).

## Suites, in the order `run_all.py` executes them (highest value first)

### 1. `negative_tests.py`

Five scenarios. Every assertion pins the HTTP status **and** the specific
`detail.reason` string in the matching audit event, because this lab has hit
the vacuous-negative-test failure mode several times during development (one
example: a tightened chain_id validator made an escalation-guard test pass
for the wrong reason after the guard itself had been deleted).

| Test | Mechanism | Denial | Audit reason (`detail.reason`, verbatim) |
|---|---|---|---|
| Forged parent signature | `parentsim vend -corrupt-signature` | HTTP 401 | `manifest signature verification failed: ...` |
| Scope-escalation manifest | request `resource:admin:everything` (zero overlap with Π(P)) | HTTP 403 | `policy engine granted no scopes (Π(requested) ∩ Π(parent) = ∅) — refusing to mint an identity with no authority` |
| Replay (nonce reuse) | resubmit the identical manifest | HTTP 409 | `nonce has already been used for this parent (replay refused)` |
| Credential use after revocation | capture a JWT-SVID pre-disposal, dispose, replay it | HTTP 403 | `policy denied` (from the resource's own audit log, not the vending service's) |
| Orphaned child (parent dies before disposal) | vend with `ttl=5`, never dispose | reaped within `REAPER_INTERVAL` (15s) | `ttl_expired` |

**Falsification:** every guard above was mutated on a **scratch copy** of
`src/vending-service` (never the working tree) and the existing Go unit test that exercises it was
run before/after. See `results/falsification.md` for the full before/after
transcript of all five (unit-test level, not a live cluster
rebuild-and-redeploy five times over — the guards already have dedicated
tests in `cmd/vending-service/main_test.go`, and mutating at that level
exercises the exact code path this suite's live assertions depend on).

### 2. `multi_hop.py` — P → C → G

This is the single strongest result the lab can add (the recursive-delegation gap
Ștefănescu & Aciobăniței's "Lineage" paper addresses with formal proofs —
this lab demonstrates it operationally). **No structural limit was found.**
`manifest.Validate()` already accepts a dynamic-parent shape
(`/agent/parent/<id>/child/<subtask>`) and Π(P) for such a
parent is read back from its own `nhi_grants_*` OPA module rather than
asserted — so a just-vended child can immediately act as
parent for a further delegation with **zero code changes**. This is the
first thing in the repo to actually exercise that path
(`verify-vending.sh` never vends past one hop).

Hop 1 (P→C) requests `{A,B}` against Π(P) = `{A,B,jobs}` → Π(C) = `{A,B}`.
Hop 2 (C→G) requests `{A,B,jobs}` against the just-derived Π(C) = `{A,B}` —
`jobs` is a genuine escalation attempt (it IS in the root's Π(P), but not in
Π(C)) and is correctly attenuated away: Π(G) = `{A,B}`, not `{A,B,jobs}`.
This is the meaningful multi-hop case — attenuation composes hop-over-hop
and does not "see through" to the root's authority. Both hops' audit events
are checked for correct actor attribution (hop 2's vend event is attributed
to the **child's own SPIFFE ID**, not the root parent).

### 3. `functional_tests.py`

- **Randomized scope containment** (30 runs): random subsets of a 5-scope
  pool (the 3 real resource scopes + 2 fictitious ones, so some runs
  legitimately have zero overlap with Π(P)) requested against `exp-root`;
  asserts `child_scopes == requested ∩ Π(P)` **exactly** (not just "is a
  subset" — a service that always granted `∅` would trivially pass a
  subset-only check, which is not what attenuation means).
- **Credential expiry on child termination** (10 runs): vend → wait for the
  child's SVID → dispose (models parent-initiated task completion) →
  measure how long the Workload API takes to actually stop renewing.
  Distinct from the negative-test suite's one-shot version of the same
  check: this measures the *distribution* of that latency, since "on
  termination" is a timing claim that only requires revocation to be
  observable to auditors, not instantaneous.

### 4. `performance.py`

Per-stage latency over **≥100 runs** (default 100, pass an integer arg to
change), storage growth of the delegation store, and a response-payload-size
proxy for network load.

**Single-machine kind cluster on a developer machine — these numbers are
RELATIVE, not absolute.** SPIRE server, SPIRE agent,
OPA, the policy engine, the vending service and the resource all share the
same cores and the same container network. No attempt is made to disguise
that.

**Measurement overhead vs. measured latency, made explicit per field** (see
the module docstring in `performance.py` for the full rationale):

- `vend_call_wall_s` / `operate_call_wall_s` / `dispose_call_wall_s` —
  **harness-measured** wall clock around each `kubectl exec parentsim ...`
  call. Includes kubectl-exec's own connection setup, which is not part of
  the system under test — an upper bound, not the server's own latency.
- `attest_to_vend_audit_delta_s` — **server-measured**, computed from the
  vending service's own audit event timestamps (attest-allow →
  vend-allow, both inside one HTTP request). Not contaminated by
  kubectl-exec overhead; the more trustworthy figure for this specific
  split.
- `spire_attestation_wall_s` — **harness-measured** polling latency (0.5s
  poll interval) from the vend response to the child's own SPIRE agent
  actually producing the new SVID. This is SPIRE agent sync-interval-bound
  behaviour, not vending-service code, and dominates a full cycle's wall
  time by roughly two orders of magnitude over every other stage (see
  results).

Storage growth: the vending-service image is distroless with no shell
(by design — the highest-privilege credential in the lab gets no shell to
attack from), so the SQLite delegation store's file size is read via an
**ephemeral `kubectl debug` container** sharing the pod's PID namespace
(`/proc/1/root/...`) rather than by modifying the image. Reported as `db +
db-wal + db-shm` (WAL mode keeps recent writes in the `-wal` file until a
checkpoint) with an explicit caveat that this makes "bytes per delegation"
a noisy upper-bound estimate between checkpoints, not a precise per-row
figure — reported as measured, not smoothed.

Network load: **not a packet capture.** Response body byte counts per
stage only, explicitly labeled as a lower bound that excludes TLS/HTTP/TCP/
IP framing, the OPA mTLS round trip, the SPIRE Workload API's own gRPC
traffic, and kubectl's own transport. A single-node kind cluster uses the
loopback/bridge network, not a real multi-host network, so an absolute
bandwidth figure would be meaningless regardless.

## What this suite does NOT do (left undone, stated rather than hidden)

- No wrong-caller-identity / relayed-manifest scenario has its own suite
  entry: it is exactly what `verify-vending.sh` already exercises end to end
  (`src/deploy/scripts/verify-vending.sh`, "NEGATIVE — wrong caller identity").
- The performance suite's `spire_attestation_wall_s` is bound by the SPIRE
  agent's sync interval, not by anything this lab's own code controls; no
  attempt was made to tune that interval down to produce smaller numbers,
  since the honest baseline is what the section above documents.
- No concurrent/parallel load test: every suite runs strictly sequentially
  (`.NOTPARALLEL`-equivalent discipline), so these are single-flight
  latencies, not a throughput/contention benchmark. A concurrent-vend
  benchmark against the shared SQLite store and the shared SPIRE admin
  connection would be a reasonable follow-up, not attempted here.
