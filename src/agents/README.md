# src/agents — parent/child agent harness

Python, `spiffe` (the official `pyspiffe`-lineage Workload API
client, PyPI package name `spiffe`), `kubernetes` (in-cluster k8s API
client), `cryptography` (ECDSA signing), `requests`.

This is the harness `make demo` drives: one parent pod
(`parent.py`) that fetches its own SPIRE-issued credentials, decides to
fork, signs and submits a spawn manifest to the vending service, creates
the child pod via the k8s API, waits for it, and disposes the delegation —
and one child pod (`child.py`), created by the parent, that fetches its own
credentials and reads its one granted dataset from the protected
resource.

## Why the child pod is created *after* the manifest is submitted

`verify-vending.sh` (driven by `src/vending-service/cmd/parentsim`) creates
its child fixture pod *before* submitting a manifest — a known limitation
recorded in `src/vending-service/README.md`: that script alone demonstrates no-human-action *identity issuance* into a pod that already
exists, not a real spawn. `parent.py` closes that gap deliberately: it picks
the child pod's name itself (`manifest.new_child_pod_name()`), submits it as
`child_selectors["k8s:pod-name"]`, waits for the vending service's `201`,
and only then calls the k8s API to create a pod with that exact
`metadata.name`. The SPIRE registration entry exists before the pod that
will attest against it does — this is what makes "the child obtains its own
identity with no human action" describe an actual fork.

## The scripted-fork seam

`parent.py`'s `decide_to_fork(own_spiffe_id) -> dict` is the entire surface
a real agent framework would need to replace. It is scripted here — a fixed
task, a fixed scope request, a fixed TTL, read from environment variables —
deliberately: LLM-driven forking is deferred, the same kind of deferral
already made on the authorization side (the policy engine is a
deterministic stub, not an LLM). Everything downstream of
`decide_to_fork()` — signing, submitting the manifest, creating the child
pod, waiting, disposing — is mechanism, not policy, and does not need to
change for a real framework to plug in: it would call `decide_to_fork`'s
replacement, get back the same plain dict shape (JSON-able, not tied to
`manifest.SpawnManifest`), and everything else in `main()` runs unmodified.

## Files

- `manifest.py` — the Python side of the spawn-manifest signature
  scheme. `SpawnManifest.canonical_bytes()` must byte-for-byte match what
  `src/vending-service/internal/manifest.CanonicalBytes()` (Go) produces —
  the Go vending service *recomputes* the signed payload independently from
  the manifest fields it receives rather than trusting the bytes it was
  sent (see that function's own doc comment), so if this module's JSON
  encoding drifts from Go's `encoding/json` in field order, map-key
  ordering, or HTML-safe character escaping, every signature this harness
  produces starts failing verification silently. `sign_manifest()` produces
  a detached JWS (RFC 7515 Appendix F) with the raw, fixed-width `r‖s`
  ECDSA signature JOSE requires — not the DER encoding `cryptography`'s
  `sign()` returns by default.
- `common.py` — Workload API helpers (retrying fetch, since the SPIRE agent
  needs a moment to notice a freshly created entry) and the lab-wide
  audit-event shape, shared by both agents.
- `parent.py`, `child.py` — see module docstrings.
- `Dockerfile` — one image, both roles; the k8s manifests pick the role via
  `command`, the same "one image, dispatch by command" shape
  `cmd/parentsim`'s fixtures use.

## Cross-language correctness: how this was actually verified

Nothing here talks to the vending service's `signature.Verify` (Go) from a
unit test — there is no Python test suite calling into a Go binary. Instead,
before wiring the rest of the harness, both halves were checked directly
against each other:

1. **Canonicalization.** A temporary Go test
   (`internal/manifest/zzz_canon_check_test.go`, deleted before commit — not
   part of the tree) printed `SpawnManifest.CanonicalBytes()` for a fixed
   manifest containing `<`, `>` and `&` in `task_context` specifically to
   exercise Go's HTML-safe escaping. `manifest.py`'s `canonical_bytes()` was
   run against the identical field values and diffed byte-for-byte against
   that output — identical.
2. **Signature.** A Python script generated a self-signed EC P-256
   certificate with a `spiffe://` URI SAN (mirroring
   `internal/signature`'s own Go test fixtures), signed a manifest with
   `sign_manifest()`, and wrote the certificate and signed manifest to disk.
   A second temporary Go test
   (`internal/signature/zzz_python_check_test.go`, also deleted before
   commit) loaded both files and called `signature.Verify()` directly — the
   Python-produced detached JWS verified successfully against Go's own
   verifier, using the caller-supplied trust root, on the first attempt.

Both scratch files are gone; this section exists so the claim "Python's
manifest and Go's verifier actually agree" is falsifiable again by whoever
needs to re-check it, without having to re-derive the check from scratch.

## Build and run

```sh
make demo            # from the repo root, or `make -C src/deploy demo`
```

`demo` depends on `agents-test` (a `py_compile` sanity check — there is no
Go here to `go vet`/`go test`; see the Makefile comment for why this
harness does not also carry a parallel pytest suite), `agents-image` (build + `kind load`), `entries`
(`register-entries.sh` — registers the static
`spiffe://lab.local/agent/parent/demo` root-parent entry, and deliberately
registers nothing for the child), `policy-engine-up` (re-applies
`manifests/policy-engine/36-policy-engine-bootstrap.yaml`, which grants
`agent/parent/demo` its bootstrap Π(P) = `{resource:read:datasetA}`),
`vending-service-up`, `resource-up`.

`src/deploy/scripts/demo.sh` then: restarts the vending service and the
policy engine (the latter picks up the bootstrap ConfigMap; the vending
service's store is durable, so its restart empties nothing — the parent's
time-based nonces and the per-vend `chain_id` keep runs independent), applies
the demo parent's RBAC and pod (delete-then-create for idempotency — pod
specs are immutable),
waits for the parent pod to reach `Succeeded`/`Failed`, then collects every
component's audit events (`kubectl logs`, filtered to lines starting with
`{`) from the parent pod, the child pod, and the vending-service,
policy-engine and resource pods into one `timestamp`-sorted JSON-lines file,
`src/deploy/demo-audit.jsonl` (gitignored — a fresh artifact per run).

**Collection is bounded to the run's own time window.** The five pods
`demo.sh` reads from are long-lived and accumulate audit events across
*every* earlier `make demo`/`make verify-policy`/`make verify-vending` invocation
against the same cluster. An unbounded `kubectl logs` collection was tried
first: it returned ~150 events, ~96% of them leftover verify-policy/
verify-vending traffic sharing no chain_id with the current run —
worthless, and actively misleading, as an input to per-stage latency
computation. `demo.sh` now records a `START_TIME` (UTC, a couple of
seconds before the run's own work begins) and passes it to every `kubectl
logs --since-time` call, and its own attribution check asserts the
collected window contains *exactly one* non-empty `chain_id` — the one this
run minted — not merely that a linked chain exists somewhere in the file.
A typical clean run collects 8 events: `spawn`+`attest` (parent, pre-vend,
`chain_id=""`), two `vend` (vending service and policy engine, each
attributing the *caller* that reached them — the parent and the vending
service respectively), two `operate` (the resource's own event and the
child's own, both attributing the child), two `dispose` (same
vending-service/policy-engine split as vend).

An unbounded collection also showed audit events with an empty
`actor_spiffe_id` (14 in one inspection, all from the resource, all
`/datasets/A`) — these are `verify-resource.sh`'s own negative-test traffic
(`verify-resource.sh` exercises unauthenticated/malformed-token requests against
the resource, which fail before an actor identity is ever established) and
not something a demo run produces. The time-window bound already excludes
them from `demo-audit.jsonl`; noted here rather than chased, since nothing
in this harness creates them.

Manual re-run of just the collected-log checks against an existing
`demo-audit.jsonl`: inspect it directly with `jq`, e.g.
`jq -c 'select(.chain_id=="<chain_id>")' src/deploy/demo-audit.jsonl`.

## Known limitations

None of these weakens a property this harness claims; its scope is
deliberately the happy path (negative testing lives in `src/experiments`).

- **No negative-path testing in this harness.** `parent.py`/`child.py` only
  ever run the allow path. Forged signatures, scope escalation, replay,
  post-revocation access and orphaned children are all already exercised
  against the real vending service by `verify-vending.sh` — this harness does
  not repeat them, and `src/experiments` repeats them at volume.
- **Demo pods accumulate if the namespace is inspected between runs.**
  `demo.sh` deletes the previous run's parent pod and any pod labeled
  `app=nhi-demo-child` *before* creating this run's fixtures, so repeated
  `make demo` invocations are idempotent — but it does not delete them
  *after* a PASS, so a human can `kubectl logs`/`describe` the finished
  pods. Running `make demo` many times without ever inspecting in between
  leaves no litter (each run cleans up the previous one), but killing the
  script mid-run can leave a pod for the *next* run's cleanup step to catch
  rather than this one's.
- **Plaintext HTTP ingress, inherited.** Same as the resource and the
  vending service (see `src/vending-service/README.md`): `parent.py`'s
  calls to the vending service and `child.py`'s calls to the resource are
  plain HTTP. The bearer tokens are JWT-SVIDs with their own short TTL and
  audience restriction, and the manifest itself carries its own
  detached-JWS signature independent of the transport — but the
  transport itself is not confidentiality-protected, consistent with (not a
  new gap beyond) the rest of this lab.
- **The child's `X-NHI-Chain-Id` header is a hint, not a lookup.** Exactly
  the resource's `chain_id_source` contract
  (`src/resource/audit.go`): the resource's own `operate` audit event
  attributes the request to the *authenticated* SPIFFE ID regardless of
  this header; the header only lets a human/collector correlate log lines
  without cross-referencing `actor_spiffe_id` against the delegation
  record by hand. `child.py` emits its own `operate` audit event
  independently, with `chain_id` taken from the `CHAIN_ID` env var
  `parent.py` set when it created the pod — that one *is* authoritative
  (the parent that created this exact pod is the only source for it), just
  not verified by the resource itself.
- **One child per parent run.** `decide_to_fork()` returns a single spawn
  decision; `parent.py` does not loop or fork multiple children, and does
  not implement the multi-hop (P → C → grandchild) case the policy engine's
  Π(P) read-back already supports (exercised by `src/experiments/multi_hop.py`) on the vending-service side. Both are
  mechanically straightforward extensions of the same seam — nothing in the
  vending service or policy engine needs to change — just not built here,
  since the demo is one full cycle, not a fan-out.
