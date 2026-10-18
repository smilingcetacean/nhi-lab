# src/vending-service — Vending service

The core contribution of this lab: an external controller that mints child
SPIRE registration entries via the Entry API, against a **stock** SPIRE
server, from a spawn manifest the child's parent authenticates and signs. A
credential that already exists (the parent's) vouches for minting one for a
workload forked at execution time — rather than requiring the child's entry to
have existed in advance.

Design at a glance:

- every child entry is parented to the node alias
  `spiffe://lab.local/node/nhi-lab`;
- this service holds **unscoped SPIRE admin** (it is the server's only
  `admin_ids` entry) — read `internal/spireentry` and the limitations below
  before touching it;
- separation of duties: this service calls the policy engine, it never writes
  Rego, and it sends only `parent_spiffe_id`, never Π(P);
- namespace `nhi`, identity `spiffe://lab.local/svc/vending-service`;
- manifests carry their own detached-JWS signature, and `chain_id` is minted
  here;
- SQLite storage on a PersistentVolumeClaim, so records, nonces and a durable
  copy of the audit events survive a pod restart; parent-only disposal; dual
  TTL enforcement;
- `cmd/parentsim` is a Go test-harness parent, not the agent harness.

---

## Quick start

```bash
# from the repository root — builds, side-loads, deploys and verifies
make verify-vending

# delete the pod and prove the store, reaper, audit trail and nonces survive
make verify-persistence

# just the unit tests (no cluster needed)
make vending-service-test

# watch the audit stream (stdout of the running pod)
make logs-vending-service

# read the durable audit trail back from the volume, across restarts
make vending-audit
```

`make verify-vending` and `make verify-persistence` need `make cluster-up &&
make spire-up` first (they deploy the vending service, policy engine and
resource themselves if not already up, but assume the cluster/SPIRE/OPA
baseline exists). Both can be re-run on the same cluster: their nonces carry a
per-run id.

---

## What this service does, in order

```
POST /delegations
  │
  ├─► 1. authenticate: JWT-SVID bearer, audience = svc/vending-service
  ├─► 2a. verify manifest signature: detached JWS, x5c chained to the SPIRE
  │       trust bundle, leaf identity == parent_spiffe_id
  ├─► 3. verify claimed parent_spiffe_id == the AUTHENTICATED caller
  │       (checked here, BEFORE nonce recording — see below)
  ├─► 2b. verify nonce: (parent_spiffe_id, nonce) not seen before
  ├─► 4. call the policy engine, sending ONLY parent_spiffe_id — never Π(P)
  ├─► 5. policy engine derives Π(P) itself and pushes Rego to OPA — this
  │       service never writes policy (separation of duties)
  ├─► 6. create the child registration entry via the SPIRE Entry API
  │       (parent_id = the node alias; entry expires_at = the policy
  │       engine's expires_at, an independent TTL enforcement layer)
  └─► 7. persist the delegation record; respond 201

DELETE /delegations/{chain_id}     (parent-initiated revoke; only the
  │                                 delegation's own parent may call it)
  ├─► delete the SPIRE entry
  ├─► ask the policy engine to remove the grant module
  └─► mark the record revoked

GET /delegations/{chain_id}        (any authenticated identity may read)

reaper (every REAPER_INTERVAL)     (the orphaned-child case)
  └─► finds delegations past expires_at with revoked_at IS NULL, disposes
      them through the SAME code path as DELETE above, reason=ttl_expired
```

Every step is audited (JSON Lines, lab-wide audit schema), stage `attest`,
`vend` or `dispose`.

### Why the manifest carries its OWN signature, separate from the JWT-SVID

A JWT-SVID is a bearer token. If manifest integrity depended on nothing but
the bearer token that authenticates the HTTP call, a captured token would let
an attacker submit *any* manifest as the parent. So there is a second,
distinct binding: the parent signs the manifest's canonical bytes with the
private key backing its own X.509-SVID — a key that never leaves its Workload
API boundary — and carries the certificate chain in the JWS `x5c` header. A
stolen bearer token alone is not enough to forge a new manifest; the attacker
would also need that key.

Two checks close two different attacks, and the audit reason names which one
fired:

- **Forged/corrupted signature** → HTTP 401, reason contains `signature`.
- **Genuinely signed manifest relayed by someone else** (the signature is
  real — it really is the claimed parent's — but the AUTHENTICATED caller is
  a different identity) → HTTP 403, reason contains `does not match ...
  authenticated caller`.

`verify-vending.sh` exercises both, and specifically constructs the second case
via `parentsim sign` (build+sign, don't submit) followed by a DIFFERENT
identity relaying that exact manifest. A test that only reused
`-claim-parent` without a matching signature would have been vacuous: it would
hit the signature check first and never actually exercise step 3.

### `chain_id` is minted here, not supplied by the parent

The spawn manifest has no `chain_id` field. This service mints one per
accepted vend (`newChainID`, `cmd/vending-service/main.go`): 16 random bytes,
hex-encoded with a `c_` prefix — already satisfying the policy engine's
`^[a-z0-9_]+$` contract with no transform needed. It is returned in the
response and is what the caller must present to
`DELETE /delegations/{chain_id}` later.

### Nonce recording is ordered AFTER the caller/claim check, not before

This is the one place the step order deviates from its numbering, and it
closes a real bug: nonce recording is a state mutation. Recording it before
checking that the claimed parent equals the authenticated caller would let an
attacker who merely *relays* a captured, genuinely-signed manifest burn that
`(parent, nonce)` pair through its own, ultimately-403'd request — denying the
real parent's later, legitimate submission of that exact manifest as "already
used". See `TestHandleVendRelayedManifestDoesNotBurnTheRealParentsNonce`.

### Two independent TTL mechanisms — do not cite either alone

1. The **SPIRE registration entry's own `expires_at`** (set from the policy
   engine's `expires_at` at vend time) means SPIRE itself refuses to
   issue/renew SVIDs under the entry past that time, even if this service is
   down. This is what makes "the child's SVID stops being renewable" true
   unconditionally.
2. The **reaper** separately disposes of expired-but-not-yet-revoked
   delegation records — deleting the (by then likely already-inert) SPIRE
   entry, removing the OPA grant module (which mechanism 1 does nothing
   about), and marking the record revoked with `revocation_reason:
   "ttl_expired"`. This is what actually cleans up the orphaned-child case,
   and what makes the disposal state observable to auditors rather than
   merely "SPIRE quietly stopped renewing".

---

## The policy-synthesis seam this service depends on

This service does not implement policy synthesis itself — it calls
`src/policy-engine`'s `/synthesize` over mTLS (`internal/policyclient`),
sending only `chain_id`, `parent_spiffe_id`, `child_spiffe_id`,
`requested_scopes`, `task_context`, `ttl_seconds`. There is no field for
parent scopes in the wire type (`policyclient.SynthesizeRequest`) — the
strongest enforceable form of "this service cannot assert Π(P)", matching
the policy engine's own `synthesizeRequest`.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `:8090` | HTTP listen address (ingress: JWT-SVID bearer) |
| `VENDING_AUDIENCE` | `spiffe://lab.local/svc/vending-service` | JWT-SVID audience this service accepts |
| `TRUST_DOMAIN` | `lab.local` | selects the X.509/JWT bundle for verification |
| `POLICY_ENGINE_URL` | `https://policy-engine.nhi.svc.cluster.local:8443` | policy plane |
| `POLICY_ENGINE_SPIFFE_ID` | `spiffe://lab.local/svc/policy-engine` | peer authorized on the policy-engine leg |
| `SPIRE_SERVER_ADDR` | `spire-server.spire.svc.cluster.local:8081` | SPIRE admin API |
| `SPIRE_SERVER_SPIFFE_ID` | `spiffe://lab.local/spire/server` | SPIRE server's own serving identity — verified empirically against the running cluster, see below |
| `NODE_ALIAS_SPIFFE_ID` | `spiffe://lab.local/node/nhi-lab` | `parent_id` of every child entry |
| `DB_PATH` | `/var/lib/vending-service/vending.db` | SQLite delegation + nonce store |
| `AUDIT_LOG_PATH` | unset (`/var/lib/vending-service/audit.jsonl` in the deployed manifest) | when set, every audit event is also appended to this file; if it cannot be opened the service exits non-zero — see Storage |
| `SPIFFE_ENDPOINT_SOCKET` | `unix:///run/spire/sockets/agent.sock` | Workload API |
| `REAPER_INTERVAL` | `30s` (`15s` in the deployed manifest) | TTL sweep interval |
| `NONCE_RETENTION_MARGIN` | `24h` | how long past a manifest's own TTL a consumed nonce is still remembered |

`SPIRE_SERVER_SPIFFE_ID` was verified empirically (`tls.Dial` against
`spire-server.spire.svc.cluster.local:8081` with `InsecureSkipVerify`, then
reading `PeerCertificates[0].URIs`): the server's serving certificate carries
`spiffe://lab.local/spire/server`, distinct from any `admin_ids` entry (which
names the *caller* this service authenticates as, not the server's own
identity).

---

## Storage

SQLite, file-backed (`modernc.org/sqlite`, pure Go — no cgo, so the image
stays a static distroless build like `src/resource` and
`src/policy-engine`). Two tables, `internal/store/store.go`:

- `delegations` — the delegation record, plus `entry_id`/`policy_id` so
  disposal needs no external lookup.
- `used_nonces` — `(parent_spiffe_id, nonce)` primary key. Replay protection
  is scoped **per parent**, not global: two different parents may reuse the
  same nonce value without either being treated as a replay of the other.

**Durable across pod restarts.** `DB_PATH` and the audit file below live on
the PersistentVolumeClaim `vending-data` (`ReadWriteOnce`, 256Mi, the cluster's
default StorageClass, which is `local-path` on kind), mounted at
`/var/lib/vending-service` in place of scratch storage
(`manifests/vending-service/59-vending-data-pvc.yaml`,
`manifests/vending-service/60-vending-service.yaml`). After
`kubectl delete pod -l app=vending-service` the new pod finds everything the
old one had written:

- `GET`/`DELETE /delegations/{chain_id}` work for pre-restart delegations — a
  parent can still dispose its own live child through this service, and the
  disposal removes the child's SPIRE entry and OPA grant as usual.
- The reaper's work list (`ListExpiredUnrevoked`) is a query over the same
  table, so the new pod reaps a delegation vended before the restart when its
  TTL expires (`dispose` / `ttl_expired`, original `chain_id`).
- Replay protection holds: a nonce used before the restart is still refused
  with `409`.
- The audit events below.

`make verify-persistence` shows each of these on a live cluster.

**"Revocation state observable to auditors after the task tree is gone"**
therefore holds across a vending-service pod restart, for this service's own
events (`vend`, `dispose`, and the `attest` decisions). Its limits:

- **Single writer.** The store is one SQLite file, so the Deployment has one
  replica and `strategy: Recreate`: on a rollout the old pod stops before the
  new one starts, so two pods never hold the file (or run two reapers) at once.
  The cost is a few seconds without a vending service on every rollout. HA or
  more than one replica is not supported.
- **Node-bound volume.** The `local-path` volume is pinned to the node where it
  was first provisioned, and the pod follows it. Fine on a two-node lab cluster.
- **The volume lives inside the cluster.** Deleting the claim
  (`kubectl delete -f manifests/vending-service/`) or the cluster
  (`make clean`) erases the delegation records, the nonces and the audit file
  together. A new `vending-data` volume starts empty.
- **A new failure mode.** If the claim cannot bind, the pod stays `Pending` and
  `rollout status` times out.
- **OPA's grants are not part of this.** They live in OPA's memory. If OPA
  restarts they are gone and access fails closed (deny), which is unchanged.

### Audit copy: `AUDIT_LOG_PATH`

Every audit event is written to stdout as one JSON line, as always. When
`AUDIT_LOG_PATH` is set, the identical line is then appended to that file
(opened `O_APPEND|O_CREATE|O_WRONLY`, mode `0640`), so `kubectl logs`, `make
demo` and the experiment suites see exactly what they saw before. The schema is
unchanged. With `AUDIT_LOG_PATH` unset (unit tests, local runs) behaviour is
exactly as before.

- If the file cannot be opened at startup the service exits non-zero with a
  clear error: a service that should persist its trail but silently cannot is
  worse than one that does not start.
- A write error at runtime is reported on stderr and does not change the
  request's outcome, nor drop the stdout line (the two writes are sequential,
  not an `io.MultiWriter`).
- There is no `fsync` per event. A pod deletion or container crash keeps every
  line already written, because it sits in the node's page cache; a node or
  kernel crash can lose the last few events.
- If a file write fails partway, for example because the volume is full, the
  file can keep a fragment with no trailing newline, and the next appended
  event is joined onto it. The event is still on stdout, and the error is
  reported on stderr.
- The file is **not tamper-evident**: anyone with write access to the volume
  can edit it. There is no rotation either; at roughly 0.5 KB per event 256Mi
  holds on the order of 500k events, a limit and not a guarantee.
- Only this service's events are kept. The policy engine's and the resource's
  audit events stay on their pods' stdout and are lost with those pods.

### Reading the trail: `make vending-audit`

The image is distroless, so there is no `cat` or `tar` to `kubectl exec` or
`kubectl cp` with, and the service deliberately has no endpoint that serves its
own audit file (it holds unscoped SPIRE admin; it does not need a new surface).
`make vending-audit` instead starts a short-lived pod from `curlimages/curl`
(already used in the lab) that runs as UID/GID 65532, non-root, without
privilege escalation, mounts `vending-data` with `readOnly: true`, prints
`audit.jsonl` and is deleted again, even on failure
(`src/deploy/scripts/vending-audit.sh`, `src/deploy/manifests/test/46-vending-audit-reader.yaml`).
Only the file is written to stdout, so `make -s vending-audit | jq .` works.

---

## `cmd/parentsim` — a Go test-harness parent, NOT the agent harness

Read the doc comment at the top of `cmd/parentsim/main.go` before extending
this. It drives `verify-vending.sh`, the experiment suites and the
identity-uniqueness demo: a real parent submitting a real, signed manifest,
and a real child pod obtaining a real SVID. The Python agent harness in
`src/agents` is the seam for a real agent framework; this binary is not. Every
negative-test scenario is a flag:

| Flag | Effect |
|---|---|
| `-corrupt-signature` | flips a character in the signature — forged-manifest test |
| `-nonce <fixed>` | same nonce across two invocations — replay test |
| `-claim-parent <id>` | manifest claims a parent different from the caller's own identity |
| `-raw-manifest <json>` (with `sign` mode) | relay a manifest genuinely signed by someone ELSE — the meaningful wrong-caller-identity test, see above |

Modes: `vend`, `sign` (build+sign, don't submit), `dispose`, `get`, `whoami`,
`call` (fetch a JWT-SVID for an arbitrary audience and hit a URL — used by
the child pod), `fetch-jwt` (print a JWT-SVID, no HTTP call — used to CAPTURE
a token before disposal), `bearer-call` (replay a caller-supplied token
verbatim — the complement of `fetch-jwt`), `x509-check` (one-shot Workload
API fetch, used to observe an SVID appearing/disappearing without relying on
the streaming API's own caching).

---

## Layout

```
src/vending-service/
├── cmd/
│   ├── vending-service/   # the actual service: main.go, mtls.go, reaper.go, *_test.go
│   └── parentsim/         # Go test-harness parent (not the agent harness)
├── internal/
│   ├── manifest/          # SpawnManifest, canonicalization, structural validation
│   ├── signature/         # detached JWS + x5c verify/sign
│   ├── audit/             # audit event schema, JSON Lines; optional file sink (AUDIT_LOG_PATH)
│   ├── store/             # SQLite: delegation records + nonce replay table
│   ├── spireentry/        # SPIRE Entry API client (spire-api-sdk)
│   └── policyclient/      # policy engine client
├── Dockerfile             # the vending-service image
├── Dockerfile.parentsim   # the parentsim image
└── go.mod
```

---

## What is tested, and how

- **Unit** (`go test ./...`, no cluster): every package, including
  `internal/signature`'s round trip with REAL ECDSA keys and certificate
  chains (not mocked crypto), and `cmd/vending-service`'s handler tests
  using a fake dual bundle (`fakeBundle`) so JWT-SVID validation and x5c
  chain verification both run their actual cryptographic paths against an
  in-memory CA. Negative tests assert the *reason* string in the audit
  event, not just the HTTP status — a bare status code can be satisfied by
  an earlier rejection on the same code path, which is exactly the failure
  mode `TestHandleVendRejectsForgedSignature` and
  `TestHandleVendRejectsClaimedParentNotMatchingCaller` are written to rule
  out.
- **Integration** (`make verify-vending`, needs a live cluster): the full
  spawn → attest → vend → operate → dispose cycle against the real vending
  service, real SPIRE Entry API, real policy engine and real OPA — see
  `src/deploy/scripts/verify-vending.sh`'s header for the exact scenario list.
  Its nonces carry a per-run id, so it passes when run repeatedly against the
  same cluster.
- **Durability** (`make verify-persistence`, needs a live cluster): vends a
  long-TTL and a short-TTL child, deletes the vending-service pod, then checks
  that the new pod still serves and disposes the long-TTL delegation (and the
  resource then denies the child), reaps the short-TTL one, still refuses a
  pre-restart nonce, and that `make vending-audit` shows the pre-restart `vend`
  and post-restart `dispose` events for both chains as valid, schema-exact JSON
  lines. The audit file copy has a unit test in `internal/audit/audit_test.go`
  (both sinks byte-identical, a failing file sink does not stop stdout, schema
  keys exactly as before).

---

## Known limitations

None of these weakens a property claimed above; each is recorded rather than
hidden.

- **Durability has a scope.** The delegation store, the nonce table and this
  service's audit events survive a pod restart (see Storage). They do not
  survive deleting the claim or the cluster; the audit file is neither
  tamper-evident, rotated nor synced per event; the policy engine's and the
  resource's audit events and OPA's grants are not durable; and the service
  runs as a single replica.
- **Double-vend for the same child (untested, unfixed).**
  `internal/spireentry.CreateChildEntry` treats SPIRE's `codes.AlreadyExists`
  as success and returns the pre-existing entry's ID. Two manifests that
  resolve to the same `child_spiffe_id` therefore each get `201`, each get
  their own `chain_id`/delegation record/OPA grant, but share one underlying
  SPIRE entry. Disposing either deletes the shared entry out from under the
  other, whose delegation record is left with `revoked_at IS NULL` even
  though its child can no longer obtain an SVID. The second vend's
  `expires_at` also silently fails to apply to the pre-existing entry. A
  real fix (reject the duplicate outright vs. reconcile the two records vs.
  update the existing entry's TTL) is a decision for whoever next touches
  `internal/spireentry.go`.
- **`verify-vending.sh` creates the child pod before the manifest is
  submitted.** What that script demonstrates with no human action is
  *identity issuance* to a pod that already exists — not the pod's own
  creation. The full "child spawned with no human in the loop" claim rests on
  `make demo`, where `src/agents/parent.py` creates the child pod via the k8s
  API only after the vending service has minted its entry.
- **Plaintext HTTP ingress.** This service's own `:8090` ingress is plain
  HTTP, matching `src/resource`'s convention. A caller's JWT-SVID bearer token
  therefore crosses the pod network in cleartext on the inbound leg — the
  outbound legs to OPA and the policy engine are mTLS. This is exactly the
  scenario the manifest-signature threat model is written against (a
  captured bearer token replays the *connection*, not a *manifest* — the
  signature is what the JWT alone cannot substitute for). TLS-terminating the
  inbound leg with this service's own X.509-SVID is a reasonable follow-up,
  best done together with the resource's ingress for consistency.
- **`child_selectors` consistency check is an allow-list of
  pod-distinguishing selector keys, not a full superset check.**
  `manifest.Validate()` requires at least one `child_selectors` key from
  `{k8s:pod-uid, k8s:pod-name, k8s:sa}` (`distinguishingSelectorKeys` in
  `internal/manifest/manifest.go`), and the handler requires `k8s:ns` to match
  the caller's own attested namespace. A weaker guard ("any key besides
  `k8s:ns`") would be a key-*count* test, not a distinguishing-*power* test:
  it accepts `k8s:node-name`, a real selector SPIRE's k8s workload attestor
  emits that identifies a whole node, not one pod. Probed live,
  `{"k8s:ns": "agents", "k8s:node-name": "nhi-lab-worker"}` got a `201` that
  matched every pod on that node in this lab's fixture cluster
  (`nhi-test-workload`, `vending-test-attacker`, `vending-test-parent` — all
  co-resident on one worker), with demonstrated consequences: the submitting
  parent's own Workload API subsequently returned the *child's* SVID instead
  of its own (identity hijack of the submitting pod), the parent's next vend
  was attributed to that hijacked identity (attribution loss across the
  matched set), and `DELETE /delegations/{chain_id}` calls against the
  affected delegations returned `403` until the TTL reaper recovered them
  (loss of on-demand disposal for the full TTL window). The allow-list closes
  that specific case and fails closed on any selector key this code has not
  enumerated, by construction (only three keys are accepted; everything else
  is refused, not merely the keys known to be bad).

  What remains open, and is treated as an accepted non-goal of this lab
  rather than a defect to keep chasing: a parent can still name a real
  sibling pod's own service account (e.g. `{"k8s:ns": "agents", "k8s:sa":
  "some-other-pods-sa"}`) and have SPIRE match that pod too — `k8s:sa` is not
  unique across pods sharing a service account. A full selector-superset
  check was considered and rejected because it would reject this lab's own
  parent/child fixtures, which intentionally use different service accounts
  in the same namespace. **This lab does not defend against a malicious
  parent choosing `child_selectors` that name another pod's identity** — the
  vending service trusts the submitting parent to name selectors for the
  child it actually intends to identify, in the same way it trusts the
  parent's manifest signature to be over a request the parent actually
  means. **Attribution consequence:** for as long as this residual stands, a
  `chain_id` recorded at vend time is attributable to *the set of pods
  matching the named selectors*, not provably to one pod. In this lab's own
  fixtures that set has exactly one member because each pod's service account
  is unique, but nothing in the vending service verifies that — the guarantee
  holds topologically (how this lab happens to be deployed), not
  mechanically. Also open: `k8s:ns` plus a `k8s:sa` naming no real pod still
  returns `201`, minting an entry matching nothing that currently exists —
  fail-safe, and reclaimable by the TTL reaper (also across a
  vending-service restart, because the delegation record is durable).
- **`disposeChain`'s SPIRE-entry-delete and audit-event-emit are not atomic
  (`cmd/vending-service/main.go`).** `disposeChain` deletes the SPIRE
  registration entry first and emits the `dispose` audit event last. Any
  observer that treats "the entry is gone" as its readiness signal (e.g.
  `verify-vending.sh`'s reaper check) is reading ahead of a window in which the
  entry has been deleted but the audit event has not yet been written.
