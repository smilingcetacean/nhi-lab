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
- SQLite storage, parent-only disposal, dual TTL enforcement;
- `cmd/parentsim` is a Go test-harness parent, not the agent harness.

---

## Quick start

```bash
# from the repository root — builds, side-loads, deploys and verifies
make verify-vending

# just the unit tests (no cluster needed)
make vending-service-test

# watch the audit stream
make logs-vending-service
```

`make verify-vending` needs `make cluster-up && make spire-up` first (it
deploys the vending service, policy engine and resource itself if not already
up, but assumes the cluster/SPIRE/OPA baseline exists).

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

**Not persisted across pod restarts** in this lab configuration (`emptyDir`,
`manifests/vending-service/60-vending-service.yaml`). That has a real
consequence for disposal. On restart:

- `GET`/`DELETE /delegations/{chain_id}` 404 for every pre-restart
  delegation — a parent that is still alive and still wants to dispose its
  own live child can no longer do so through this service.
- The reaper's work list (`ListExpiredUnrevoked`) is a query over the same
  now-empty table, so it cannot reap what it no longer has a record of.
- The policy engine holds no local state, so nothing anywhere retains the
  mapping from a pre-restart `nhi_grants_*` module back to a `chain_id` —
  every such module is stranded in OPA **permanently**.

**"Revocation state observable to auditors after the task tree is gone"
therefore does NOT survive a vending-service pod restart in this deployment.**
The blast radius is bounded: a stranded `nhi_grants_*` module carries its own
`expires_at` clause and the resource's containment rule already filters
expired grants at decision time, so a stranded grant goes inert on its own
schedule rather than remaining a live authorization bypass. The **SPIRE
entry's own `expires_at`** is independent of this service's state and is
unaffected by a restart — only the bookkeeping and the OPA grant cleanup are
lost. A `PersistentVolumeClaim` backing `DB_PATH` is the real fix and is not
implemented here.

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
│   ├── audit/             # audit event schema, JSON Lines
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

---

## Known limitations

None of these weakens a property claimed above; each is recorded rather than
hidden.

- **Restart durability.** The delegation store is `emptyDir`-backed (see
  Storage above); a vending-service pod restart drops in-flight delegation
  bookkeeping and permanently strands (inert, TTL-bounded) `nhi_grants_*`
  modules in OPA. Auditor-observable revocation state holds only *between*
  restarts, not unconditionally.
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
  fail-safe, reclaimable by the TTL reaper, but unreclaimable if the
  vending-service pod restarts before the reaper runs.
- **`disposeChain`'s SPIRE-entry-delete and audit-event-emit are not atomic
  (`cmd/vending-service/main.go`).** `disposeChain` deletes the SPIRE
  registration entry first and emits the `dispose` audit event last. Any
  observer that treats "the entry is gone" as its readiness signal (e.g.
  `verify-vending.sh`'s reaper check) is reading ahead of a window in which the
  entry has been deleted but the audit event has not yet been written.
