# src/policy-engine — Policy engine

The synthesis half of the lab's **vend** stage, and the policy-removal half of
**dispose**. It is the ONE identity OPA's `system.authz` policy authorizes to
write Rego, which is the separation of duties that keeps the
vending service's unscoped SPIRE admin from also being the
component that decides what identities are allowed to do.

Design: a deterministic stub synthesizer (LLM backend deferred behind an
interface); a pre-declared mTLS service and the sole policy writer; namespace
`nhi`, identity `spiffe://lab.local/svc/policy-engine`; one grant module per
delegation under the `nhi_grants_*` confinement; HTTP/JSON over mTLS, with Π(P)
read back from OPA and no local state.

---

## Quick start

```bash
# from the repository root — builds, side-loads, deploys and verifies
make verify-policy

# just the unit tests (no cluster needed)
make policy-engine-test

# watch the audit stream
make logs-policy-engine
```

`make verify-policy` needs `make cluster-up && make spire-up && make verify-resource`
first (it deploys the resource itself if not already up, but assumes the
cluster and SPIRE baseline exist).

---

## What this service does, in order

```
POST /synthesize
  │
  ├─► authenticate: mTLS, client cert authorized against CLIENT_SPIFFE_ID
  ├─► validate:    chain_id matches [a-z0-9_]+; child_spiffe_id is a
  │                strict single-segment descendant of parent_spiffe_id
  │                (parent + "/child/" + <subtask-id>) and does
  │                not collide with a bootstrap root parent — see
  │                identity.go
  ├─► derive Π(P): GET /v1/policies from OPA (nhi_grants_* modules matching
  │                parent_spiffe_id, unexpired) UNION the bootstrap ConfigMap
  │                entry for parent_spiffe_id, if any
  ├─► synthesize:  Π(C) = requested_scopes ∩ Π(P)   (deterministic stub)
  ├─► render:      package nhi.grants.<slug> { spiffe_id, scopes, expires_at }
  ├─► push:        PUT /v1/policies/nhi_grants_<slug> to OPA, over mTLS
  └─► respond:     {child_scopes, policy_id, expires_at}

DELETE /synthesize/{chain_id}
  └─► DELETE /v1/policies/nhi_grants_<slug(chain_id)> from OPA
```

Every step is audited (JSON Lines, lab-wide audit schema), stage `vend` or `dispose`.

### Π(P) is never supplied by the caller

This is the central design rule of this service, and the thing most worth
getting right if you touch this code. The wire request
(`synthesizeRequest` in `main.go`) has **no field** that could carry parent
scopes — not "we ignore an incoming `parent_scopes` key", but "there is no
field in the Go struct for `json.Unmarshal` to populate even if the caller
sends one". `TestSynthesizeRequestHasNoParentScopesField` and
`TestHandleSynthesizeIgnoresCallerSuppliedParentScopes` enforce this at both
the type level and end to end through the handler.

Π(P) instead comes from two sources this service derives itself:

1. **OPA read-back** — `GET /v1/policies`, filtered to `nhi_grants_*`,
   parsed, and unioned for every unexpired module whose `spiffe_id` equals
   the request's `parent_spiffe_id`. This is how a **dynamic** parent (one
   that was itself vended as a child) contributes its authority: whatever it
   was granted when *it* was vended is exactly what it may delegate from.
2. **The bootstrap ConfigMap** (`BOOTSTRAP_PARENTS_PATH`,
   `src/deploy/manifests/policy-engine/36-policy-engine-bootstrap.yaml`) — a
   static, cluster-provisioned `spiffe_id -> scopes` table for **root**
   parents, which have no grant module because they were never vended.

A parent absent from both sources has Π(P) = ∅. Every synthesis for it
attenuates to the empty set — fail closed, not an error.

### `child_spiffe_id` must be a real descendant of `parent_spiffe_id`

`child_spiffe_id` is caller-asserted, exactly like `parent_spiffe_id` is —
neither is authenticated the way the ingress mTLS identity is. Nothing stops
a caller from naming ANY identity as the child. Left unvalidated, that
composes into a real escalation: `synthesize(parent=P1, child=P2,
requested⊆Π(P1))` is legal on its own terms (Π(C)⊆Π(P1) holds) and writes a
grant naming P2 — but P2 might be a wholly unrelated identity, not any
descendant of P1. A later `synthesize(parent=P2, ...)` then reads that grant
back as P2's OWN authority via `deriveParentScopes`, which unions every grant
module naming the parent regardless of how it came to exist. Two legal-looking
calls compose into privilege escalation against an inflated, caller-influenced
Π(P2).

`identity.go`'s `validateChildDescendant` closes this: `child_spiffe_id` must
equal `parent_spiffe_id + "/child/" + <subtask-id>`, with a
non-empty, single-segment, trickery-free `<subtask-id>` (go-spiffe's own
`spiffeid` parser rejects `..` and empty path segments), in the same trust
domain, and not equal to any entry in the bootstrap root-parent table (a root
parent is pre-provisioned authority and cannot also be a synthesized child).
Violations are rejected with HTTP 400 and a `deny` audit event **before**
Π(P) is even derived or anything is written to OPA.
`TestHandleSynthesizeRejectsSiblingParentEscalation` drives the exact
escalation above through the real handler; `verify-policy.sh` check [7] does the
same against the live cluster.

`chain_id` is validated too, against `^[a-z0-9_]+$`. The point is not
tidiness: `slugify` lowercases and maps everything outside `[a-z0-9_]` to `_`,
so on a wider input space `chain-1`, `chain.1` and `CHAIN_1` all fold onto the
*same* OPA policy ID — and one delegation would silently overwrite another's
grant module. Accepting only the characters slugify leaves untouched makes the
transform the identity function over everything that reaches it, so two
distinct accepted `chain_id`s are always two distinct policy IDs. That is
injectivity, not merely a reduced collision probability. Callers must
therefore send `chain_id`s already in this form; `-` and uppercase are
rejected at the boundary rather than quietly rewritten.

### The Rego shape, and the two names that must not be confused

One delegation's grant is one OPA module:

```rego
package nhi.grants.<slug>

spiffe_id  := "spiffe://lab.local/agent/parent/t1/child/c1"

scopes     := ["resource:read:datasetA"]

expires_at := 1785012840
```

`<slug>` is `chain_id` with every character outside `[a-z0-9_]` replaced by
`_` (`rego.go:slugify`). It is shared by two different renderings that must
not be confused:

| | Separator | Used as |
|---|---|---|
| `policyID(chainID)` | `nhi_grants_<slug>` | the OPA policy **ID** — the last path segment of `PUT`/`DELETE /v1/policies/<id>`, and what `system.authz`'s `startswith(input.path[2], "nhi_grants_")` matches |
| `packageName(chainID)` | `nhi.grants.<slug>` | the Rego **package** — dot-separated, so the containment rule in `nhi/resource.rego` can address it as `data.nhi.grants.<slug>` |

Disposal only has `chain_id` (there is no local state), so it
recomputes `policyID(chainID)` rather than looking anything up — get the two
renderings backwards and disposal silently targets the wrong (or a
nonexistent) module.

### Parsing is strict by design

This service is the **only** writer of `nhi_grants_*` modules, so
`parseGrantModule` (used when reading Π(P) back) is a narrow regex matched
against the exact shape `renderGrantModule` produces — not a best-effort Rego
parser. Anything that does not match — a hand-edited module, hostile
injected content, a corrupted write — is a hard error for the whole
`GET /v1/policies` call, not a module silently skipped. Silently skipping
would look identical to "this parent has no grant", which is exactly the
condition an attacker forging a module would want to hide inside.
`TestParseGrantModuleRejectsMalformed` exercises nine ways a module can
deviate from the expected shape.

### task_context is accepted and logged, and does nothing else

`SynthesisRequest.TaskContext` exists because the deferred LLM backend
needs it in its signature. The deterministic stub never reads it.
`TestTaskContextIsInert` asserts two requests differing only in
`task_context` produce identical `child_scopes`.

---

## The synthesis interface seam

```go
type Synthesizer interface {
    Synthesize(ctx context.Context, req SynthesisRequest) (SynthesisResult, error)
}
```

`deterministicSynthesizer` (`synth.go`) is the only implementation: Π(C) =
`requested_scopes ∩ Π(P)`, nothing else. A `TODO` in `synth.go` marks
where an LLM-backed implementation would attach — same interface, same
caller, `TaskContext` finally read instead of ignored. **No LLM code or SDK
dependency exists in this package**, by design: the seam is real,
the backend behind it is not built.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `:8443` | mTLS listen address |
| `OPA_URL` | `https://opa.opa.svc.cluster.local:8181` | policy plane |
| `OPA_SPIFFE_ID` | `spiffe://lab.local/svc/opa` | peer authorized on the OPA leg |
| `CLIENT_SPIFFE_ID` | `spiffe://lab.local/svc/vending-service` | the ONE identity `/synthesize` accepts |
| `BOOTSTRAP_PARENTS_PATH` | `/etc/policy-engine/parents.json` | root-parent table |
| `SPIFFE_ENDPOINT_SOCKET` | `unix:///run/spire/sockets/agent.sock` | Workload API |

---

## An observed host quirk in `verify-policy.sh` — not a code bug

The very first connection between a just-created probe pod and a
just-rolled `policy-engine` pod (the `CLIENT_SPIFFE_ID` override in the
script's step 2 forces a fresh rollout every run) sometimes hits a bare TCP
**connect timeout** — no TLS bytes exchanged at all — on this development
host, while a retry moments later succeeds immediately. `verify-policy.sh`'s
`synth()` helper retries up to three times on exactly that symptom (curl
exit 7/28) and nothing else: a completed TLS handshake or HTTP response is
never retried, so the actual things under test (the mTLS refusal, the
attenuation, the disposal) are not what the retry is protecting against.
This reads as a new-pod-IP conntrack/CNI characteristic of the sandboxed
kind cluster used here — the long-lived `resource`/`opa` pods `verify.sh`
and `verify-resource.sh` talk to never show it — not a defect in the Go service.
Recorded here rather than silently retried away.

## How the mTLS ingress is tested

- **Unit-tested** (`main_test.go`): the handler logic, using a fabricated
  `*x509.Certificate` with a SPIFFE URI SAN set directly on
  `http.Request.TLS.PeerCertificates` — this proves the *authorization logic
  inside the handler* (actor extraction, audit attribution) is correct, but
  it never exercises the actual `tlsconfig.MTLSServerConfig` TLS handshake.
- **Integration-tested in isolation** (`verify-policy.sh`), against an
  **override**, so the policy engine can be exercised without the vending
  service: the
  script patches the running Deployment's `CLIENT_SPIFFE_ID` to
  `spiffe://lab.local/svc/policy-probe` (an existing ephemeral
  verification-only identity, see `manifests/test/41-policy-probe.yaml`),
  proves `/synthesize` accepts that identity and refuses the *other* ephemeral
  probe identity (`svc/policy-engine`) at the TLS handshake, then restores the
  Deployment to its real default afterward.
- **Integration-tested with the real default** (`verify-vending.sh`, `make
  demo`, `make experiments`): `svc/vending-service` calls `/synthesize` and
  `DELETE /synthesize/{chain_id}` with its live X509-SVID on every vend and
  disposal.

---

## Layout

```
src/policy-engine/
├── main.go        # wiring, request path, config
├── synth.go       # the synthesis interface seam + the deterministic stub
├── rego.go        # slug/policy-ID/package-name derivation, render + strict parse
├── identity.go    # chain_id shape + child_spiffe_id descendant validation
├── opa.go         # the OPA client (list/put/delete) and Π(P) derivation
├── bootstrap.go   # root-parent ConfigMap loader
├── mtls.go        # SPIFFE-ID-authorized TLS config, both directions
├── audit.go       # audit event schema, JSON Lines
├── *_test.go      # unit tests
└── Dockerfile     # static build, distroless nonroot
```

The base containment rule this service's grants are judged against is **not**
here — it ships with the cluster in
`src/deploy/manifests/opa/30-opa-config.yaml`, precisely so
the component that writes grants cannot also define what a grant means.

---

## Contract for callers (the vending service)

- Send only `chain_id`, `parent_spiffe_id`, `child_spiffe_id`,
  `requested_scopes`, `task_context`, `ttl_seconds` — never parent scopes.
  There is nowhere in the request for them to go.
- `child_spiffe_id` must be `parent_spiffe_id + "/child/" + <subtask-id>`
  — the caller must mint the child's SPIFFE ID in exactly that shape
  before calling `/synthesize`, or the call is rejected with HTTP 400 (see
  `identity.go`). This is also what SPIRE's own registration entry for the
  child should use as its `spiffeID`, so the identity `/synthesize` grants a
  policy to and the identity SPIRE actually issues an SVID for are the same
  string.
- `chain_id` must match `^[a-z0-9_]+$`.
- `policy_id` from the `/synthesize` response is what the delegation
  record should store for later disposal — or just recompute
  `nhi_grants_<slugify(chain_id)>` directly, since it is a pure function.
