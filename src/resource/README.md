# src/resource — Protected resource

The lab's protected HTTP API: the **operate** stage of the NHI lifecycle. It is
where a credential is actually spent, and therefore where the
`Π(C) ⊆ Π(P)` claim is either enforced or not.

Design: JWT-SVID ingress with default deny; OPA reached as an mTLS service, not
a sidecar; namespace `nhi` and identity `spiffe://lab.local/svc/resource`; OPA
authorized by SPIFFE ID rather than hostname; and a fixed authorization
contract with the policy engine's generated grants (below).

---

## Quick start

```bash
# from the repository root — builds, side-loads, deploys and verifies
make verify-resource

# just the unit tests
make resource-test

# watch the audit stream
make logs-resource
```

`make verify-resource` proves default deny, then grant, against the running cluster. It
needs `make cluster-up && make spire-up` first.

---

## The two credentials

The single most confusing thing about this service is that it sits between two
different SPIFFE credentials, in opposite directions. They are not
interchangeable.

| | Ingress (callers → resource) | Egress (resource → OPA) |
|---|---|---|
| Credential | caller's **JWT-SVID**, `Authorization: Bearer` | this service's **X509-SVID** |
| Verified against | SPIRE trust bundle, audience `spiffe://lab.local/svc/resource` | SPIRE trust bundle, peer authorized as `spiffe://lab.local/svc/opa` |
| Transport | plain HTTP | **mTLS** |

The audience binding is load-bearing: a JWT-SVID minted for
`spiffe://lab.local/svc/vending-service` is perfectly valid in the trust domain
and is still refused here. `verify-resource.sh` asserts exactly that case.

---

## Request path

Every protected request takes one path, and the order is the security argument:

```
  authenticate  ──►  derive required scopes  ──►  ask OPA  ──►  serve
   (JWT-SVID)         (from method + path)        (mTLS)
        │                                            │
        └──── 401 ────┐                     403 ─────┘
                      ▼
              audit event, always
```

No branch refuses a request without emitting an audit event. That is not
tidiness — the negative tests must show the denial *and* the record of it, so
a silent refusal path would be a hole in the evidence.

### Required scopes are server-derived

`scopes` in the OPA input means the scopes the endpoint **demands**, computed
from the method and path in `scopes.go`. It never means scopes the caller
claimed.

A SPIRE JWT-SVID carries no custom claims — there is nowhere for SPIRE to put a
*verified* scope list. Anything scope-shaped arriving from a caller is therefore
unauthenticated, and honouring it would be a self-grant: a child could simply
assert `resource:read:datasetB` and be believed. So:

- the **resource** says what the request demands;
- **OPA** holds what the subject has been granted;
- the decision is containment of the first in the second.

Neither side can widen the other. `TestRequiredScopesIgnoreCallerInput` and
`TestOPAInputExcludesChainID` are what stop this eroding.

### The chain id is a hint, not evidence

`X-NHI-Chain-Id` is recorded on every audit event alongside a
`chain_id_source` field (`absent` | `client-asserted` | `resolved`). Anyone can
send any value, so it is never an input to a decision — the OPA input has no
`chain_id` field at all, and a unit test enforces that.

The authenticated `actor_spiffe_id` is the attribution anchor. `resolved` is
reserved for a future version in which the chain is looked up from the
vending service's delegation record for the authenticated identity rather than
taken from the request; it is not emitted today.

---

## Endpoints

| Method | Path | Required scope |
|---|---|---|
| `GET` | `/datasets/A` | `resource:read:datasetA` |
| `GET` | `/datasets/B` | `resource:read:datasetB` |
| `POST` | `/jobs` | `resource:write:jobs` |
| `GET` | `/healthz` | none — unauthenticated liveness |

Method is part of an endpoint's identity: holding the read scope for `/jobs`
does not let a caller `POST` to it.

### Status codes carry meaning

| Code | Means |
|---|---|
| `401` | no credential, or an invalid/expired/wrong-audience one. OPA was never consulted. |
| `403` | valid credential, policy said no. This is the default-deny case. |
| `404` | valid credential, no such endpoint. Still audited. |
| `503` | OPA could not be reached. **Denied** — an unreachable authorization service must not become an authorization bypass. |

The 401/403 split matters for the experiments: "I am nobody" and "I am somebody
without this grant" are different findings.

---

## Configuration

All via environment, all with working defaults for the in-cluster deployment.

| Variable | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | ingress address |
| `OPA_URL` | `https://opa.opa.svc.cluster.local:8181` | policy plane |
| `OPA_DECISION_PATH` | `/v1/data/nhi/resource/allow` | the containment rule |
| `RESOURCE_AUDIENCE` | `spiffe://lab.local/svc/resource` | required JWT-SVID audience |
| `OPA_SPIFFE_ID` | `spiffe://lab.local/svc/opa` | peer authorized on the mTLS leg |
| `SPIFFE_ENDPOINT_SOCKET` | `unix:///run/spire/sockets/agent.sock` | Workload API |

---

## Audit events

JSON Lines on stdout, using the lab-wide audit schema shared by every component
(changing it breaks the experiments that parse it):

```json
{"timestamp":"2026-07-25T21:40:11.123456Z","stage":"operate",
 "chain_id":"chain-abc","actor_spiffe_id":"spiffe://lab.local/svc/test-workload",
 "outcome":"allow",
 "detail":{"method":"GET","path":"/datasets/A",
           "required_scopes":["resource:read:datasetA"],
           "chain_id_source":"client-asserted",
           "policy_decision":true,"decision_latency_ms":2.41}}
```

`outcome` is `allow`, `deny` or `error`. `policy_decision` and
`decision_latency_ms` are present only when OPA was actually consulted — absent
on an authentication failure, which never reaches OPA. The experiments read
`decision_latency_ms` for per-stage timings rather than re-instrumenting.

---

## Layout

```
src/resource/
├── main.go           # wiring, request path, chain-id handling
├── scopes.go         # the protected surface; server-side scope derivation
├── authz.go          # the OPA client and the input contract
├── mtls.go           # SPIFFE-ID-authorized TLS config for the OPA leg
├── audit.go          # audit event schema, JSON Lines
├── resource_test.go  # unit tests
└── Dockerfile        # static build, distroless nonroot
```

The policy the service is judged against is **not** here — it ships with the
cluster in `src/deploy/manifests/opa/30-opa-config.yaml`, precisely so the
enforcement point cannot define its own rule.

---

## How other components use this

- The **policy engine** generates grant modules matching the grant shape
  above, named `nhi_grants_<slug>`. The prefix is enforced by OPA's
  `system.authz`: a module named anything else is refused, including one that
  would override the base containment rule.
- A **child agent** does what `verify-resource.sh` does: fetch a JWT-SVID for
  audience `spiffe://lab.local/svc/resource` from the Workload API, then present
  it as a bearer token.
