# nhi-lab — runtime identity vending for agent-spawned workloads

A laboratory implementation, on Kubernetes and SPIFFE/SPIRE, of one complete
non-human-identity lifecycle for a **child workload forked at runtime by a
parent agent** — a child that was never pre-registered:

**spawn → attest → vend → operate → log → dispose**

Stock SPIRE requires a registration entry to exist *before* a workload can
attest. This lab adds the missing path: the parent's own SPIFFE credential
attests a signed request to register the child, an independent policy engine
derives the child's permissions from the parent's, and only then is the
child's identity minted — against an unmodified SPIRE server.

## Properties demonstrated

| Property | Meaning | Where it is enforced / tested |
|---|---|---|
| **Provenance** | The child was legitimately spawned by the parent, proven by the parent's own credential (JWT-SVID + a detached JWS over the manifest, signed with its X.509-SVID key). No human in the loop. | `src/vending-service`; `make verify-vending`, negative suite |
| **Scope attenuation** | Π(child) ⊆ Π(parent), enforced by the policy engine, never asserted by the caller; default deny at the resource. Composes across hops (P → C → G). | `src/policy-engine`, `src/resource`; `make verify-policy`, functional and multi-hop suites |
| **Attribution** | Every credentialed action is traceable to the delegation chain via a `chain_id` minted at vend time and carried in JSON-lines audit events from every component. | all components; `make demo` |
| **Disposal** | The child's SPIRE entry and OPA grant are revoked on demand by the parent, or by a TTL reaper if the parent dies; SPIRE entry expiry is an independent second layer. | `src/vending-service`; `make verify-vending`, negative and functional suites |

## Architecture

```
 parent agent ──(1) signed spawn manifest, JWT-SVID──► vending service ──(3) create entry──► SPIRE server
      │                                                     │  (sole SPIRE admin)                 │
      │                                         (2) derive Π(C), mTLS                       entry synced
      │                                                     ▼                                     ▼
      │                                               policy engine ──(write grant)──► OPA   SPIRE agent
      │                                               (sole Rego writer)                 ▲        │
      └──(4) create child pod (k8s API)──► child agent ─(5) attest, fetch SVID ──────────┼────────┘
                                               │                                         │
                                               └──(6) JWT-SVID──► protected resource ──(7) decision (mTLS)
```

Every component emits JSON-lines audit events (`timestamp, stage, chain_id,
actor_spiffe_id, outcome, detail`) to stdout; `make demo` collects them into
one file. The vending service also appends its own events to a file on a
persistent volume, which `make vending-audit` reads back.

## Prerequisites

Linux/amd64 with Docker ≥ 25, kind v0.32.0, kubectl, Go 1.26, Python 3.14 with
`uv`, `jq` and `make`. Exact pinned versions, image digests and dependency
versions are in [`src/deploy/README.md`](src/deploy/README.md#pinned-versions).

## Quick start

```bash
make cluster-up        # kind cluster (1 control-plane + 1 worker), pinned images
make spire-up          # SPIRE, static entries, mTLS-authenticated OPA, policy-engine declaration
make verify            # baseline checks

make verify-resource   # default deny, then grant
make verify-policy     # scope synthesis, attenuation, disposal
make verify-vending    # full runtime vend lifecycle, plus forged/relayed/replayed negatives
make verify-persistence # delete the vending-service pod; store, reaper, audit trail and nonces survive
make vending-audit     # print the vending service's durable audit trail (audit.jsonl) from its volume
make demo              # one spawn → … → dispose cycle driven by the Python agent harness
make experiments       # negative, multi-hop, functional and performance suites

make clean             # delete the cluster
```

Targets must run sequentially — never with `make -j`. `make help` lists
everything.

## Layout

```
.
├── Makefile                 # routes every target to src/deploy/Makefile
└── src/
    ├── deploy/              # cluster, SPIRE, OPA, manifests, scripts, Makefile
    ├── resource/            # protected HTTP API (Go)
    ├── policy-engine/       # scope synthesis + grant writer (Go)
    ├── vending-service/     # runtime identity vending via the SPIRE Entry API (Go)
    ├── agents/              # parent/child agent harness (Python)
    └── experiments/         # experiment suites + committed reference run (Python)
```

## Scope and known limitations

This is a single-node, single-trust-domain lab. The policy engine is a
deterministic set-intersection stub behind an interface intended for an
LLM-backed implementation; agent forking is scripted behind a similar seam.
Performance numbers from the bundled reference run are relative, not absolute.
The vending service holds SPIRE's unscoped admin privilege. Its delegation
store, replay nonces and a copy of its audit events are kept on a
PersistentVolumeClaim and survive a pod restart, but not deleting the cluster;
the other components' audit events stay on stdout, and the audit file is not
tamper-evident. Each component README ends with its
own known-limitations section; the most consequential are in
[`src/vending-service/README.md`](src/vending-service/README.md#known-limitations).
