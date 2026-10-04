# src/deploy — cluster, SPIRE, policy plane and every lab target

The substrate every other component runs on: a local **kind** cluster, a
**SPIRE** server/agent pair using PSAT node attestation and the Kubernetes
workload attestor in trust domain `lab.local`, and the **authenticated policy
plane** — an mTLS-only OPA plus a pre-declared policy engine. The Makefile here
also builds, deploys and verifies the resource, policy engine, vending service,
agent harness and experiments.

Design choices this directory embodies:

- a local kind cluster rather than a managed one;
- plain manifests rather than Helm;
- the Workload API socket shared by `hostPath` rather than the SPIFFE CSI driver;
- every workload entry parented to a stable **node alias** rather than to an
  agent's SPIFFE ID (which embeds a node UID and changes on every rebuild);
- an **authenticated** policy plane: OPA is a Service reached only over mTLS;
- a `spiffe-helper` sidecar to deliver SVIDs to OPA, which cannot speak the
  Workload API;
- namespace `nhi` for infrastructure services, with the identity convention
  `spiffe://lab.local/svc/<service-account>`;
- DNS SANs on service entries so plain TLS clients (curl) can verify them
  without `--insecure`.

---

## Quick start

```bash
# from the repository root
make clean && make cluster-up && make spire-up && make verify
```

`make verify` exits non-zero if any check fails. It prints the evidence for
each check rather than only a verdict.

`make help` lists every target. The main ones:

| Target | Effect |
|---|---|
| `make cluster-up` | Create the kind cluster `nhi-lab` (idempotent) and side-load the pinned images into both nodes |
| `make spire-up` | Deploy SPIRE server + agent, wait for node attestation, create the static registration entries, deploy the policy plane (OPA + pre-declared policy engine) and the static test workload |
| `make verify` | Assert the baseline: a pod in namespace `agents` under service account `nhi-test` obtains an X.509-SVID **and** a JWT-SVID; **and** the authenticated policy-plane topology |
| `make resource-up` | Build the resource image, side-load it, deploy it into namespace `nhi` |
| `make verify-resource` | One pod and one JWT-SVID: denied without a grant, allowed on dataset A with one, still denied on B |
| `make logs-resource` | Follow the resource's JSON-Lines audit events |
| `make policy-engine-test` | Run the policy engine's Go unit tests |
| `make policy-engine-up` | Build the policy engine image, side-load it, and (re)deploy `manifests/policy-engine/` |
| `make verify-policy` | `POST /synthesize` derives Π(P) from OPA plus the bootstrap table, attenuates an escalation attempt, and the resulting grant governs the resource's allow/deny matrix end to end; `DELETE /synthesize/{chain_id}` disposes it |
| `make logs-policy-engine` | Follow the policy engine's JSON-Lines audit events |
| `make vending-service-test` | Run the vending service's Go unit tests |
| `make vending-service-up` | Build the vending service image, side-load it and deploy it |
| `make verify-vending` | A real spawn manifest, signed and submitted by a real test-parent pod, dynamically creates a child SPIRE registration entry; the child obtains an SVID with no human action; scope escalation is attenuated; forged/relayed manifests and replayed nonces are refused; disposal (on-demand and TTL-reaped) revokes the entry, the grant, and access — see `src/vending-service/README.md` |
| `make logs-vending-service` | Follow the vending service's JSON-Lines audit events |
| `make demo` | One full spawn → attest → vend → operate → dispose cycle driven by the Python agent harness, with every component's audit events collected into `src/deploy/demo-audit.jsonl` |
| `make demo-identity-uniqueness` | Short narrated demo: one parent vends three children, each with a distinct chain_id, SPIFFE ID, SPIRE entry and OPA grant |
| `make experiments` | Run the negative, multi-hop, functional and performance suites (`src/experiments/`) |
| `make clean` | Delete the kind cluster and its kubeconfig context — full teardown |
| `make agent-list` / `make entry-show` / `make bundle-show` | `spire-server` CLI shortcuts against the running server |
| `make logs-server` / `make logs-agent` | Follow SPIRE logs |
| `make opa-port-forward` | Forward OPA to `localhost:8181`. This forwards the port but not the authority — OPA requires a client X509-SVID the host cannot present |

Everything runs against the kubectl context `kind-nhi-lab` explicitly; no target
ever acts on your current context.

**Do not run targets with `make -j`.** Every target mutates one shared cluster
and the ordering is causal; the Makefile sets `.NOTPARALLEL:` because some
shells inject `-j` into `MAKEFLAGS`.

### Running a second cluster alongside this one

Two variables, deliberately separated:

| Variable | Default | What it names |
|---|---|---|
| `CLUSTER_NAME` | `nhi-lab` | the **logical** cluster: the `k8s_psat` `cluster` key hard-coded in the server/agent ConfigMaps, and the node alias `spiffe://lab.local/node/<name>`. Changing it means editing those pinned ConfigMaps, so leave it alone. |
| `KIND_CLUSTER` | `$(CLUSTER_NAME)` | the **infrastructure** cluster: the kind cluster and the kubecontext `kind-<name>`. |

So a second, identically configured cluster is:

```
make cluster-up KIND_CLUSTER=nhi-lab-2 && make spire-up KIND_CLUSTER=nhi-lab-2
```

Overriding `CLUSTER_NAME` alone would produce a node alias selector
(`k8s_psat:cluster:nhi-lab-2`) that no agent can ever match — the agents still
attest as `nhi-lab` — and the failure is silent.

---

## Pinned versions

Verified on Linux/amd64.

### Host toolchain

| Tool | Version | Notes |
|---|---|---|
| Docker Engine | 29.6.2 | containerd image store (`overlayfs` driver) |
| kind | v0.32.0 | |
| kubectl | v1.36.2 | |
| Go | 1.26.5 | resource, policy engine, vending service |
| Python | 3.14.6 | agent harness and experiments; `uv` for the experiments venv |
| OPA CLI | 1.18.2 | matches the in-cluster OPA image |
| `spire-server` / `spire-agent` CLI | 1.15.2 | matches the in-cluster SPIRE images |
| jq | any | required by `scripts/verify.sh` |

`make load-images` needs `docker save --platform`, i.e. Docker ≥ 25.

### Cluster

| Component | Version |
|---|---|
| Kubernetes (kind node image) | **v1.36.1** |
| Node image | `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5` |
| containerd (in-node) | 2.3.1 |
| Node OS | Debian GNU/Linux 13 (trixie) |
| Topology | 1 control-plane (`nhi-lab-control-plane`) + 1 worker (`nhi-lab-worker`) |
| CNI / StorageClass | kindnet / `standard` (rancher.io/local-path), both kind defaults |

The node image is pinned **by digest**, not by tag, so the Kubernetes version
cannot drift when kind is upgraded.

### Container images

| Image | Tag | linux/amd64 manifest digest |
|---|---|---|
| `ghcr.io/spiffe/spire-server` | `1.15.2` | `sha256:410c624a2f2311c23ecc96c24abd854213333f57ccf4fd1c8d3e30b3dbf007bb` |
| `ghcr.io/spiffe/spire-agent` | `1.15.2` | `sha256:5fbe8ac3ad5b1cff355bcf40badb579691e3c8de6cc4c3b8f6792e51336d12a5` |
| `openpolicyagent/opa` | `1.18.2` | `sha256:ab232aee04fdef51a2a0e2e21269386b3f8d169f77754f4ff38fe74e72423e6f` |
| `ghcr.io/spiffe/spiffe-helper` | `0.11.0` | `sha256:2759b3a699bb63b91cc5896f46cd6f70b9e3dfed9f7f4355a3a0a4e702984f9c` |
| `curlimages/curl` | `8.18.0` | `sha256:4940582f3591ca417f9e486a1cc2bfeef6cb3abb92b5a5c462655ceb8cff5115` |

`spiffe-helper` delivers OPA's X509-SVID. `curlimages/curl` is used only by the
ephemeral verify probes — it is the mTLS client that exercises the
policy-plane assertions, and no lab component depends on it at runtime.

SPIRE image tags deliberately equal the pinned CLI version (1.15.2), because the
`spire-server` CLI is executed *inside* the server container by
`scripts/register-entries.sh` and by the `entry-show` / `agent-list` targets.

### Direct Go module dependencies of `src/vending-service`

| Module | Version | Purpose |
|---|---|---|
| `github.com/spiffe/spire-api-sdk` | `v1.15.2` | the SPIRE Entry API client — pinned to match the in-cluster SPIRE server |
| `google.golang.org/grpc` | `v1.79.3` | transport for the Entry API |
| `github.com/go-jose/go-jose/v4` | `v4.1.4` | detached-JWS manifest signing/verification (`cmd/parentsim` signs, the service verifies) |
| `modernc.org/sqlite` | `v1.54.0` | pure-Go SQLite driver (no cgo) for the delegation/nonce store |

---

## Layout

```
src/deploy/
├── Makefile                          # every runnable action
├── kind/kind-config.yaml             # 1 control-plane + 1 worker, node image by digest
├── manifests/
│   ├── 00-namespaces.yaml            # spire, opa, nhi, agents
│   ├── spire/
│   │   ├── 10-server-rbac.yaml       # SA + TokenReview/pods/nodes + bundle ConfigMap
│   │   ├── 11-server-configmap.yaml  # server.conf  (trust domain, k8s_psat, TTLs, admin_ids)
│   │   ├── 12-server-bundle-configmap.yaml
│   │   ├── 13-server-statefulset.yaml
│   │   ├── 20-agent-rbac.yaml        # SA + nodes/proxy for the kubelet query
│   │   ├── 21-agent-configmap.yaml   # agent.conf (k8s_psat, k8s + unix attestors)
│   │   └── 22-agent-daemonset.yaml
│   ├── opa/
│   │   ├── 30-opa-config.yaml        # system.authz Rego, base resource policy, spiffe-helper conf
│   │   ├── 31-opa.yaml               # mTLS Deployment + Service
│   │   └── 32-opa-networkpolicy.yaml # ingress limited to the policy-plane clients
│   ├── policy-engine/
│   │   ├── 35-policy-engine.yaml     # Deployment + Service, pre-declared by spire-up
│   │   └── 36-policy-engine-bootstrap.yaml  # root-parent scope table (ConfigMap)
│   ├── resource/
│   │   └── 50-resource.yaml          # protected resource, ns nhi
│   ├── vending-service/
│   │   └── 60-vending-service.yaml   # vending service, ns nhi
│   ├── agents/
│   │   ├── 70-demo-parent-rbac.yaml  # demo parent SA + Role to create child pods
│   │   └── 71-demo-parent-pod.yaml   # demo parent pod, applied by demo.sh
│   ├── experiments/
│   │   └── 60-experiments-fixtures.yaml  # parent/child/grandchild/attacker pods
│   └── test/
│       ├── 40-test-workload.yaml     # ns agents, sa nhi-test
│       ├── 41-policy-probe.yaml      # ephemeral mTLS probes, applied by verify.sh
│       ├── 42-resource-client.yaml   # ephemeral caller, applied by verify-resource.sh/verify-policy.sh
│       ├── 43-child-workload.yaml    # ephemeral child identity, applied by verify-policy.sh
│       ├── 44-vending-test-parent.yaml  # test parent + attacker, applied by verify-vending.sh
│       └── 45-vending-test-child.yaml   # unregistered child, applied by verify-vending.sh
└── scripts/
    ├── register-entries.sh           # idempotent static entry creation
    ├── verify.sh                     # baseline + authenticated policy plane
    ├── verify-resource.sh            # default deny, then grant
    ├── verify-policy.sh              # synthesis, attenuation, disposal
    ├── verify-vending.sh             # full in-cluster vend lifecycle + negatives
    ├── demo.sh                       # `make demo`
    ├── demo-identity-uniqueness.sh   # `make demo-identity-uniqueness`
    └── demo-identity-uniqueness-walkthrough.md  # the same demo, step by step by hand
```

---

## How the pieces fit

### Node attestation (PSAT)

The single most common bring-up failure is an audience mismatch, so it is
spelled out here. Two values must agree:

| Where | Setting |
|---|---|
| `manifests/spire/11-server-configmap.yaml` | `NodeAttestor "k8s_psat"` → `clusters."nhi-lab".audience = ["spire-server"]` |
| `manifests/spire/22-agent-daemonset.yaml` | `volumes[spire-token].projected.sources[0].serviceAccountToken.audience: spire-server` |

The agent presents the projected token; the server calls `TokenReview` with
`audiences: ["spire-server"]`; the API server checks the token's `aud` claim.
The server additionally restricts issuance to
`service_account_allow_list = ["spire:spire-agent"]`, so only the SPIRE agent's
own service account can attest a node.

Successful attestation is *observed*, not assumed: `make spire-up` polls
`spire-server agent list` and fails if two `k8s_psat` agents have not appeared,
and `make verify` re-checks it.

### Trust bootstrap

The server's `Notifier "k8sbundle"` writes the trust bundle into the
`spire-bundle` ConfigMap in namespace `spire`; the agent mounts it as
`trust_bundle_path`. `make spire-up` blocks on the `bundle.crt` key appearing
(`make wait-bundle`) before applying the agent DaemonSet, so there is no
crash-loop window. No join tokens are used.

### Workload attestation and the Workload API socket

The agent runs with `hostPID: true` (so it can inspect the calling process in
another pod's PID namespace) and `hostNetwork: true` (so the `k8s` workload
attestor can reach the node's kubelet on `127.0.0.1:10250`). The kubelet's
certificate is self-signed in kind, so `skip_kubelet_verification = true` is
set — a lab-only shortcut and a known limitation of this deployment.

The Workload API socket is shared through a `hostPath` at `/run/spire/sockets`
rather than through the SPIFFE CSI driver. A workload pod needs only:

```yaml
volumes:
  - name: spire-agent-socket
    hostPath: { path: /run/spire/sockets, type: DirectoryOrCreate }
```

mounted read-write (`connect(2)` on a Unix socket requires write permission).

### SPIFFE ID scheme in use

| Purpose | SPIFFE ID |
|---|---|
| Trust domain | `lab.local` |
| Node alias (parent of every workload entry) | `spiffe://lab.local/node/nhi-lab` |
| SPIRE agents (assigned by `k8s_psat`) | `spiffe://lab.local/spire/agent/k8s_psat/nhi-lab/<node-uid>` |
| Infrastructure services | `spiffe://lab.local/svc/<name>` |
| Static test workload | `spiffe://lab.local/svc/test-workload` |
| OPA (serving identity) | `spiffe://lab.local/svc/opa` |
| Policy engine (only writer of Rego) | `spiffe://lab.local/svc/policy-engine` |
| Protected resource | `spiffe://lab.local/svc/resource` |
| Vending service (SPIRE admin) | `spiffe://lab.local/svc/vending-service` |
| Verify-only mTLS probe | `spiffe://lab.local/svc/policy-probe` |
| Parent agent | `spiffe://lab.local/agent/parent/<task-id>` |
| Child agent | `spiffe://lab.local/agent/parent/<task-id>/child/<subtask-id>` |

Static root parents registered by `scripts/register-entries.sh`:
`policy-verify` (verify-policy), `vend-verify` (verify-vending), `demo`
(`make demo`) and `exp-root` (experiments). Their scopes live in
`manifests/policy-engine/36-policy-engine-bootstrap.yaml`. Child identities are
**never** registered here — minting them at runtime is the vending service's
job.

### TTLs

| Credential | TTL | Set in |
|---|---|---|
| CA | 24h | `server.conf` `ca_ttl` |
| X.509-SVID | 1h | `server.conf` `default_x509_svid_ttl` |
| JWT-SVID | 5m | `server.conf` `default_jwt_svid_ttl` |

The JWT-SVID TTL is deliberately short: JWT-SVIDs are the credential the
protected resource accepts, so a short lifetime makes the "dispose" stage
observable inside a single experiment run.

### The vending service's SPIRE admin grant

`server.conf` sets `admin_ids = ["spiffe://lab.local/svc/vending-service"]`, so
the vending service may call the Entry API over the server's TCP endpoint
`spire-server.spire.svc.cluster.local:8081` (authenticated by its X509-SVID,
not a JWT-SVID). SPIRE 1.15 cannot scope this grant: the holder may create or
delete **any** entry. Scope attenuation is therefore enforced by the vending
service's own code plus default deny at the resource, not by the SPIRE server.
Child entries are parented to the node alias `spiffe://lab.local/node/nhi-lab`.

---

## The authenticated policy plane

OPA is **not** an open service in this lab. Every request to it is mutually
authenticated with X509-SVIDs and authorized against the client's SPIFFE ID.

| Identity | May do | May not do |
|---|---|---|
| `spiffe://lab.local/svc/policy-engine` | `PUT`/`DELETE`/`GET` `/v1/policies/nhi_grants_*`, evaluate `/v1/data/*` | touch any policy outside `nhi_grants_*` |
| `spiffe://lab.local/svc/resource` | `POST /v1/data/*` (ask for a decision) | write or delete any policy |
| anything else, incl. `svc/vending-service` and every agent | — | everything |
| no client certificate | — | refused at the TLS handshake |

Three mechanisms compose, and the order matters:

1. **`--authentication=tls`** makes a client certificate mandatory. An
   anonymous caller is refused during the TLS handshake and never reaches HTTP.
2. **`--authorization=basic`** evaluates `system.authz`
   (`manifests/opa/30-opa-config.yaml`), which defaults to deny and reads the
   caller's SPIFFE ID from the certificate's **URI SAN**. Note that
   `Subject.CommonName` is empty on a SPIRE SVID — a CN-based rule would not
   error, it would silently match nothing.
3. **A NetworkPolicy** narrows who can open a connection at all. This is
   defence in depth *behind* authentication, not a substitute for it.

The `nhi_grants_` prefix confinement is load-bearing: OPA's policy API can
delete a module loaded from disk at startup and can add a second module to an
existing package, so an unconfined writer could replace the containment rule in
`nhi.resource` itself. With the prefix, the component that writes *grants*
cannot rewrite the *rule that constrains grants*.

`make verify` asserts all of this rather than assuming it, using two ephemeral
probe pods it creates and destroys within the run: an anonymous `PUT` is
refused at the handshake, a `PUT` from `svc/policy-probe` returns HTTP 401 from
`system.authz` (proving the handshake *succeeded* — so the refusal is an
authorization decision, not a dropped packet), and a `PUT` from
`svc/policy-engine` returns 200, which is the positive control that stops a
uniformly deny-everything policy from passing as correct.

### Two consequences worth knowing before you debug something

**Health probes are `tcpSocket`, and cannot be anything else.** OPA's
`--authentication=tls` applies `RequireAndVerifyClientCert` to *every* listener,
including `--diagnostic-addr`. The diagnostic port is exempt from OPA's
authn/authz at the HTTP layer but not at the TLS layer below it. The kubelet
holds no SVID, so no HTTP probe of any scheme can succeed. Readiness therefore
means "the listener accepts TCP" and nothing more. The same holds for the
policy engine.

**Service accounts are security boundaries.** Identity is the selector pair
(`k8s:ns:nhi`, `k8s:sa:<name>`), so any pod running under service account
`policy-engine` in namespace `nhi` *is* the policy engine as far as SPIRE is
concerned. Kubernetes RBAC over who may create pods with that service account is
part of the trusted computing base.

### The policy engine on this substrate

The policy engine's Deployment and Service are **pre-declared** by
`make spire-up`; `make policy-engine-up` builds and side-loads the image. It
does not get to choose its own identity or its own authority over OPA — see
`src/policy-engine/README.md` for its two-credential structure (mTLS in from
the caller, mTLS out to OPA). Π(P) for a root parent comes from the read-only
bootstrap ConfigMap `manifests/policy-engine/36-policy-engine-bootstrap.yaml`.

`child_spiffe_id` is validated as a structural descendant of
`parent_spiffe_id` (`parent + "/child/" + <subtask-id>`) before a grant naming
it is ever written. Testing that needs a real SPIFFE ID shaped as a legitimate
child, which is why `scripts/register-entries.sh` creates
`spiffe://lab.local/agent/parent/policy-verify/child/policy-verify-child`,
selected by a **dedicated** service account `k8s:sa:nhi-test-child` (reusing
`nhi-test` would give that pod a second SVID and break `verify.sh`'s "exactly
one SVID" assertion). Only the **pod** presenting those selectors —
`manifests/test/43-child-workload.yaml` — is ephemeral, applied and torn down by
`verify-policy.sh`.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `make spire-up` fails at "waiting for node attestation" | PSAT audience mismatch or RBAC. `make logs-agent`; check `TokenReview` is allowed for SA `spire-server`. |
| Agent `CrashLoopBackOff` with "no such file .../bundle.crt" | The DaemonSet was applied before the bundle was published. Re-run `make spire-up`; `wait-bundle` gates this. |
| Workload gets no SVID, agent logs "no identity issued" | Selector mismatch. Compare `make entry-show` against the pod's actual namespace/service account. |
| `kind load` fails with `content digest ...: not found` | Docker's containerd image store holds a multi-arch index whose other platforms are absent. The Makefile already works around this via `docker save --platform`; ensure Docker ≥ 25. |
| `docker info` fails | An environment problem (e.g. your user is not in the `docker` group in this session), not something to work around in the Makefile. |
