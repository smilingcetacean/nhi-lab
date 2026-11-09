# nhi-lab — runtime identity vending for agent-spawned workloads

A laboratory implementation, on Kubernetes and SPIFFE/SPIRE, of one complete
non-human-identity lifecycle for a **child workload forked at runtime by a
parent agent**, a child that was never pre-registered:

**spawn → attest → vend → operate → log → dispose**

Stock SPIRE requires a registration entry to exist *before* a workload can
attest. This lab adds the missing path: the parent's own SPIFFE credential
attests a signed request to register the child, an independent policy engine
derives the child's permissions from the parent's, and only then does the
vending service mint the child's identity, against an unmodified SPIRE server.

## Properties demonstrated

| Property | Meaning | Where it is enforced / tested |
|---|---|---|
| **Provenance** | The parent proves it spawned the child with its own credential: a JWT-SVID, plus a detached JWS over the manifest signed with its X.509-SVID key. A nonce per manifest refuses replays. No human is in the loop. | `src/vending-service`; `make verify-vending`, negative suite |
| **Scope attenuation** | The policy engine computes Π(child) = requested ∩ Π(parent) and derives Π(parent) itself; the caller never asserts it. The resource denies by default, and OPA's base policy honours a grant only while every ancestor's grant is live. Attenuation composes across hops (P → C → G); `MAX_DELEGATION_DEPTH` (default 2) stops G from vending further. | `src/policy-engine`, `src/resource`, `src/deploy/manifests/opa`; `make verify-policy`, `make rego-test`, `make verify-disposal`, functional and multi-hop suites |
| **Attribution** | The vending service mints a `chain_id` for every delegation, and the vending service, the policy engine, and the agent harness record it in their JSON-lines audit events. The resource anchors each event on the caller's authenticated SPIFFE ID (`actor_spiffe_id`). The `chain_id` it logs comes from the caller's `X-NHI-Chain-Id` header, carries the label `client-asserted` (or `absent`), and never feeds a decision. | all components; `make demo`, `make verify-present`, `make present-audit` |
| **Disposal** | The parent revokes a delegation with `DELETE /delegations/{chain_id}`, which also revokes every descendant. Disposal removes the OPA grant first, then the SPIRE entry, then marks the record revoked. The demo and OpenCode parent pods dispose their delegations when deleted, and Kubernetes garbage-collects their child pods through ownerReferences. If a parent dies without cleaning up, the TTL reaper disposes its delegations at expiry. A child's expiry never exceeds its parent's earliest live grant, a manifest may ask for at most 6 h, and SPIRE's own entry expiry is an independent second layer. | `src/vending-service`, `src/agents`; `make verify-vending`, `make verify-disposal`, `make verify-exit-hooks`, `make verify-persistence`, negative and functional suites |

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

Three kinds of parent drive this flow: a scripted Python parent (`make demo`),
an OpenCode parent pod whose only tool runs one delegation cycle (`make
present-up`), and `cmd/parentsim`, a Go test-harness parent that the verify
scripts, experiments, and benchmarks run inside fixture pods. The OpenCode
parent's child returns its result over mTLS, and the parent accepts only the
vended child's SPIFFE ID.

The agent harness, the vending service, the policy engine, and the resource
emit JSON-lines audit events (`timestamp, stage, chain_id, actor_spiffe_id,
outcome, detail`) to stdout. `make demo` collects one run's events into
`src/deploy/demo-audit.jsonl`, and `make present-audit` streams them live. The
vending service also appends its own events to `audit.jsonl` on its persistent
volume, which `make vending-audit` reads back.

## Prerequisites

Linux on amd64 with Docker ≥ 28 (client and daemon; the daemon reachable
without sudo), kind v0.32.0, kubectl v1.36.2, Go 1.26.5, Python 3.14.6 with
`uv`, the OPA CLI 1.18.2, `jq`, GNU make ≥ 4.0, and bash ≥ 5.0. Docker 28 is
the floor because image side-loading runs `docker save --platform`, which the
docker client gained in version 28. `./install.sh --check-only` checks all of
them: a missing tool stops the install, and a version other than the tested
one only warns. `sudo ./install.sh --install-tools` installs the missing ones
(see [Installing the host tools](#installing-the-host-tools)). Exact pinned
versions, image digests, and dependency versions are in
[`src/deploy/README.md`](src/deploy/README.md#pinned-versions);
`requirements.txt` lists the same host tools.

Debian is not supported as a host, because the packages apt supplies on Debian are too
old for the lab: Debian 13's `docker.io` is 26.1.5, and the lab needs Docker 28
or later. `--install-tools` refuses to run on Debian. Ubuntu, Fedora, and Arch
are supported.

Expect about 5 GB of images in Docker's store and about 4 GB more inside the
two kind node containers.

## Quick start

From a clone of this repository:

```bash
./install.sh --check-only           # check the host tools; changes nothing
sudo ./install.sh --install-tools   # only if tools are missing: install them, then stop
./install.sh                        # without sudo: state what it installs, ask, bring everything up, run `make verify`
```

`install.sh` drives the existing make targets in this order:

1. `make cluster-up`: the kind cluster `nhi-lab` (one control-plane and one
   worker node, Kubernetes v1.36.1) with the pinned images side-loaded;
2. `make spire-up`: SPIRE, the static registration entries, mTLS-authenticated
   OPA, the policy engine's declared identity, and a test workload;
3. `make policy-engine-up`, `make vending-service-up`, `make resource-up`;
4. `make present-up`: the agent harness and OpenCode images and the OpenCode
   parent pod;
5. `make experiments-fixtures-up` and `uv sync --locked` in `src/experiments`;
6. `make verify`, the smoke test.

This bring-up needs no root, installs nothing system-wide, and never downloads
a Python interpreter; kind adds the kube context `kind-nhi-lab` to your
kubeconfig and makes it current. The script never calls sudo itself. Re-running
it is safe: it reuses the cluster, rebuilds the lab
images from the working tree, restarts the components, and keeps the data
volumes.

Options, as a prefix in bash, zsh, or fish 3.1 and later:

```bash
./install.sh --yes                                         # skip the confirmation prompt
KIND_CLUSTER=lab2 ./install.sh                             # create or reuse a cluster with another name
ANTHROPIC_KEY_FILE=$HOME/path/to/key-file ./install.sh     # LLM key for the OpenCode parent
```

With `KIND_CLUSTER`, pass the same value to every later target, for example
`make verify-vending KIND_CLUSTER=lab2`. The key file holds one
`ANTHROPIC_API_KEY=<key>` line; make hands only its path to `kubectl create
secret --from-env-file`, so the key never appears in an argument list or a log.
Without a key file the OpenCode parent runs with no LLM, and `make
verify-present` does not need one.

### Installing the host tools

`sudo ./install.sh --install-tools` (or the same command from a root shell)
installs the host tools the check finds missing, then stops. A tool that is
present at another version stays in use and keeps its warning, and an existing
destination is never overwritten.

- **From the distro's packages** (apt-get on Ubuntu, dnf on Fedora, pacman on
  Arch): GNU make, jq, Docker Engine and its buildx plugin where the
  distro ships one, plus curl, ca-certificates, tar, and gzip if they are
  missing. On Arch this runs `pacman -Syu`, a full system upgrade, because
  partial upgrades are unsupported there.
- **Pinned downloads into `/usr/local`**, each checked against a SHA-256 pinned
  in `install.sh`: kind, kubectl, Go (`/usr/local/go`), the OPA CLI, and uv.
  uv then installs Python 3.14.6 under `/usr/local/share/uv`, checking it
  against a checksum built into uv.
- **Docker.** When the mode installs Docker, it starts the daemon if systemd is
  running, and adds the user who ran sudo to the `docker` group, which takes
  effect at the next login.

Before changing anything it lists every package and download with its source
and destination, and asks for confirmation unless `--yes` is given. It records
what it installed in `/usr/local/share/nhi-lab/installed-tools.txt`, so you can
remove it by hand. When it finishes, run `./install.sh` without sudo for the
bring-up.

If the distro's Docker package is older than 28, the mode stops before
changing anything.

Under sudo, the check runs with sudo's `PATH`, not yours. A tool you keep only
in your own directories, such as `~/.local/bin`, therefore counts as missing
and is installed again into `/usr/local/bin`. The list shown before
confirmation names every tool it will install, so decline if you don't want a
second copy.

To run the lab from inside a container, start it with the host's Docker socket
mounted and on the host's network (`-v /var/run/docker.sock:/var/run/docker.sock
--network host`): kind creates its nodes on the host's Docker, and its
kubeconfig points at `127.0.0.1`. Mount your clone read-only and copy it inside
the container (`./install.sh --help` has an example on `ubuntu:24.04`), so that
running as root there leaves no root-owned files in your clone.

### After the install

Run targets one at a time and never with `make -j`: every target changes the
same cluster, and the root Makefile does not serialize the goals it forwards.

| Command | What it does |
|---|---|
| `make demo` | One spawn → attest → vend → operate → dispose cycle by the Python agent harness; audit events in `src/deploy/demo-audit.jsonl` |
| `make verify-vending` | The full runtime vend lifecycle, plus forged, relayed, and replayed manifests |
| `make verify-disposal` | Cascade revocation, TTL attenuation, depth and child limits, a crashed parent, the vending service's lack of network access to OPA, and token checks at the resource |
| `make verify-persistence` | Deletes the vending-service pod; its records, reaper, audit trail, and nonces survive |
| `make verify-exit-hooks` | Deletes each parent pod mid-cycle; its delegation is disposed and its child pod is garbage-collected |
| `make verify-present` | The OpenCode parent end to end without an LLM: one cycle, an impostor on the callback, and an attenuated request |
| `make present-shell` | Opens OpenCode in the parent pod (needs `ANTHROPIC_KEY_FILE`) |
| `make present-audit` | Streams live audit events from the parent, vending service, policy engine, and resource |
| `make vending-audit` | Prints the vending service's durable audit trail from its volume |
| `make experiments` | Negative, multi-hop, functional, and performance suites; writes `src/experiments/results/<run-id>/` |
| `make help` | Lists every target |
| `make clean` | Deletes the cluster and its kube context |

These checks need no cluster: `make resource-test`, `make
policy-engine-test`, and `make vending-service-test` (Go unit tests), `make
agents-test` (byte-compiles the agent harness), and `make rego-test` (Rego unit
tests; needs the OPA CLI).

The benchmarks are not part of `make experiments`; run them on an otherwise
idle host with `make vend-to-svid`, `make vend-to-access`, `make
revoke-to-deny`, or `make revocation-speed`, or run
`src/experiments/storage_growth.py` by hand (its docstring has the command).
They write to `src/experiments/results/<run-id>/`; the committed runs are in
`benchmarks/`.

### Without install.sh

```bash
make cluster-up    # kind cluster (one control-plane, one worker), pinned images
make spire-up      # SPIRE, static entries, mTLS-authenticated OPA, policy-engine declaration, test workload
make verify        # baseline checks
```

Every verify, demo, and experiment target builds, side-loads, and deploys the
components it needs on top of this baseline.

## Layout

```
.
├── install.sh                 # host check, tool install (--install-tools), full bring-up, and smoke test
├── Makefile                   # forwards every target to src/deploy/Makefile
├── requirements.txt           # host tool prerequisites, listed for reference
├── LICENSE                    # Apache License 2.0
├── benchmarks/                # committed benchmark runs (CSV, JSON, per-trial logs, provenance) and plots/
└── src/
    ├── deploy/
    │   ├── Makefile           # every recipe
    │   ├── kind/              # kind cluster config (node image pinned by digest)
    │   ├── manifests/         # SPIRE, OPA, policy engine, resource, vending service, agents, test and experiment fixtures
    │   ├── policy-tests/      # Rego unit tests for the base containment policy
    │   └── scripts/           # verify, demo, audit, and entry-registration scripts
    ├── resource/              # protected HTTP API (Go)
    ├── policy-engine/         # scope synthesis and grant writer (Go)
    ├── vending-service/       # runtime identity vending via the SPIRE Entry API (Go); cmd/parentsim is the test-harness parent
    ├── agents/                # Python parent/child agent harness; opencode/ holds the OpenCode parent's config and tool
    └── experiments/
        ├── *.py               # experiment suites (run_all.py) and benchmark scripts
        └── results/           # reference-run/, timestamped runs, and falsification.md
```
