# src/ — lab implementation

| Directory | Language | Contents |
|---|---|---|
| `deploy/` | Make, YAML, Bash | kind cluster config, SPIRE server/agent, the mTLS policy plane (OPA + pre-declared policy engine), every k8s manifest, the Makefile, and the verify/demo scripts |
| `resource/` | Go | Protected HTTP API: JWT-SVID ingress, mTLS to OPA for every decision, default deny |
| `policy-engine/` | Go | Derives a child's scopes (Π(C) = requested ∩ Π(P)) and is the only writer of grant Rego to OPA; deterministic stub behind an interface seam |
| `vending-service/` | Go | Mints child SPIRE registration entries at runtime via the Entry API from a parent-signed spawn manifest; disposal and TTL reaper; `cmd/parentsim` test-harness parent |
| `agents/` | Python | Parent/child agent harness driven by `make demo` |
| `experiments/` | Python (`uv`) | Negative, multi-hop, functional and performance suites, plus a committed reference run |

Each directory has its own README with build, run and design notes. Every
runnable action is a `make` target — see `deploy/README.md`.
