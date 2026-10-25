# src/deploy/Makefile — cluster, SPIRE baseline and every lab component.
#
# `make` is the single entry point for the lab. Run targets from the
# repository root via the top-level Makefile (`make cluster-up`) or directly
# with `make -C src/deploy cluster-up`.
#
# Canonical bring-up:
#     make clean && make cluster-up && make spire-up && make verify

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# Every target here mutates one shared cluster, and the ordering between them is
# causal, not incidental: entries must exist before the workloads that need
# SVIDs, the bundle before the agent, the agent before attestation. Parallelism
# buys nothing (the work is almost entirely waiting on the API server) and cost
# real debugging time when a `make -j` run started `entries` before
# `namespaces`. The prerequisites below are correct on their own; this is the
# belt to that pair of braces.
.NOTPARALLEL:

# CLUSTER_NAME is the *logical* cluster name: it is the k8s_psat `cluster` key
# in the SPIRE server/agent ConfigMaps and the node alias
# spiffe://lab.local/node/$(CLUSTER_NAME) that workload entries are parented
# to. Changing it requires editing those ConfigMaps, so leave it alone.
#
# KIND_CLUSTER is the *infrastructure* name: the kind cluster and kubecontext.
# It defaults to CLUSTER_NAME and is split out so a second cluster can run on
# the same machine without touching the pinned SPIRE configuration — e.g.
# `make cluster-up KIND_CLUSTER=nhi-lab-2`. Override KIND_CLUSTER, never
# CLUSTER_NAME, for that.
CLUSTER_NAME  ?= nhi-lab
KIND_CLUSTER  ?= $(CLUSTER_NAME)
KUBECTX       ?= kind-$(KIND_CLUSTER)
TRUST_DOMAIN  ?= lab.local
DEPLOY_DIR    := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
MANIFESTS     := $(DEPLOY_DIR)/manifests
SCRIPTS       := $(DEPLOY_DIR)/scripts

KUBECTL       := kubectl --context $(KUBECTX)

# Exported so every script and the experiment suites target the same cluster
# as the recipe that invoked them. Without this, `make verify-vending
# KIND_CLUSTER=<other>` would deploy to <other> but run its checks against
# the scripts' default context, kind-nhi-lab.
export CLUSTER_NAME KUBECTX TRUST_DOMAIN

# Pinned images. See README.md for the full version table and digests.
KIND_NODE_IMAGE   := kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5
SPIRE_VERSION     := 1.15.2
SPIRE_SERVER_IMG  := ghcr.io/spiffe/spire-server:$(SPIRE_VERSION)
SPIRE_AGENT_IMG   := ghcr.io/spiffe/spire-agent:$(SPIRE_VERSION)
OPA_IMG           := openpolicyagent/opa:1.18.2
# SVID delivery (as PEM files) for components that cannot speak the Workload API.
SPIFFE_HELPER_IMG := ghcr.io/spiffe/spiffe-helper:0.11.0
# mTLS client used only by verify.sh's policy-plane authentication checks.
CURL_IMG          := curlimages/curl:8.18.0
WORKLOAD_IMAGES   := $(SPIRE_SERVER_IMG) $(SPIRE_AGENT_IMG) $(OPA_IMG) \
                     $(SPIFFE_HELPER_IMG) $(CURL_IMG)

SPIRE_SERVER_EXEC := $(KUBECTL) exec -n spire spire-server-0 -c spire-server -- /opt/spire/bin/spire-server

.PHONY: help
help: ## Show available targets
	@echo "NHI lab — src/deploy (kind: $(KIND_CLUSTER), logical: $(CLUSTER_NAME), trust domain: $(TRUST_DOMAIN))"
	@echo
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Cluster
# ---------------------------------------------------------------------------

.PHONY: cluster-up
cluster-up: ## Create the kind cluster (idempotent) and preload pinned images
	@if kind get clusters 2>/dev/null | grep -qx '$(KIND_CLUSTER)'; then \
	  echo ">> kind cluster '$(KIND_CLUSTER)' already exists"; \
	else \
	  echo ">> creating kind cluster '$(KIND_CLUSTER)'"; \
	  kind create cluster --name '$(KIND_CLUSTER)' --config '$(DEPLOY_DIR)/kind/kind-config.yaml' --wait 120s; \
	fi
	@$(MAKE) --no-print-directory load-images
	@echo ">> waiting for nodes to be Ready"
	@$(KUBECTL) wait --for=condition=Ready nodes --all --timeout=180s
	@$(KUBECTL) get nodes -o wide

# Images are side-loaded rather than pulled by the kubelet so that a bring-up
# is reproducible without hitting a registry, and so image identity is fixed at
# `make` time rather than at pod-schedule time.
#
# Note the docker save/kind load image-archive round-trip: `kind load
# docker-image` asks containerd to import *all* platforms of the local image,
# and Docker's containerd image store keeps the full multi-arch index while
# holding only this host's layers — so the direct path fails with
# "content digest ...: not found". Exporting a single platform sidesteps it.
LOAD_PLATFORM ?= linux/$(shell docker version --format '{{.Server.Arch}}')

.PHONY: load-images
load-images: ## Pull pinned images and side-load them into the kind nodes
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	for img in $(WORKLOAD_IMAGES); do \
	  if ! docker image inspect "$$img" >/dev/null 2>&1; then \
	    echo ">> pulling $$img"; docker pull -q --platform '$(LOAD_PLATFORM)' "$$img" >/dev/null; \
	  fi; \
	  echo ">> loading $$img into kind/$(KIND_CLUSTER)"; \
	  docker save --platform '$(LOAD_PLATFORM)' "$$img" -o "$$tmp/img.tar"; \
	  kind load image-archive --name '$(KIND_CLUSTER)' "$$tmp/img.tar"; \
	  rm -f "$$tmp/img.tar"; \
	done

# Build image $(1) from build context $(2) with Dockerfile $(3), then side-load
# it into the kind cluster through the same single-platform docker save /
# kind load image-archive round-trip that load-images uses, for the same reason.
define build_and_load_image
	@echo ">> building $(1)"
	@docker build -q -t '$(1)' -f '$(3)' '$(2)' >/dev/null
	@echo ">> loading $(1) into kind/$(KIND_CLUSTER)"
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	  docker save --platform '$(LOAD_PLATFORM)' '$(1)' -o "$$tmp/img.tar"; \
	  kind load image-archive --name '$(KIND_CLUSTER)' "$$tmp/img.tar"
endef

# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------

# This target brings up the whole in-cluster baseline —
# SPIRE, its static entries, OPA and the static test workload — so that the
# documented sequence `make clean && make cluster-up && make spire-up &&
# make verify` is sufficient on a machine with no prior state.
.PHONY: spire-up
spire-up: namespaces spire-server spire-agent entries opa-up policy-engine-declare test-workload ## Deploy SPIRE + policy plane + static entries + test workload
	@echo
	@echo ">> baseline up. Run 'make verify'."

.PHONY: namespaces
namespaces: ## Create the spire / opa / agents namespaces
	@$(KUBECTL) apply -f '$(MANIFESTS)/00-namespaces.yaml'

.PHONY: spire-server
spire-server: namespaces ## Deploy the SPIRE server StatefulSet
	@echo ">> deploying SPIRE server $(SPIRE_VERSION)"
	@$(KUBECTL) apply -f '$(MANIFESTS)/spire/10-server-rbac.yaml'
	@$(KUBECTL) apply -f '$(MANIFESTS)/spire/11-server-configmap.yaml'
	@$(KUBECTL) apply -f '$(MANIFESTS)/spire/12-server-bundle-configmap.yaml'
	@$(KUBECTL) apply -f '$(MANIFESTS)/spire/13-server-statefulset.yaml'
	@echo ">> waiting for spire-server to become Ready"
	@$(KUBECTL) rollout status statefulset/spire-server -n spire --timeout=300s

.PHONY: spire-agent
spire-agent: spire-server wait-bundle ## Deploy the SPIRE agent DaemonSet
	@echo ">> deploying SPIRE agent $(SPIRE_VERSION)"
	@$(KUBECTL) apply -f '$(MANIFESTS)/spire/20-agent-rbac.yaml'
	@$(KUBECTL) apply -f '$(MANIFESTS)/spire/21-agent-configmap.yaml'
	@$(KUBECTL) apply -f '$(MANIFESTS)/spire/22-agent-daemonset.yaml'
	@echo ">> waiting for spire-agent DaemonSet to become Ready"
	@$(KUBECTL) rollout status daemonset/spire-agent -n spire --timeout=300s
	@echo ">> waiting for node attestation to complete"
	@for i in $$(seq 1 60); do \
	  n=$$($(SPIRE_SERVER_EXEC) agent list 2>/dev/null | grep -c '^Attestation type .*k8s_psat' || true); \
	  if [ "$$n" -ge 2 ]; then echo ">> $$n agents attested via k8s_psat"; exit 0; fi; \
	  sleep 2; \
	done; \
	echo "!! node attestation did not complete; see 'make logs-agent'"; \
	$(SPIRE_SERVER_EXEC) agent list; exit 1

# The agent's trust_bundle_path points at a key the server's k8sbundle Notifier
# writes asynchronously. Applying the DaemonSet before that key exists produces
# a pointless crash-loop, so gate on it.
.PHONY: wait-bundle
wait-bundle: ## Block until the server has published the trust bundle ConfigMap
	@echo ">> waiting for the spire-bundle ConfigMap to be populated"
	@for i in $$(seq 1 60); do \
	  b=$$($(KUBECTL) get configmap spire-bundle -n spire -o jsonpath='{.data.bundle\.crt}' 2>/dev/null || true); \
	  if [ -n "$$b" ]; then echo ">> trust bundle published ($${#b} bytes)"; exit 0; fi; \
	  sleep 2; \
	done; \
	echo "!! trust bundle never appeared in configmap/spire-bundle"; exit 1

# Depends on spire-agent, not merely on spire-server: the node alias is
# selected on k8s_psat:cluster, so it is only meaningful once agents have
# actually attested.
.PHONY: entries
entries: spire-agent ## Create the static registration entries (idempotent)
	@bash '$(SCRIPTS)/register-entries.sh'

# Depends on `entries`: OPA's spiffe-helper sidecar blocks until the Workload
# API issues svc/opa an SVID, so applying this before the registration entry
# exists just parks the init container until it times out.
.PHONY: opa-up
opa-up: namespaces entries ## Deploy OPA as an mTLS-authenticated service
	@echo ">> deploying OPA (authentication=tls, authorization=basic)"
	@$(KUBECTL) apply -f '$(MANIFESTS)/opa/'
	@$(KUBECTL) rollout status deployment/opa -n opa --timeout=180s

.PHONY: policy-engine-declare
policy-engine-declare: namespaces entries ## Pre-declare the policy engine's identity/manifests (no image build)
	@echo ">> pre-declaring policy engine"
	@$(KUBECTL) apply -f '$(MANIFESTS)/policy-engine/'

# Depends on entries: without its registration entry the pod comes up but never
# receives an SVID, and `make verify` fails on a symptom two steps removed from
# the cause.
.PHONY: test-workload
test-workload: entries ## Deploy the static test workload in namespace agents
	@echo ">> deploying static test workload"
	@$(KUBECTL) apply -f '$(MANIFESTS)/test/40-test-workload.yaml'
	@$(KUBECTL) rollout status deployment/nhi-test-workload -n agents --timeout=180s

# ---------------------------------------------------------------------------
# Verification and inspection
# ---------------------------------------------------------------------------

.PHONY: verify
verify: ## Verify the baseline (attestation, X.509/JWT-SVIDs, authenticated OPA)
	@bash '$(SCRIPTS)/verify.sh'

# ---------------------------------------------------------------------------
# Protected resource
# ---------------------------------------------------------------------------

RESOURCE_SRC := $(abspath $(DEPLOY_DIR)/../resource)
RESOURCE_IMG := nhi-lab/resource:dev

.PHONY: resource-test
resource-test: ## Unit-test the protected resource
	@cd '$(RESOURCE_SRC)' && go test ./...

.PHONY: resource-image
resource-image: ## Build the resource image and side-load it into kind
	$(call build_and_load_image,$(RESOURCE_IMG),$(RESOURCE_SRC),$(RESOURCE_SRC)/Dockerfile)

.PHONY: resource-up
resource-up: resource-image entries ## Deploy the protected resource
	@echo ">> deploying the protected resource"
	@$(KUBECTL) apply -f '$(MANIFESTS)/resource/'
	@$(KUBECTL) rollout status deployment/resource -n nhi --timeout=180s

.PHONY: verify-resource
verify-resource: resource-test resource-up ## Verify the resource (default deny, then grant)
	@bash '$(SCRIPTS)/verify-resource.sh'

.PHONY: logs-resource
logs-resource: ## Tail the protected resource's audit events
	@$(KUBECTL) logs -n nhi -l app=resource -c resource --tail=200 -f

# The base containment policy (resource.rego) is unit-tested with the pinned OPA
# binary against the text shipped in the ConfigMap. No cluster is needed.
.PHONY: rego-test
rego-test: ## Unit-test the base containment policy (Rego) with the pinned OPA
	@bash '$(DEPLOY_DIR)/policy-tests/run.sh'

# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

POLICY_ENGINE_SRC := $(abspath $(DEPLOY_DIR)/../policy-engine)
POLICY_ENGINE_IMG := nhi-lab/policy-engine:dev

.PHONY: policy-engine-test
policy-engine-test: ## Unit-test the policy engine
	@cd '$(POLICY_ENGINE_SRC)' && go test ./...

.PHONY: policy-engine-image
policy-engine-image: ## Build the policy engine image and side-load it into kind
	$(call build_and_load_image,$(POLICY_ENGINE_IMG),$(POLICY_ENGINE_SRC),$(POLICY_ENGINE_SRC)/Dockerfile)

# Re-applies manifests/policy-engine/ (including the bootstrap ConfigMap) and
# waits for the rollout; spire-up only pre-declares the Deployment.
.PHONY: policy-engine-up
policy-engine-up: policy-engine-image entries ## Build, load and (re)deploy the policy engine
	@echo ">> deploying the policy engine"
	@$(KUBECTL) apply -f '$(MANIFESTS)/policy-engine/'
	@$(KUBECTL) rollout status deployment/policy-engine -n nhi --timeout=180s

.PHONY: verify-policy
verify-policy: policy-engine-test policy-engine-up resource-up ## Verify the policy engine (synthesis + OPA push/removal)
	@bash '$(SCRIPTS)/verify-policy.sh'

.PHONY: logs-policy-engine
logs-policy-engine: ## Tail the policy engine's audit events
	@$(KUBECTL) logs -n nhi -l app=policy-engine -c policy-engine --tail=200 -f

# ---------------------------------------------------------------------------
# Vending service
# ---------------------------------------------------------------------------

VENDING_SRC := $(abspath $(DEPLOY_DIR)/../vending-service)
VENDING_IMG := nhi-lab/vending-service:dev
PARENTSIM_IMG := nhi-lab/parentsim:dev

.PHONY: vending-service-test
vending-service-test: ## Unit-test the vending service
	@cd '$(VENDING_SRC)' && go test ./...

.PHONY: vending-service-image
vending-service-image: ## Build the vending service image and side-load it into kind
	$(call build_and_load_image,$(VENDING_IMG),$(VENDING_SRC),$(VENDING_SRC)/Dockerfile)

# parentsim is a minimal Go parent used by verify-vending and the experiment
# fixtures, not the Python agent harness — see src/vending-service/cmd/parentsim.
.PHONY: parentsim-image
parentsim-image: ## Build the parentsim test-harness image and side-load it into kind
	$(call build_and_load_image,$(PARENTSIM_IMG),$(VENDING_SRC),$(VENDING_SRC)/Dockerfile.parentsim)

# Depends on entries: svc/vending-service's own registration entry must exist
# before its pod can obtain an SVID.
# The restart after `apply` is what puts a rebuilt image onto a running
# cluster: the image has a fixed `:dev` tag and imagePullPolicy is Never, so
# when the manifest is unchanged `apply` alters nothing and no new pod would
# start. The store is durable (a PersistentVolumeClaim), so the restart clears
# no delegation records, nonces or audit events.
.PHONY: vending-service-up
vending-service-up: vending-service-image entries ## Build, load and (re)deploy the vending service
	@echo ">> deploying the vending service"
	@$(KUBECTL) apply -f '$(MANIFESTS)/vending-service/'
	@$(KUBECTL) rollout restart deployment/vending-service -n nhi
	@$(KUBECTL) rollout status deployment/vending-service -n nhi --timeout=180s

.PHONY: verify-vending
verify-vending: vending-service-test policy-engine-up vending-service-up parentsim-image resource-up ## Verify the vending service (in-cluster spawn/attest/vend/operate/dispose)
	@bash '$(SCRIPTS)/verify-vending.sh'

# Proves the vending store and its audit trail survive a pod restart: vends a
# long-TTL and a short-TTL child, deletes the vending-service pod, then checks
# disposal through the API, the reaper, the audit file and replay protection
# against the NEW pod. Same prerequisites as verify-vending.
.PHONY: verify-persistence
verify-persistence: vending-service-test policy-engine-up vending-service-up parentsim-image resource-up ## Verify the vending store, reaper, audit trail and nonces survive a pod restart
	@bash '$(SCRIPTS)/verify-persistence.sh'

# Proves the revocation, TTL and creation-limit rules on a live cluster: a
# revoked child takes its whole subtree down, a child never outlives its
# parent's grant, the depth and live-child limits refuse with no state left
# behind, a parent that never disposes is covered by the TTL and the reaper, and
# the vending service cannot open a connection to OPA. Same prerequisites as
# verify-persistence plus the experiment fixtures, whose parent, child and
# grandchild pods form the P -> C -> G chain. It restarts the vending service to
# change its limits and puts the shipped values back afterwards.
.PHONY: verify-disposal
verify-disposal: rego-test vending-service-test policy-engine-test policy-engine-up vending-service-up parentsim-image resource-up experiments-fixtures-up ## Verify cascade revocation, TTL attenuation and creation limits end to end
	@bash '$(SCRIPTS)/verify-disposal.sh'

.PHONY: logs-vending-service
logs-vending-service: ## Tail the vending service's audit events
	@$(KUBECTL) logs -n nhi -l app=vending-service -c vending-service --tail=200 -f

# The vending service image is distroless (no cat, no tar), so the durable
# copy of its audit events (audit.jsonl on the vending-data volume) is read by
# a short-lived pod that mounts the volume read-only. See scripts/vending-audit.sh.
# stdout is the file alone, so `make -s vending-audit | jq .` works.
.PHONY: vending-audit
vending-audit: ## Print the vending service's durable audit trail (audit.jsonl) from its volume
	@bash '$(SCRIPTS)/vending-audit.sh'

# ---------------------------------------------------------------------------
# Agent harness (parent/child), `make demo`
# ---------------------------------------------------------------------------

AGENTS_SRC := $(abspath $(DEPLOY_DIR)/../agents)
AGENTS_IMG := nhi-lab/agents:dev

# There is no Go here to `go vet`/`go test` — py_compile is this Python
# harness's equivalent cheap static check (SyntaxError, obvious import
# mistakes) before spending a docker build on it. There is deliberately no
# pytest suite here: the cross-language signature round-trip (Python signs,
# Go's internal/signature.Verify accepts) that this harness depends on is
# exercised end to end by `make demo` and the experiment suites.
.PHONY: agents-test
agents-test: ## Byte-compile the agent harness (no Go here to vet/test)
	@cd '$(AGENTS_SRC)' && python3 -m py_compile common.py manifest.py parent.py child.py

.PHONY: agents-image
agents-image: ## Build the agent harness image and side-load it into kind
	$(call build_and_load_image,$(AGENTS_IMG),$(AGENTS_SRC),$(AGENTS_SRC)/Dockerfile)

# The OpenCode parent image extends the agents image (same harness, plus a
# pinned, checksum-verified OpenCode and its locked-down project), so it is
# built after it.
OPENCODE_IMG := nhi-lab/opencode-parent:dev

.PHONY: opencode-image
opencode-image: agents-image ## Build the OpenCode parent image and side-load it into kind
	$(call build_and_load_image,$(OPENCODE_IMG),$(AGENTS_SRC),$(AGENTS_SRC)/Dockerfile.opencode)

# One full spawn -> attest -> vend -> operate -> dispose cycle, with audit
# events from every component collected into one JSON-lines file.
# Depends on `entries` (the demo parent's static SPIRE entry and the
# demo-child's deliberate absence — register-entries.sh) and
# `policy-engine-up` (re-applies the bootstrap ConfigMap naming the demo
# parent's Π(P) — manifests/policy-engine/36-policy-engine-bootstrap.yaml).
.PHONY: demo
demo: agents-test agents-image entries policy-engine-up vending-service-up resource-up ## Run the full spawn/attest/vend/operate/dispose demo
	@bash '$(SCRIPTS)/demo.sh'

.PHONY: logs-demo-parent
logs-demo-parent: ## Tail the demo parent's log
	@$(KUBECTL) logs -n agents nhi-demo-parent -c parent --tail=200 -f

# ---------------------------------------------------------------------------
# OpenCode parent (presentation)
# ---------------------------------------------------------------------------

# Path of a file holding one `ANTHROPIC_API_KEY=<value>` line. There is no
# default: nothing in this repository names a location on anyone's machine.
# Only the PATH is ever handled here. `kubectl create secret --from-env-file`
# reads the file itself, so the value never appears in argv, in this Makefile's
# output, or in a log. Without it the Secret is left exactly as it is.
ANTHROPIC_KEY_FILE ?=
# A leading ~/ is expanded here: fish, and zsh by default, pass
# `ANTHROPIC_KEY_FILE=~/...` to make unexpanded, and the recipes quote the path,
# so nothing downstream would expand it either.
PRESENT_KEY_FILE = $(patsubst ~/%,$(HOME)/%,$(ANTHROPIC_KEY_FILE))

# Runs before any image is built, so a mistyped path fails in seconds rather
# than after the builds. Printing the path is fine: it is a location, not the
# key.
.PHONY: present-key-check
present-key-check:
	@if [ -n '$(ANTHROPIC_KEY_FILE)' ] && [ ! -r '$(PRESENT_KEY_FILE)' ]; then \
	  echo "!! ANTHROPIC_KEY_FILE='$(ANTHROPIC_KEY_FILE)' is not a readable file"; exit 1; \
	fi

# Same prerequisites as `demo` plus the OpenCode image. The steps, in order:
#   1. the LLM key Secret (env from a Secret is read when a pod starts, which
#      is one reason the pod is recreated below);
#   2. the parent's RBAC (shared with the demo parent);
#   3. a policy engine restart, so it reads the bootstrap row that gives
#      agent/parent/opencode its Π(P) (dataset A only);
#   4. the pod is deleted and re-applied: pod specs are immutable, and a new
#      pod starts with the current image and Secret.
.PHONY: present-up
present-up: present-key-check agents-test agents-image entries policy-engine-up vending-service-up resource-up opencode-image ## Deploy the OpenCode parent pod (ANTHROPIC_KEY_FILE=<file> supplies the LLM key)
	@if [ -n '$(ANTHROPIC_KEY_FILE)' ]; then \
	  $(KUBECTL) create secret generic opencode-llm -n agents \
	    --from-env-file='$(PRESENT_KEY_FILE)' --dry-run=client -o yaml \
	    | $(KUBECTL) apply -f - >/dev/null; \
	  if $(KUBECTL) describe secret opencode-llm -n agents | grep -q '^ANTHROPIC_API_KEY:'; then \
	    echo ">> Secret opencode-llm applied from the key file"; \
	  else \
	    echo "!! the key file has no ANTHROPIC_API_KEY=... line; the agent will have no LLM"; \
	  fi; \
	elif $(KUBECTL) get secret opencode-llm -n agents >/dev/null 2>&1; then \
	  echo ">> no ANTHROPIC_KEY_FILE given; keeping the existing Secret opencode-llm"; \
	else \
	  echo "!! no ANTHROPIC_KEY_FILE given and no Secret opencode-llm: the agent will have no LLM"; \
	  echo "!! until one is provided: make present-up ANTHROPIC_KEY_FILE=<file with ANTHROPIC_API_KEY=...>"; \
	fi
	@$(KUBECTL) apply -f '$(MANIFESTS)/agents/70-demo-parent-rbac.yaml' >/dev/null
	@$(KUBECTL) apply -f '$(MANIFESTS)/policy-engine/' >/dev/null
	@$(KUBECTL) rollout restart deployment/policy-engine -n nhi >/dev/null
	@$(KUBECTL) rollout status deployment/policy-engine -n nhi --timeout=120s
	@$(KUBECTL) delete pod nhi-opencode-parent -n agents --wait --ignore-not-found >/dev/null
	@$(KUBECTL) apply -f '$(MANIFESTS)/agents/72-opencode-parent-pod.yaml'
	@$(KUBECTL) wait --for=condition=Ready pod/nhi-opencode-parent -n agents --timeout=120s
	@echo
	@echo ">> OpenCode parent is up. Next: make present-shell"

.PHONY: present-shell
present-shell: ## Start the OpenCode TUI in the parent pod (needs a terminal)
	@$(KUBECTL) exec -it -n agents nhi-opencode-parent -c parent -- sh -c 'cd /workspace && exec opencode'

# No LLM and no key needed: it drives the same tool OpenCode would call, with
# fixed arguments, and checks the identity, audit and refusal behaviour.
.PHONY: verify-present
verify-present: present-up ## Verify the OpenCode parent end to end without an LLM (cycle, impostor, attenuation)
	@bash '$(SCRIPTS)/verify-present.sh'

# A parent pod deleted mid-cycle disposes its delegation first, and its child pod
# is garbage-collected. Same prerequisites as present-up, which covers `demo`'s.
.PHONY: verify-exit-hooks
verify-exit-hooks: present-up ## Verify the parents' exit hooks: delete each parent pod mid-cycle, check disposal and ownerReferences
	@bash '$(SCRIPTS)/verify-exit-hooks.sh'

.PHONY: present-audit
present-audit: ## Stream live audit events from the parent, vending service, policy engine and resource
	@bash '$(SCRIPTS)/present-audit.sh'

# A short, narrated demo (contrast the full `demo` above): one parent
# identity (the experiments-parent fixture) vends
# three children back to back and shows each spawn's chain_id/child SPIFFE
# ID/SPIRE entry/OPA grant are all uniquely minted. See
# scripts/demo-identity-uniqueness.sh for the full rationale.
.PHONY: demo-identity-uniqueness
demo-identity-uniqueness: vending-service-up resource-up experiments-fixtures-up ## Short demo: one parent vends 3 children, each uniquely identified
	@bash '$(SCRIPTS)/demo-identity-uniqueness.sh'

# ---------------------------------------------------------------------------
# Experiments (src/experiments, Python/uv)
# ---------------------------------------------------------------------------

EXPERIMENTS_SRC := $(abspath $(DEPLOY_DIR)/../experiments)

.PHONY: experiments-fixtures-up
experiments-fixtures-up: parentsim-image entries policy-engine-up ## Deploy the experiment fixtures (parent/child/grandchild/attacker)
	@echo ">> deploying experiment fixtures"
	@$(KUBECTL) apply -f '$(MANIFESTS)/experiments/'
	@$(KUBECTL) rollout status deployment/experiments-parent -n agents --timeout=150s
	@$(KUBECTL) rollout status deployment/experiments-child -n agents --timeout=150s
	@$(KUBECTL) rollout status deployment/experiments-grandchild -n agents --timeout=150s
	@$(KUBECTL) rollout status deployment/experiments-attacker -n agents --timeout=150s

.PHONY: experiments-fixtures-down
experiments-fixtures-down: ## Tear down the experiment fixtures
	@$(KUBECTL) delete -f '$(MANIFESTS)/experiments/' --ignore-not-found

# Writes a results directory with raw data + a summary table; negative and
# functional tests must pass/deny as expected.
# Depends on the same live components every other verify-* target does
# (vending-service, resource, policy engine) plus its own dedicated fixtures
# (a root parent with a wider bootstrap scope set than the verify/demo parents, so
# the randomized-scope functional suite has more than a singleton to
# randomize over — manifests/policy-engine/36-policy-engine-bootstrap.yaml).
.PHONY: experiments
experiments: vending-service-up resource-up experiments-fixtures-up ## Run the experiment suites (negative, multi-hop, functional, performance)
	@cd '$(EXPERIMENTS_SRC)' && uv run python3 run_all.py

.PHONY: status
status: ## Show cluster, pod and SPIRE state
	@$(KUBECTL) get nodes -o wide
	@$(KUBECTL) get pods -A -o wide | grep -E 'NAME|spire|opa|agents' || true

.PHONY: agent-list
agent-list: ## spire-server agent list
	@$(SPIRE_SERVER_EXEC) agent list

.PHONY: entry-show
entry-show: ## spire-server entry show
	@$(SPIRE_SERVER_EXEC) entry show

.PHONY: bundle-show
bundle-show: ## spire-server bundle show
	@$(SPIRE_SERVER_EXEC) bundle show

.PHONY: logs-server
logs-server: ## Tail the SPIRE server log
	@$(KUBECTL) logs -n spire spire-server-0 -c spire-server --tail=200 -f

.PHONY: logs-agent
logs-agent: ## Tail the SPIRE agent logs
	@$(KUBECTL) logs -n spire -l app=spire-agent --tail=200 --prefix -f

# This is of limited use on its own: OPA requires a client
# X509-SVID, and the host has no SVID to present. It forwards the port, not the
# authority. To exercise the API by hand, exec into a pod that holds an
# appropriate SVID instead — see scripts/verify.sh for the curl invocation.
.PHONY: opa-port-forward
opa-port-forward: ## Forward OPA to localhost:8181 (still requires a client SVID)
	@$(KUBECTL) port-forward -n opa svc/opa 8181:8181

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

.PHONY: clean
clean: ## Delete the kind cluster entirely
	@if kind get clusters 2>/dev/null | grep -qx '$(KIND_CLUSTER)'; then \
	  echo ">> deleting kind cluster '$(KIND_CLUSTER)'"; \
	  kind delete cluster --name '$(KIND_CLUSTER)'; \
	else \
	  echo ">> kind cluster '$(KIND_CLUSTER)' does not exist"; \
	fi
	@kubectl config delete-context '$(KUBECTX)' >/dev/null 2>&1 || true
	@echo ">> clean"
