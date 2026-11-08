# Top-level entry point for the NHI lifecycle lab.
#
# `make` is the single interface for humans and CI. This file only routes to
# src/deploy/Makefile, where the real recipes live; run `make help` for the
# full target list.
#
# The kind cluster name defaults to `nhi-lab`. Pass KIND_CLUSTER=<name> to run
# a second, independent cluster on the same machine.
#
# On a new machine, ./install.sh checks the host tools, states what it will
# download and install, and then brings every component up through the
# targets below.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

DEPLOY := src/deploy

.PHONY: help
help: ## Show available targets
	@echo "NHI lifecycle lab — top-level targets"
	@echo
	@echo "  First time on this machine: ./install.sh  (./install.sh --help says what it checks and installs)"
	@echo
	@$(MAKE) --no-print-directory -C $(DEPLOY) help | tail -n +3
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' '$(firstword $(MAKEFILE_LIST))' | grep -v '^help:' \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# Every target src/deploy documents (a `## ` comment, so `make help` lists it)
# must be in DEPLOY_TARGETS below, or `make help` shows a target this file
# cannot reach. A forwarded name that src/deploy no longer documents is
# reported too. The list stays explicit so that `make <typo>` still fails;
# this catches the opposite drift. Undocumented src/deploy targets, such as the
# require-base prerequisite, are internal and are neither forwarded nor checked.
.PHONY: check-targets
check-targets: ## Check that every documented src/deploy target is forwarded by the root Makefile
	@documented=$$(grep -hE '^[a-zA-Z0-9_-]+:.*## ' '$(DEPLOY)/Makefile' | cut -d: -f1 | grep -vx help | sort -u); \
	forwarded=$$(printf '%s\n' $(DEPLOY_TARGETS) | sort -u); \
	missing=$$(comm -23 <(printf '%s\n' "$$documented") <(printf '%s\n' "$$forwarded")); \
	stale=$$(comm -13 <(printf '%s\n' "$$documented") <(printf '%s\n' "$$forwarded")); \
	if [ -n "$$missing" ]; then echo "!! documented in $(DEPLOY)/Makefile but not forwarded:" $$missing >&2; fi; \
	if [ -n "$$stale" ]; then echo "!! forwarded but not documented in $(DEPLOY)/Makefile:" $$stale >&2; fi; \
	if [ -n "$$missing$$stale" ]; then exit 1; fi; \
	echo ">> all $$(printf '%s\n' "$$documented" | wc -l) documented $(DEPLOY) targets are forwarded"

# Route every deploy target to src/deploy. Listed explicitly rather than with a
# catch-all so `make <typo>` still fails loudly.
DEPLOY_TARGETS := cluster-up load-images spire-up namespaces spire-server \
                  spire-agent wait-bundle entries opa-up policy-engine-declare \
                  test-workload verify \
                  resource-test resource-image resource-up verify-resource \
                  policy-engine-test policy-engine-image policy-engine-up \
                  verify-policy logs-policy-engine \
                  vending-service-test vending-service-image parentsim-image \
                  vending-service-up verify-vending verify-persistence \
                  verify-disposal rego-test \
                  logs-vending-service vending-audit \
                  agents-test agents-image demo logs-demo-parent \
                  opencode-image present-up present-shell verify-present \
                  verify-exit-hooks \
                  present-audit \
                  demo-identity-uniqueness \
                  experiments-fixtures-up experiments-fixtures-down experiments \
                  revocation-speed vend-to-svid vend-to-access revoke-to-deny \
                  status agent-list entry-show bundle-show logs-server \
                  logs-agent logs-resource opa-port-forward clean

.PHONY: $(DEPLOY_TARGETS)
$(DEPLOY_TARGETS):
	@$(MAKE) --no-print-directory -C $(DEPLOY) $@
