# Top-level entry point for the NHI lifecycle lab.
#
# `make` is the single interface for humans and CI. This file only routes to
# src/deploy/Makefile, where the real recipes live; run `make help` for the
# full target list.
#
# The kind cluster name defaults to `nhi-lab`. Pass KIND_CLUSTER=<name> to run
# a second, independent cluster on the same machine.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

DEPLOY := src/deploy

.PHONY: help
help: ## Show available targets
	@echo "NHI lifecycle lab — top-level targets"
	@echo
	@$(MAKE) --no-print-directory -C $(DEPLOY) help | tail -n +3

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
                  logs-vending-service vending-audit \
                  agents-test agents-image demo logs-demo-parent \
                  demo-identity-uniqueness \
                  experiments-fixtures-up experiments-fixtures-down experiments \
                  status agent-list entry-show bundle-show logs-server \
                  logs-agent logs-resource opa-port-forward clean

.PHONY: $(DEPLOY_TARGETS)
$(DEPLOY_TARGETS):
	@$(MAKE) --no-print-directory -C $(DEPLOY) $@
