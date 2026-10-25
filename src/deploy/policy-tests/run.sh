#!/usr/bin/env bash
# Runs the Rego unit tests against the base containment policy exactly as it
# ships: resource.rego is cut out of the opa-authz ConfigMap
# (manifests/opa/30-opa-config.yaml) into a scratch directory, so a test can
# never pass against a stale copy of the policy.
#
# Needs only the `opa` binary (pinned to the version in the Makefile's OPA_IMG);
# no cluster.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${HERE}/../manifests/opa/30-opa-config.yaml"
PINNED_OPA="1.18.2"

if ! command -v opa >/dev/null 2>&1; then
  echo "!! opa is not installed; need v${PINNED_OPA}" >&2
  exit 1
fi
# Captured first: `opa version | grep -q` can kill opa with SIGPIPE and fail
# the pipeline under pipefail.
OPA_VERSION="$(opa version)"
if ! grep -q "^Version: ${PINNED_OPA}\$" <<<"${OPA_VERSION}"; then
  echo "!! opa version is not the pinned ${PINNED_OPA}:" >&2
  echo "${OPA_VERSION}" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# The block scalar under `resource.rego: |` is indented four spaces; it ends at
# the first non-blank line indented less than that.
awk '
  /^  resource\.rego: \|[[:space:]]*$/ { inblock = 1; next }
  inblock && /^[^[:space:]]/ { exit }
  inblock && /^ {0,3}[^[:space:]]/ { exit }
  inblock { sub(/^    /, ""); print }
' "${CONFIG}" >"${WORK}/resource.rego"

if ! grep -q '^package nhi\.resource$' "${WORK}/resource.rego"; then
  echo "!! could not extract resource.rego from ${CONFIG}" >&2
  exit 1
fi

cp "${HERE}"/*_test.rego "${WORK}/"
opa test --verbose "${WORK}"
