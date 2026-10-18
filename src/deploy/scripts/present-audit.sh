#!/usr/bin/env bash
# `make present-audit`: follow the live audit events of the OpenCode parent pod,
# the vending service, the policy engine and the resource as one compact line
# each (time, stage, outcome, chain_id, actor, detail). Run it in a second
# terminal next to `make present-shell`; Ctrl-C stops it.
set -uo pipefail
K=(kubectl --context "${KUBECTX:-kind-${CLUSTER_NAME:-nhi-lab}}")
{
  "${K[@]}" logs -n agents nhi-opencode-parent -c parent -f --since=1s &
  for app in vending-service policy-engine resource; do
    "${K[@]}" logs -n nhi -l "app=${app}" -c "${app}" -f --since=1s &
  done
  wait
} | grep --line-buffered '^{' | jq -rc --unbuffered \
  '[.timestamp[11:23], .stage, .outcome, (.chain_id | if . == "" then "-" else . end),
    (.actor_spiffe_id | sub("^spiffe://[^/]*/"; "")), (.detail | tostring | .[0:90])] | join("  ")'
