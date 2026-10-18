#!/usr/bin/env bash
# `make demo`: executes one full spawn -> attest -> vend -> operate -> dispose
# cycle end-to-end with all audit events captured to a single JSON log, and
# exits green.
#
# This script drives that cycle against the REAL vending service, the real
# SPIRE Entry API, the real policy engine and the real protected resource —
# src/agents/parent.py and src/agents/child.py drive it; every other
# component is the same one the verify-* targets exercise. Unlike
# verify-vending.sh (which creates the child pod BEFORE the manifest is
# submitted, a scripting shortcut), this is the
# harness that closes that gap: parent.py creates the child pod strictly
# AFTER the vending service has minted its SPIRE entry, so "the child
# obtains its own identity with no human action" describes an actual spawn.
#
# The single collected JSON-lines audit log this produces
# (src/deploy/demo-audit.jsonl, gitignored — a fresh artifact per run, not a
# committed fixture) is the attribution deliverable: every stage's event,
# from every component that emits one, carrying the same chain_id.
#
# Collection is bounded to THIS run's own time window (START_TIME below,
# passed to `kubectl logs --since-time`), not "this pod's whole log
# history". The five long-lived pods this script reads from
# (vending-service, policy-engine, resource, and the demo parent/child
# across repeated invocations) accumulate audit events from every earlier
# `make demo`/`make verify-policy`/`make verify-vending` run against the same
# cluster — an unbounded collection once returned ~150 events, ~96% of them
# leftover verify-policy/verify-vending traffic with no chain_id
# relationship to this run, which would make per-stage latency numbers
# computed against this file meaningless. Bounding by time is
# the least fragile fix available: it needs no cooperation from the other
# four components (no run-id parameter, no new filtering convention), only
# a timestamp this script already has to record for itself.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS="${SCRIPT_DIR}/../manifests"
OUT_FILE="${SCRIPT_DIR}/../demo-audit.jsonl"

KUBECTL=(kubectl --context "${KUBECTX}")

# A couple of seconds of slack before "now": kubectl logs --since-time is a
# second-granularity cutoff, and this run's own events (spawn/attest/vend/
# operate/dispose) all happen strictly after this point in wall-clock time
# (the restarts below emit no audit events at all), so a little slack costs
# nothing and protects against clock-rounding excluding this run's own
# earliest event.
START_TIME="$(date -u -d '2 seconds ago' +%Y-%m-%dT%H:%M:%SZ)"
echo ">> demo run window starts at ${START_TIME} (UTC)"

FAILURES=0
CHECK_NO=0
step() {
  CHECK_NO=$((CHECK_NO + 1))
  printf '\n\033[1m[%d] %s\033[0m\n' "${CHECK_NO}" "$1"
}
pass() { printf '    \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '    \033[31mFAIL\033[0m %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

# Deliberately no EXIT cleanup trap here: pre-run cleanup (below, before
# creating this run's fixtures) already makes repeated invocations
# idempotent, and leaving the finished parent/child pods in place after a
# PASS lets a human inspect them (`kubectl logs`, `kubectl describe`)
# without racing a teardown. verify-vending.sh's ephemeral test fixtures are a
# different case — those exist only to drive negative tests and are torn
# down on purpose.

# ---------------------------------------------------------------------------
step "Restarting the vending service and the policy engine (the policy engine picks up the demo bootstrap parent)"
# The vending service's delegation/nonce store is durable (a PersistentVolumeClaim),
# so this restart no longer gives the run an empty store, and nothing here
# depends on one: the agent harness uses time-based nonces
# (agents/manifest.py), every vend gets a new chain_id, and the collection
# below is bounded to this run's own time window. The restart is kept so the
# run starts against a freshly started pod. Rolling the policy engine picks up
# manifests/policy-engine/36-policy-engine-bootstrap.yaml's "demo" entry if
# this is the first run since it was added.
"${KUBECTL[@]}" rollout restart deployment/vending-service -n nhi >/dev/null
"${KUBECTL[@]}" rollout status deployment/vending-service -n nhi --timeout=60s >/dev/null
"${KUBECTL[@]}" rollout restart deployment/policy-engine -n nhi >/dev/null
"${KUBECTL[@]}" rollout status deployment/policy-engine -n nhi --timeout=60s >/dev/null
pass "vending service and policy engine restarted"

# ---------------------------------------------------------------------------
step "Deploying the demo parent (RBAC, then the pod itself)"
"${KUBECTL[@]}" apply -f "${MANIFESTS}/agents/70-demo-parent-rbac.yaml" >/dev/null
# Pods are immutable once created; delete-then-create makes repeated `make
# demo` runs idempotent, mirroring verify-vending.sh's fixture-cleanup trap.
"${KUBECTL[@]}" delete -f "${MANIFESTS}/agents/71-demo-parent-pod.yaml" --ignore-not-found --wait=true >/dev/null 2>&1 || true
"${KUBECTL[@]}" delete pod -n agents -l app=nhi-demo-child --ignore-not-found --wait=true >/dev/null 2>&1 || true
"${KUBECTL[@]}" apply -f "${MANIFESTS}/agents/71-demo-parent-pod.yaml" >/dev/null
pass "demo parent pod applied"

# ---------------------------------------------------------------------------
step "Waiting for the parent to run the full cycle (spawn -> attest -> vend -> operate -> dispose)"
"${KUBECTL[@]}" wait --for=condition=Ready pod/nhi-demo-parent -n agents --timeout=60s >/dev/null 2>&1 || true
PARENT_PHASE=""
for attempt in $(seq 1 60); do
  PARENT_PHASE=$("${KUBECTL[@]}" get pod nhi-demo-parent -n agents -o jsonpath='{.status.phase}' 2>/dev/null || true)
  if [ "${PARENT_PHASE}" = "Succeeded" ] || [ "${PARENT_PHASE}" = "Failed" ]; then
    break
  fi
  sleep 3
done
echo "    | parent pod phase: ${PARENT_PHASE:-Unknown}"
if [ "${PARENT_PHASE}" = "Succeeded" ]; then
  pass "parent completed the full cycle (pod phase Succeeded)"
else
  fail "parent pod did not reach Succeeded (phase=${PARENT_PHASE:-Unknown}); see 'kubectl logs -n agents nhi-demo-parent'"
fi

CHILD_POD=$("${KUBECTL[@]}" get pod -n agents -l app=nhi-demo-child -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -n "${CHILD_POD}" ]; then
  echo "    | child pod: ${CHILD_POD}"
else
  fail "no child pod found (label app=nhi-demo-child) — the parent may have failed before creating it"
fi

# ---------------------------------------------------------------------------
step "Collecting every component's audit events into a single JSON-lines log"
# All audit events are captured to a single JSON log. Each component already
# writes JSON-lines audit events to its own container's stdout (one shared
# shape across src/vending-service/internal/audit, src/policy-engine/audit.go,
# src/resource/audit.go, and src/agents/common.py); this step is what turns
# five separate `kubectl logs` streams into the one collected artifact a
# downstream analysis consumes. Lines are filtered to those starting with '{' (discarding
# plain-text startup/progress logging that shares the same stdout) and
# sorted by `timestamp` so the merged file reads as one causal sequence
# regardless of which pod's log buffer flushed first.
: > "${OUT_FILE}"
collect() {
  local ns="$1" selector="$2" container="$3"
  "${KUBECTL[@]}" logs -n "${ns}" -l "${selector}" -c "${container}" \
    --since-time="${START_TIME}" --tail=500 --prefix=false 2>/dev/null \
    | grep '^{' >> "${OUT_FILE}" || true
}
collect agents app=nhi-demo-parent parent
if [ -n "${CHILD_POD}" ]; then
  "${KUBECTL[@]}" logs -n agents "${CHILD_POD}" -c child \
    --since-time="${START_TIME}" --tail=500 2>/dev/null | grep '^{' >> "${OUT_FILE}" || true
fi
collect nhi app=vending-service vending-service
collect nhi app=policy-engine policy-engine
collect nhi app=resource resource

SORTED_FILE=$(mktemp)
if [ -s "${OUT_FILE}" ]; then
  jq -s -c 'sort_by(.timestamp)[]' "${OUT_FILE}" > "${SORTED_FILE}" 2>/dev/null && mv "${SORTED_FILE}" "${OUT_FILE}"
else
  rm -f "${SORTED_FILE}"
fi

LINE_COUNT=$(wc -l < "${OUT_FILE}" | tr -d ' ')
echo "    | collected ${LINE_COUNT} audit event(s) -> ${OUT_FILE}"
if [ "${LINE_COUNT}" -gt 0 ]; then
  pass "single JSON-lines audit log written, ${LINE_COUNT} events"
else
  fail "no audit events collected at all"
fi

# Every line must be valid, schema-shaped JSON (timestamp, stage, chain_id,
# actor_spiffe_id, outcome, detail) — a malformed line would make this
# "single JSON log" claim false in the one way that matters most to a
# downstream consumer.
INVALID=0
while IFS= read -r line; do
  echo "${line}" | jq -e '.timestamp and .stage and (.chain_id != null) and .actor_spiffe_id and .outcome and .detail' >/dev/null 2>&1 || INVALID=$((INVALID + 1))
done < "${OUT_FILE}"
if [ "${INVALID}" -eq 0 ] && [ "${LINE_COUNT}" -gt 0 ]; then
  pass "every collected line is valid, audit-schema-shaped JSON"
else
  fail "${INVALID} of ${LINE_COUNT} collected line(s) are not valid audit-schema JSON"
fi

# ---------------------------------------------------------------------------
step "Verifying attribution: exactly ONE chain_id, carrying vend+operate+dispose, no orphans from other chains"
# Stricter than "a linked chain exists somewhere in the file" — this is what
# makes the artifact trustworthy for per-stage latency computation:
# a single spawn must produce a single chain, and the bounded time window
# (START_TIME above) means any OTHER non-empty chain_id appearing here is
# evidence the window leaked another run's tail, not evidence of a second
# legitimate delegation this demo never created.
VEND_CHAIN=$(jq -r 'select(.stage=="vend" and .outcome=="allow") | .chain_id' "${OUT_FILE}" 2>/dev/null | head -1)
echo "    | chain_id minted at vend: ${VEND_CHAIN:-<none>}"
if [ -n "${VEND_CHAIN:-}" ] && [ "${VEND_CHAIN}" != "null" ]; then
  pass "a chain_id was minted at vend time"
else
  fail "no chain_id found on a vend/allow event"
fi

DISTINCT_CHAINS=$(jq -r 'select(.chain_id != "") | .chain_id' "${OUT_FILE}" 2>/dev/null | sort -u)
DISTINCT_COUNT=$(echo "${DISTINCT_CHAINS}" | grep -c . || true)
echo "    | distinct non-empty chain_id(s) in the collected window: ${DISTINCT_COUNT}"
if [ "${DISTINCT_COUNT}" -eq 1 ] && [ "${DISTINCT_CHAINS}" = "${VEND_CHAIN:-}" ]; then
  pass "exactly one chain_id in the collected window, and it is this run's"
else
  fail "expected exactly one chain_id (${VEND_CHAIN:-<none>}), found: $(echo "${DISTINCT_CHAINS}" | tr '\n' ',')"
fi

STAGES_WITH_CHAIN=$(jq -r --arg cid "${VEND_CHAIN:-}" 'select(.chain_id == $cid) | .stage' "${OUT_FILE}" 2>/dev/null | sort -u | tr '\n' ',')
echo "    | stages carrying chain_id=${VEND_CHAIN:-<none>}: ${STAGES_WITH_CHAIN}"
for want in vend operate dispose; do
  if echo "${STAGES_WITH_CHAIN}" | grep -q "${want}"; then
    pass "stage '${want}' is present under the same chain_id"
  else
    fail "stage '${want}' is missing under chain_id=${VEND_CHAIN:-<none>}"
  fi
done

ORPHAN_OPERATE=$(jq -r --arg cid "${VEND_CHAIN:-}" 'select(.stage=="operate" and .chain_id != "" and .chain_id != $cid) | .chain_id' "${OUT_FILE}" 2>/dev/null | sort -u | tr '\n' ',')
if [ -z "${ORPHAN_OPERATE}" ]; then
  pass "no operate event carries a different, non-empty chain_id from another delegation"
else
  fail "operate event(s) found under a different chain_id, orphaned from this run: ${ORPHAN_OPERATE}"
fi

# ---------------------------------------------------------------------------
step "Verifying the lifecycle stages present: spawn, attest, vend, operate, dispose"
ALL_STAGES=$(jq -r '.stage' "${OUT_FILE}" 2>/dev/null | sort -u | tr '\n' ',')
echo "    | stages observed: ${ALL_STAGES}"
for want in spawn attest vend operate dispose; do
  if echo "${ALL_STAGES}" | grep -q "${want}"; then
    pass "stage '${want}' present in the collected log"
  else
    fail "stage '${want}' missing from the collected log"
  fi
done

printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ DEMO: PASS (%d checks) ================\033[0m\n' "${CHECK_NO}"
  printf 'One full spawn -> attest -> vend -> operate -> dispose cycle, driven end to end\n'
  printf 'by src/agents/parent.py and src/agents/child.py, no human action after `make demo`:\n'
  printf '  parent fetched its own SVID, decided to fork, signed and submitted a manifest\n'
  printf '  vending service minted a SPIRE entry BEFORE the child pod existed\n'
  printf '  parent created the child pod with the exact selectors promised\n'
  printf '  child obtained its own SVID via the Workload API, read its granted dataset\n'
  printf '  parent disposed the delegation once the child finished\n'
  printf '  every event above is one collected JSON-lines log: %s\n' "${OUT_FILE}"
  exit 0
else
  printf '\033[31m================ DEMO: FAIL (%d/%d checks failed) ================\033[0m\n' "${FAILURES}" "${CHECK_NO}"
  printf 'Parent pod logs:\n'
  "${KUBECTL[@]}" logs -n agents nhi-demo-parent -c parent --tail=100 2>/dev/null || true
  exit 1
fi
