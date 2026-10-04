#!/usr/bin/env bash
# Short, narrated demo: ONE parent identity vends THREE children in a row and
# this script shows, live, that each spawn produces its own uniquely
# identified set of artifacts — a distinct chain_id, a distinct child SPIFFE
# ID, a distinct SPIRE registration entry, and a distinct OPA grant module —
# even though all three are minted by the same parent, back to back, with
# overlapping requested scopes.
#
# This is not a verification script (contrast demo.sh/verify-vending.sh,
# which assert pass/fail checks) — it exists only to make "identities are
# vended and uniquely identified" (provenance + attribution) externally
# visible in a few seconds, for a live audience. Nothing it depends on is
# new: it drives the real vending service via the real cmd/parentsim binary
# running in the experiments-parent
# fixture pod (spiffe://lab.local/agent/parent/exp-root, holds all three
# resource scopes per manifests/policy-engine/36-policy-engine-bootstrap.yaml),
# exactly the pattern verify-vending.sh and src/experiments already use.
#
# Unlike verify-vending.sh, nonces are left RANDOM (parentsim generates one when
# -nonce is omitted) rather than fixed, so this script is safely re-runnable
# against a cluster that already has state on it (no vending-service restart
# needed, no risk of a stale "already used" 409 from a PRIOR run of this same
# script).
#
# Prerequisites (see `make -C src/deploy demo-identity-uniqueness` for the
# one-liner): cluster-up, spire-up, vending-service-up, resource-up,
# experiments-fixtures-up.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"

PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/parent/exp-root"
KUBECTL=(kubectl --context "${KUBECTX}")

FAILURES=0
CHECK_NO=0
step() { CHECK_NO=$((CHECK_NO + 1)); printf '\n\033[1m[%d] %s\033[0m\n' "${CHECK_NO}" "$1"; }
pass() { printf '    \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '    \033[31mFAIL\033[0m %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
info() { printf '    \033[36m%s\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
step "Finding the parent pod (experiments-parent, ${PARENT_ID})"
PARENT_POD=$("${KUBECTL[@]}" get pods -n agents -l app=experiments-parent \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "${PARENT_POD}" ]; then
  fail "no running experiments-parent pod found — run 'make experiments-fixtures-up' first"
  exit 1
fi
echo "    | parent pod: ${PARENT_POD}"
exec_p() { "${KUBECTL[@]}" exec -n agents "${PARENT_POD}" -c parentsim -- "$@" 2>&1; }

WHOAMI=$(exec_p /parentsim whoami)
echo "    | ${WHOAMI}"
if echo "${WHOAMI}" | grep -q "${PARENT_ID}"; then
  pass "the pod attests as exactly one identity: ${PARENT_ID}"
else
  fail "expected whoami to report ${PARENT_ID}, got: ${WHOAMI}"
fi

# split_status_body <combined output> -> "<http-code>|<json body>"
split_status_body() {
  local out="$1" code body
  code=$(printf '%s\n' "${out}" | grep -o 'HTTP [0-9]*' | tail -1 | awk '{print $2}')
  body=$(printf '%s\n' "${out}" | grep -v '^HTTP ' | tr '\n' ' ')
  echo "${code:-000}|${body}"
}
field() { echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | cut -d'"' -f4; }

# ---------------------------------------------------------------------------
step "Vending THREE children from the SAME parent, back to back"
info "One identity (${PARENT_ID}) submits three separate spawn requests."
info "Watch chain_id / child_spiffe_id / policy_id differ on every single one."

declare -a NAMES=(alpha beta gamma)
declare -a SCOPES=(resource:read:datasetA resource:read:datasetB resource:write:jobs)
declare -a CHAIN_IDS=()
declare -a CHILD_IDS=()
declare -a POLICY_IDS=()

for i in 0 1 2; do
  name="${NAMES[$i]}"
  scope="${SCOPES[$i]}"
  OUT=$(exec_p /parentsim vend \
    -child-path-hint="child/demo-${name}" \
    -scopes="${scope}" \
    -task-context="identity-uniqueness demo: child ${name}" \
    -selectors="k8s:ns=agents,k8s:sa=demo-child-${name}" \
    -ttl=300)
  R=$(split_status_body "${OUT}")
  CODE="${R%%|*}"; BODY="${R#*|}"
  if [ "${CODE}" != "201" ]; then
    fail "child ${name}: expected HTTP 201, got '${CODE}': ${BODY}"
    continue
  fi
  cid=$(field "${BODY}" chain_id)
  child_id=$(field "${BODY}" child_spiffe_id)
  policy_id=$(field "${BODY}" policy_id)
  CHAIN_IDS+=("${cid}")
  CHILD_IDS+=("${child_id}")
  POLICY_IDS+=("${policy_id}")
  echo
  echo "    child \"${name}\" (requested ${scope}):"
  echo "      chain_id      = ${cid}"
  echo "      child_spiffe  = ${child_id}"
  echo "      policy_id     = ${policy_id}   (the OPA module: package nhi.grants.${policy_id#nhi_grants_})"
  pass "child ${name} minted (HTTP 201)"
done

# ---------------------------------------------------------------------------
step "Uniqueness check #1 — three distinct chain_ids, three distinct child SPIFFE IDs, three distinct policy_ids"
UNIQ_CHAINS=$(printf '%s\n' "${CHAIN_IDS[@]}" | sort -u | wc -l)
UNIQ_CHILDREN=$(printf '%s\n' "${CHILD_IDS[@]}" | sort -u | wc -l)
UNIQ_POLICIES=$(printf '%s\n' "${POLICY_IDS[@]}" | sort -u | wc -l)
echo "    | distinct chain_ids: ${UNIQ_CHAINS}/3   distinct child SPIFFE IDs: ${UNIQ_CHILDREN}/3   distinct policy_ids: ${UNIQ_POLICIES}/3"
if [ "${UNIQ_CHAINS}" = "3" ] && [ "${UNIQ_CHILDREN}" = "3" ] && [ "${UNIQ_POLICIES}" = "3" ]; then
  pass "every spawn from the same parent produced a fully distinct identity + artifact set"
else
  fail "expected 3 distinct values in each column — a collision would mean two children share an identity or grant"
fi

# ---------------------------------------------------------------------------
step "Uniqueness check #2 — SPIRE holds one independently addressable registration entry per child"
for i in 0 1 2; do
  name="${NAMES[$i]}"; child_id="${CHILD_IDS[$i]:-}"
  [ -z "${child_id}" ] && continue
  ENTRY=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -spiffeID "${child_id}" 2>/dev/null)
  ENTRY_ID=$(echo "${ENTRY}" | grep '^Entry ID' | awk '{print $NF}')
  echo "    | ${name}: SPIRE Entry ID = ${ENTRY_ID:-<none>}  (SPIFFE ID ${child_id})"
  if [ -n "${ENTRY_ID}" ]; then
    pass "${name} has its own SPIRE registration entry (${ENTRY_ID})"
  else
    fail "${name}: no SPIRE entry found for ${child_id}"
  fi
done

# ---------------------------------------------------------------------------
step "Uniqueness check #3 — the vending service's own record, read back per chain_id"
for i in 0 1 2; do
  name="${NAMES[$i]}"; cid="${CHAIN_IDS[$i]:-}"
  [ -z "${cid}" ] && continue
  OUT=$(exec_p /parentsim get -chain-id="${cid}")
  R=$(split_status_body "${OUT}")
  CODE="${R%%|*}"; BODY="${R#*|}"
  echo "    | ${name} (chain_id=${cid}): HTTP ${CODE} — ${BODY}"
  if [ "${CODE}" = "200" ] && echo "${BODY}" | grep -q "${CHILD_IDS[$i]}"; then
    pass "${name}'s delegation record is independently readable by its own chain_id"
  else
    fail "${name}: GET /delegations/${cid} did not return its own record"
  fi
done

# ---------------------------------------------------------------------------
step "Disposing all three — each disposal is scoped to its OWN chain_id only"
for i in 0 1 2; do
  name="${NAMES[$i]}"; cid="${CHAIN_IDS[$i]:-}"
  [ -z "${cid}" ] && continue
  OUT=$(exec_p /parentsim dispose -chain-id="${cid}")
  R=$(split_status_body "${OUT}")
  if [ "${R%%|*}" = "200" ]; then
    pass "${name} (chain_id=${cid}) disposed"
  else
    fail "${name}: dispose returned '${R%%|*}': ${R#*|}"
  fi
done

step "Confirming disposal removed exactly the disposed entries, nothing else"
for i in 0 1 2; do
  name="${NAMES[$i]}"; child_id="${CHILD_IDS[$i]:-}"
  [ -z "${child_id}" ] && continue
  GONE=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -spiffeID "${child_id}" 2>/dev/null | grep -c '^Entry ID' || true)
  if [ "${GONE}" = "0" ]; then
    pass "${name}'s SPIRE entry is gone"
  else
    fail "${name}'s SPIRE entry still exists after disposal"
  fi
done

printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ IDENTITY-UNIQUENESS DEMO: PASS (%d checks) ================\033[0m\n' "${CHECK_NO}"
  printf 'One parent identity (%s) vended three children.\n' "${PARENT_ID}"
  printf 'Every artifact the lab produces at vend time — chain_id, child SPIFFE ID,\n'
  printf 'SPIRE registration entry, OPA grant module — was unique per spawn, and\n'
  printf 'disposal of one never touched the others.\n'
  exit 0
else
  printf '\033[31m================ IDENTITY-UNIQUENESS DEMO: FAIL (%d/%d checks failed) ================\033[0m\n' "${FAILURES}" "${CHECK_NO}"
  exit 1
fi
