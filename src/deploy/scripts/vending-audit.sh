#!/usr/bin/env bash
# Print the vending service's durable audit trail for `make vending-audit`.
#
#   The vending service appends every audit event, as the same JSON line it
#   writes to stdout, to /var/lib/vending-service/audit.jsonl on the
#   `vending-data` volume. The service image is distroless (no `cat`, no
#   `tar`), so this script starts a short-lived reader pod that mounts that
#   volume READ-ONLY as UID/GID 65532, prints the file, and deletes the pod
#   again, including when something fails (manifests/test/46-vending-audit-reader.yaml).
#
# stdout carries ONLY the file's lines, so the output can be piped to jq or
# redirected to a file; progress and errors go to stderr. verify-persistence.sh
# calls this script to read the trail back, so the two share one mechanism.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${SCRIPT_DIR}/../manifests/test/46-vending-audit-reader.yaml"

NS=nhi
POD=vending-audit-reader
KUBECTL=(kubectl --context "${KUBECTX}")

log() { echo ">> $*" >&2; }

cleanup() {
  "${KUBECTL[@]}" delete pod "${POD}" -n "${NS}" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true
}
trap cleanup EXIT

PVC_PHASE=$("${KUBECTL[@]}" get pvc vending-data -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [ "${PVC_PHASE}" != "Bound" ]; then
  log "PVC ${NS}/vending-data is '${PVC_PHASE:-missing}', not Bound: nothing to read yet. Run 'make vending-service-up' first."
  exit 1
fi

# A pod is immutable, so a leftover from an interrupted run is removed first.
cleanup
"${KUBECTL[@]}" apply -f "${MANIFEST}" >/dev/null || { log "could not create ${POD}"; exit 1; }

PHASE=""
for _ in $(seq 1 90); do
  PHASE=$("${KUBECTL[@]}" get pod "${POD}" -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  case "${PHASE}" in
    Succeeded|Failed) break ;;
  esac
  sleep 1
done

case "${PHASE}" in
  Succeeded)
    "${KUBECTL[@]}" logs "${POD}" -n "${NS}" -c reader
    ;;
  Failed)
    log "reader pod failed; its output (a missing audit.jsonl means the vending service has not written one):"
    "${KUBECTL[@]}" logs "${POD}" -n "${NS}" -c reader >&2 || true
    exit 1
    ;;
  *)
    log "reader pod did not finish within 90s (phase '${PHASE:-unknown}'):"
    "${KUBECTL[@]}" describe pod "${POD}" -n "${NS}" 2>&1 | tail -n 20 >&2
    exit 1
    ;;
esac
