#!/usr/bin/env bash
# install.sh: check the host tools, state what will be downloaded and
# installed, bring every lab component up on a local kind cluster, and run the
# smoke test. Run ./install.sh --help for the full description.
#
# The script drives the existing `make` targets and holds no recipe logic of
# its own. Every cluster or image action below is a make target that also works
# on its own; this file adds the host check, the statement of what is
# installed, the order of the bring-up and the user-facing text.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
REPO_ROOT="$(pwd)"

# Tested versions. They mirror the "Pinned versions" table in
# src/deploy/README.md. A different version is a warning, not an error: the
# pins record what was tested, not what is required. Docker below 25 is an
# error, because image side-loading needs `docker save --platform`.
PIN_DOCKER="29.6.2"
MIN_DOCKER_MAJOR=25
PIN_KIND="v0.32.0"
PIN_KUBECTL="v1.36.2"
PIN_GO="1.26.5"
PIN_PYTHON="3.14.6"
PIN_OPA="1.18.2"
MIN_MAKE="4.0"
MIN_BASH="5.0"

KIND_CLUSTER="${KIND_CLUSTER:-nhi-lab}"
export KIND_CLUSTER
KUBECTX="kind-${KIND_CLUSTER}"

MODE="install"
ASSUME_YES=0

usage() {
  cat <<EOF
Usage: ./install.sh [--check-only] [--yes] [--help]

Brings up the whole lab on a local kind cluster: SPIRE, the authenticated
policy plane (OPA and the policy engine), the vending service, the protected
resource, the Python agent harness, the OpenCode parent and the experiment
fixtures. It ends with the 'make verify' smoke test and a list of next steps.

Modes:
  (no option)    Check the host, state what will be installed, ask for
                 confirmation, bring everything up, run the smoke test.
  --check-only   Check the host tools and platform only. Changes nothing.
  --yes, -y      Do not ask for confirmation.
  --help, -h     Show this text.

Environment:
  KIND_CLUSTER        Name of the kind cluster to create or reuse
                      (default: nhi-lab). Pass the same value to later make
                      targets: make verify-vending KIND_CLUSTER=<name>.
  ANTHROPIC_KEY_FILE  Optional. Path to a file holding one
                      ANTHROPIC_API_KEY=<key> line, for the OpenCode parent's
                      LLM. The script passes the path to make and never reads
                      the file. Without it the OpenCode parent runs with no
                      LLM; 'make verify-present' needs none.
  Both work as a prefix in bash, zsh and fish 3.1 or later, for example:
      KIND_CLUSTER=lab2 ./install.sh
      ANTHROPIC_KEY_FILE=\$HOME/path/to/key-file ./install.sh

Host check (check-only: this script never installs a host tool and never uses
sudo):
  Linux on amd64 (anything else stops the script as unsupported)
  docker ${PIN_DOCKER} (at least ${MIN_DOCKER_MAJOR}; daemon reachable without sudo)
  kind ${PIN_KIND}, kubectl ${PIN_KUBECTL}, go ${PIN_GO}, python3 ${PIN_PYTHON},
  opa ${PIN_OPA}, uv, jq, GNU make ${MIN_MAKE} or later, bash ${MIN_BASH} or later
  A missing tool is an error. A version other than the tested one is a warning.

$(print_statement)

Re-running it on an installed cluster is safe: the cluster is reused, the lab
images are rebuilt from the working tree and the components restarted, and the
data volumes are kept. 'make clean' deletes the cluster.

Exit status: 0 on success; 1 if the host check fails, a step fails, or the
confirmation is declined; 2 on a usage error.
EOF
}

# What the bring-up downloads and installs, and where. The text follows the
# Makefile (load-images, build_and_load_image, the -up targets) and the
# Dockerfiles; keep it in step with them.
print_statement() {
  local cluster_line clusters
  # Captured first: `kind get clusters | grep -q` can end kind with SIGPIPE,
  # and pipefail would then report no match.
  clusters="$(kind get clusters 2>/dev/null || true)"
  if grep -qx "${KIND_CLUSTER}" <<<"${clusters}"; then
    cluster_line="  - Reuses the existing kind cluster '${KIND_CLUSTER}'. Its lab components are
    rebuilt and restarted; its data volumes are kept."
  else
    cluster_line="  - Creates the kind cluster '${KIND_CLUSTER}': two Docker containers (a
    control-plane and a worker node) running Kubernetes v1.36.1."
  fi
  cat <<EOF
What this downloads and installs, and where:
${cluster_line}
  - kind adds the kube context '${KUBECTX}' to your kubeconfig
    (\$KUBECONFIG, or ~/.kube/config) and makes it the current context.
    Every make target names this context explicitly. 'make clean' removes it.
  - Into the local Docker image store, pulled if not already present:
      kindest/node:v1.36.1 (pinned by digest)
      ghcr.io/spiffe/spire-server:1.15.2, ghcr.io/spiffe/spire-agent:1.15.2,
      openpolicyagent/opa:1.18.2, ghcr.io/spiffe/spiffe-helper:0.11.0,
      curlimages/curl:8.18.0
    and the build base images golang:1.26,
    gcr.io/distroless/static-debian12:nonroot, python:3.13-slim and node:24-slim.
  - Into the local Docker image store, built from this repository:
      nhi-lab/resource:dev, nhi-lab/policy-engine:dev,
      nhi-lab/vending-service:dev, nhi-lab/parentsim:dev, nhi-lab/agents:dev,
      nhi-lab/opencode-parent:dev
    These builds download, inside the build containers only: Go modules
    ('go mod download'), the agent harness's Python packages ('pip install -r
    src/agents/requirements.txt'), the OpenCode tool's npm packages ('npm ci'
    from its lockfile), ca-certificates and curl from Debian's package
    archive (inside the OpenCode image build), and the OpenCode
    1.19.3 binary from its GitHub release, checked against a pinned SHA-256.
  - Every image above is also copied into both kind node containers.
  - Creates src/experiments/.venv with uv, using a Python already on this
    machine (uv is told never to download one). The experiment suites use only
    the standard library, so no package is installed into it.
  - Nothing is installed system-wide, no host tool is installed, and sudo is
    never used. Expect about 5 GB of images in Docker's store, and about 4 GB
    more inside the two kind node containers (measured 2026-11-07).
EOF
}

die_usage() { echo "install.sh: $1" >&2; echo "Run ./install.sh --help for usage." >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --check-only) MODE="check" ;;
    --yes|-y)     ASSUME_YES=1 ;;
    --help|-h)    usage; exit 0 ;;
    *)            die_usage "unknown option '$1'" ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Host check
# ---------------------------------------------------------------------------

ERRORS=()
WARNINGS=()

# ver_ge A B: true when version A >= version B.
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

row() { printf '  %-9s %-12s %-14s %s\n' "$1" "$2" "$3" "$4"; }

# check_exact <tool> <found> <tested>
check_exact() {
  local tool="$1" found="$2" tested="$3"
  if [ -z "${found}" ]; then
    row "${tool}" "missing" "${tested}" "ERROR"
    ERRORS+=("${tool} not found on PATH; the tested version is ${tested}")
  elif [ "${found}" = "${tested}" ]; then
    row "${tool}" "${found}" "${tested}" "ok"
  else
    row "${tool}" "${found}" "${tested}" "differs (warning)"
    WARNINGS+=("${tool} ${found} differs from the tested ${tested}")
  fi
}

# check_min <tool> <found> <minimum>: below the minimum is a warning.
check_min() {
  local tool="$1" found="$2" min="$3"
  if [ -z "${found}" ]; then
    row "${tool}" "missing" ">= ${min}" "ERROR"
    ERRORS+=("${tool} not found on PATH; version ${min} or later is needed")
  elif ver_ge "${found}" "${min}"; then
    row "${tool}" "${found}" ">= ${min}" "ok"
  else
    row "${tool}" "${found}" ">= ${min}" "older (warning)"
    WARNINGS+=("${tool} ${found} is older than the tested ${min}")
  fi
}

# check_any <tool> <found>: any version.
check_any() {
  local tool="$1" found="$2"
  if [ -z "${found}" ]; then
    row "${tool}" "missing" "any" "ERROR"
    ERRORS+=("${tool} not found on PATH")
  else
    row "${tool}" "${found}" "any" "ok"
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

check_host() {
  echo "Host check (nothing is installed or changed)"
  echo
  row "TOOL" "FOUND" "TESTED" "STATUS"

  local os arch
  os="$(uname -s)"; arch="$(uname -m)"
  if [ "${os}" = "Linux" ] && [ "${arch}" = "x86_64" ]; then
    row "platform" "${os}/${arch}" "Linux/x86_64" "ok"
  else
    row "platform" "${os}/${arch}" "Linux/x86_64" "UNSUPPORTED"
    ERRORS+=("unsupported platform ${os}/${arch}: the lab supports Linux on amd64 only")
  fi

  # Docker: the client must exist, the daemon must answer without sudo, and the
  # server must be at least version 25 on amd64.
  if ! have docker; then
    row "docker" "missing" "${PIN_DOCKER}" "ERROR"
    ERRORS+=("docker not found on PATH; the tested version is ${PIN_DOCKER}")
  else
    local dout dver darch
    if dout="$(docker version --format '{{.Server.Version}} {{.Server.Arch}}' 2>&1)"; then
      dver="${dout%% *}"; darch="${dout##* }"
      if [ "${dver%%.*}" -lt "${MIN_DOCKER_MAJOR}" ] 2>/dev/null; then
        row "docker" "${dver}" "${PIN_DOCKER}" "ERROR"
        ERRORS+=("docker ${dver} is older than ${MIN_DOCKER_MAJOR}; image side-loading needs 'docker save --platform'")
      elif [ "${dver}" = "${PIN_DOCKER}" ]; then
        row "docker" "${dver}" "${PIN_DOCKER}" "ok"
      else
        row "docker" "${dver}" "${PIN_DOCKER}" "differs (warning)"
        WARNINGS+=("docker ${dver} differs from the tested ${PIN_DOCKER}")
      fi
      if [ "${darch}" != "amd64" ]; then
        ERRORS+=("the Docker daemon runs on ${darch}; the lab supports amd64 only")
      fi
    else
      row "docker" "no daemon" "${PIN_DOCKER}" "ERROR"
      if grep -qi 'permission denied' <<<"${dout}"; then
        ERRORS+=("your user cannot reach the Docker daemon. Add it to the 'docker' group and log in again; this script never uses sudo")
      else
        ERRORS+=("the Docker daemon is not reachable. Start it, then re-run")
      fi
    fi
  fi

  local v
  v=""; if have kind; then v="$(kind version 2>/dev/null | awk '{print $2}' || true)"; fi
  check_exact "kind" "${v}" "${PIN_KIND}"

  v=""; if have kubectl; then v="$(kubectl version --client 2>/dev/null | awk '/^Client Version:/{print $3}' || true)"; fi
  check_exact "kubectl" "${v}" "${PIN_KUBECTL}"

  v=""; if have go; then v="$(go env GOVERSION 2>/dev/null || true)"; v="${v#go}"; fi
  check_exact "go" "${v}" "${PIN_GO}"

  v=""; if have python3; then v="$(python3 --version 2>&1 | awk '{print $2}' || true)"; fi
  check_exact "python3" "${v}" "${PIN_PYTHON}"

  # Captured before parsing: `opa version | awk` can end opa with SIGPIPE.
  v=""; if have opa; then local ov; ov="$(opa version 2>/dev/null || true)"; v="$(awk '/^Version:/{print $2}' <<<"${ov}")"; fi
  check_exact "opa" "${v}" "${PIN_OPA}"

  v=""; if have uv; then v="$(uv --version 2>/dev/null | awk '{print $2}' || true)"; fi
  check_any "uv" "${v}"

  v=""; if have jq; then v="$(jq --version 2>/dev/null || true)"; v="${v#jq-}"; fi
  check_any "jq" "${v}"

  v=""
  if have make; then
    local mv; mv="$(make --version 2>/dev/null || true)"; mv="${mv%%$'\n'*}"
    if [[ "${mv}" == "GNU Make "* ]]; then
      v="${mv#GNU Make }"
    else
      row "make" "not GNU" ">= ${MIN_MAKE}" "ERROR"
      ERRORS+=("make is not GNU make; the Makefiles need GNU make ${MIN_MAKE} or later")
      v="-"
    fi
  fi
  if [ "${v}" != "-" ]; then check_min "make" "${v}" "${MIN_MAKE}"; fi

  check_min "bash" "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}" "${MIN_BASH}"

  # CLUSTER_NAME is the logical name hard-coded in the SPIRE ConfigMaps
  # (src/deploy/Makefile). Overriding it breaks attestation silently.
  if [ -n "${CLUSTER_NAME:-}" ] && [ "${CLUSTER_NAME}" != "nhi-lab" ]; then
    ERRORS+=("CLUSTER_NAME=${CLUSTER_NAME} is set. It must stay nhi-lab; set KIND_CLUSTER to name the kind cluster instead")
  fi
  if ! [[ "${KIND_CLUSTER}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    ERRORS+=("KIND_CLUSTER='${KIND_CLUSTER}' is not a valid kind cluster name (lowercase letters, digits and '-')")
  fi

  # Only the path is checked, by the Makefile's own key-file check. The file is
  # never read here.
  if [ -n "${ANTHROPIC_KEY_FILE:-}" ] && have make; then
    if ! make --no-print-directory -s -C src/deploy present-key-check >/dev/null 2>&1; then
      ERRORS+=("ANTHROPIC_KEY_FILE='${ANTHROPIC_KEY_FILE}' is not a readable file")
    fi
  fi

  echo
  local w e
  for w in "${WARNINGS[@]+"${WARNINGS[@]}"}"; do echo "  warning: ${w}"; done
  for e in "${ERRORS[@]+"${ERRORS[@]}"}"; do echo "  error:   ${e}"; done
  if [ ${#WARNINGS[@]} -gt 0 ]; then
    echo "  Warnings do not stop the install. The TESTED column is what the lab was tested with."
  fi
}

check_host

if [ ${#ERRORS[@]} -gt 0 ]; then
  echo
  echo "!! The host check failed (${#ERRORS[@]} error(s)). Nothing was changed."
  exit 1
fi

if [ "${MODE}" = "check" ]; then
  echo
  echo ">> Host check passed. Nothing was changed (--check-only)."
  exit 0
fi

# ---------------------------------------------------------------------------
# Statement and confirmation
# ---------------------------------------------------------------------------

echo
print_statement
if [ -n "${ANTHROPIC_KEY_FILE:-}" ]; then
  echo "  - ANTHROPIC_KEY_FILE is set: make puts the key into the Kubernetes Secret"
  echo "    'opencode-llm' in the cluster, reading the file by path. This script never reads it."
else
  echo "  - ANTHROPIC_KEY_FILE is not set: the OpenCode parent will run without an LLM."
fi
echo

if [ "${ASSUME_YES}" -ne 1 ]; then
  if [ ! -t 0 ]; then
    echo "!! There is no terminal to confirm on. Re-run with --yes to proceed. Nothing was changed."
    exit 1
  fi
  read -r -p "Proceed? [y/N] " answer || answer=""
  case "${answer}" in
    y|Y|yes|YES|Yes) ;;
    *) echo ">> Declined. Nothing was changed."; exit 1 ;;
  esac
fi

# ---------------------------------------------------------------------------
# Bring-up
# ---------------------------------------------------------------------------

TOTAL_STEPS=6
STEP=0
START_ALL=${SECONDS}

banner() {
  STEP=$((STEP + 1))
  STEP_START=${SECONDS}
  printf '\n\033[1m==== [%d/%d] %s ====\033[0m\n' "${STEP}" "${TOTAL_STEPS}" "$1"
}

step_done() {
  printf '\033[1m==== [%d/%d] done in %ds ====\033[0m\n' "${STEP}" "${TOTAL_STEPS}" $((SECONDS - STEP_START))
}

failed() {
  echo
  echo "!! Step ${STEP}/${TOTAL_STEPS} failed: $1"
  echo "!! The cluster '${KIND_CLUSTER}' is left as it is for inspection ('make status KIND_CLUSTER=${KIND_CLUSTER}')."
  echo "!! Fix the cause and re-run ./install.sh; a re-run is safe. 'make clean KIND_CLUSTER=${KIND_CLUSTER}' deletes the cluster."
  exit 1
}

mk() {
  echo ">> make $*"
  make --no-print-directory -C "${REPO_ROOT}" "$@" || failed "make $*"
}

banner "Kind cluster '${KIND_CLUSTER}' and pinned images"
mk cluster-up
step_done

banner "SPIRE, the authenticated policy plane and the static entries"
mk spire-up
step_done

banner "Policy engine, vending service and protected resource"
mk policy-engine-up
mk vending-service-up
mk resource-up
step_done

banner "Agent harness and OpenCode images, and the OpenCode parent pod"
# present-up builds the agents and OpenCode images as its own prerequisites and
# passes ANTHROPIC_KEY_FILE, if set, through to a Secret by path.
mk present-up
step_done

banner "Experiment fixtures and the experiments' Python environment"
mk experiments-fixtures-up
echo ">> uv sync --locked --no-python-downloads (in src/experiments)"
(cd "${REPO_ROOT}/src/experiments" && uv sync --locked --no-python-downloads) \
  || failed "uv sync in src/experiments"
step_done

banner "Smoke test: make verify"
mk verify
step_done

# ---------------------------------------------------------------------------
# Next steps
# ---------------------------------------------------------------------------

SUFFIX=""
if [ "${KIND_CLUSTER}" != "nhi-lab" ]; then SUFFIX=" KIND_CLUSTER=${KIND_CLUSTER}"; fi
ELAPSED=$((SECONDS - START_ALL))

cat <<EOF

>> The lab is up on kind cluster '${KIND_CLUSTER}' (context ${KUBECTX}), in $((ELAPSED / 60))m $((ELAPSED % 60))s.

Next steps (run them one at a time, never with make -j):
  make demo${SUFFIX}
      one spawn -> attest -> vend -> operate -> dispose cycle; audit events in src/deploy/demo-audit.jsonl
  make verify-vending${SUFFIX}
      the full vend lifecycle, plus forged, relayed and replayed requests
  make verify-disposal${SUFFIX}
      cascade revocation, TTL attenuation and creation limits (about 4-5 minutes)
  make verify-present${SUFFIX}
      the OpenCode parent end to end, without an LLM
  make present-shell${SUFFIX}
      talk to the OpenCode parent (needs ANTHROPIC_KEY_FILE)
  make experiments${SUFFIX}
      the negative, multi-hop, functional and performance suites (about 20-30 minutes)
  make help
      every target
  make clean${SUFFIX}
      delete the cluster and its kube context
EOF
