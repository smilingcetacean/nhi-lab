#!/usr/bin/env bash
# install.sh: check the host tools, state what will be downloaded and
# installed, bring every lab component up on a local kind cluster, and run the
# smoke test. With --install-tools it first installs the host tools the check
# finds missing, as root, and stops. Run ./install.sh --help for the full
# description.
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
# pins record what was tested, not what is required. Docker below 28 is an
# error, for the client and for the server: image side-loading runs `docker
# save --platform`, which the docker client has from version 28.
PIN_DOCKER="29.6.2"
MIN_DOCKER_MAJOR=28
PIN_KIND="v0.32.0"
PIN_KUBECTL="v1.36.2"
PIN_GO="1.26.5"
PIN_PYTHON="3.14.6"
PIN_OPA="1.18.2"
MIN_MAKE="4.0"
MIN_BASH="5.0"

# --install-tools only. The uv release it downloads (the host check accepts any
# uv). The versions of the other downloads are the PIN_* values above.
PIN_UV="0.13.7"

# SHA-256 of each artifact --install-tools downloads, checked before anything
# is installed. They belong to the URLs in dl_url below. When a PIN_* version
# changes, replace the matching value from its source.
# kind:    https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-linux-amd64.sha256sum
SHA256_KIND="50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54"
# kubectl: https://dl.k8s.io/release/v1.36.2/bin/linux/amd64/kubectl.sha256
SHA256_KUBECTL="1e9045ec32bea85da43de85f0065358529ea7c7a152eca78154fba5b58c27d82"
# go:      https://go.dev/dl/?mode=json&include=all (go1.26.5.linux-amd64.tar.gz)
SHA256_GO="5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
# opa:     https://github.com/open-policy-agent/opa/releases/download/v1.18.2/opa_linux_amd64_static.sha256
SHA256_OPA="9903e5125ac281104f2c4b7371d10cc3b74a98933743fcbfc174f9bf0ab20de8"
# uv:      https://github.com/astral-sh/uv/releases/download/0.13.7/uv-x86_64-unknown-linux-musl.tar.gz.sha256
SHA256_UV="287491da03f2a785c70fa75b13e1f849918c2f2b5415fe84876b8214eeb792f9"

# --install-tools destinations.
PREFIX="/usr/local"
RECORD="${PREFIX}/share/nhi-lab/installed-tools.txt"
PY_DIR="${PREFIX}/share/uv/python"

KIND_CLUSTER="${KIND_CLUSTER:-nhi-lab}"
export KIND_CLUSTER
KUBECTX="kind-${KIND_CLUSTER}"

MODE="install"
INSTALL_TOOLS=0
ASSUME_YES=0

usage() {
  cat <<EOF
Usage: ./install.sh [--check-only | --install-tools] [--yes] [--help]

Brings up the whole lab on a local kind cluster: SPIRE, the authenticated
policy plane (OPA and the policy engine), the vending service, the protected
resource, the Python agent harness, the OpenCode parent and the experiment
fixtures. It ends with the 'make verify' smoke test and a list of next steps.

Modes:
  (no option)    Check the host, state what will be installed, ask for
                 confirmation, bring everything up, run the smoke test.
  --check-only   Check the host tools and platform only. Changes nothing.
  --install-tools
                 Install the host tools the check finds missing, as root, then
                 stop. Run it as: sudo ./install.sh --install-tools
                 (or ./install.sh --install-tools from a root shell). It does
                 not bring the lab up. Cannot be combined with --check-only.
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

Host check (without --install-tools this script never installs a host tool and
never uses sudo):
  Linux on amd64 (anything else stops the script as unsupported)
  docker ${PIN_DOCKER} (client and server at least ${MIN_DOCKER_MAJOR}; daemon reachable without sudo)
  kind ${PIN_KIND}, kubectl ${PIN_KUBECTL}, go ${PIN_GO}, python3 ${PIN_PYTHON},
  opa ${PIN_OPA}, uv, jq, GNU make ${MIN_MAKE} or later, bash ${MIN_BASH} or later
  A missing tool is an error. A version other than the tested one is a warning.

--install-tools (root only; the script never runs sudo itself):
  It installs a tool only when the host check reports it missing. A tool that
  is present at another version stays in use and keeps its warning. A
  destination that already exists, for example /usr/local/go, is never
  overwritten: that tool is reported as an error instead.
  From the distro's packages, with apt-get (Ubuntu), dnf (Fedora) or pacman
  (Arch); any other package manager is refused:
      GNU make, jq, Docker Engine and its buildx plugin
        (apt-get: docker.io docker-buildx; dnf: moby-engine docker-cli
        docker-buildx; pacman: docker docker-buildx)
      curl, ca-certificates, tar and gzip, if a download is needed and they
        are missing
      On Arch, pacman cannot install packages without a full system upgrade,
      so it runs 'pacman -Syu': every installed package is upgraded.
  Debian is not supported: the packages apt supplies there are too old for the
  lab (Debian 13's docker.io is 26.1.5, and the lab needs Docker ${MIN_DOCKER_MAJOR} or later).
  The mode stops at once on Debian and changes nothing.
  Docker ${MIN_DOCKER_MAJOR} or later is needed, for the client and the server. Before it
  changes anything, the mode reads the version of every package it would
  install, and stops if the Docker package is below ${MIN_DOCKER_MAJOR}. The package
  metadata goes into a temporary directory; nothing is installed and nothing
  else is written.
  Tools are looked up on the PATH the script runs with. Under sudo that is
  sudo's PATH, not yours: a tool kept only in your own directories, for
  example ~/.local/bin, counts as missing and is installed again into
  /usr/local/bin. The statement lists every tool before you confirm.
  Downloaded into /usr/local, each checked against a SHA-256 pinned in this
  script before anything is installed (a mismatch refuses that tool and leaves
  none of its files behind):
      $(printf '%-18s' "kind ${PIN_KIND}")/usr/local/bin/kind
      $(printf '%-18s' "kubectl ${PIN_KUBECTL}")/usr/local/bin/kubectl
      $(printf '%-18s' "go ${PIN_GO}")/usr/local/go, with go and gofmt linked into
      $(printf '%-18s' "")/usr/local/bin
      $(printf '%-18s' "opa ${PIN_OPA}")/usr/local/bin/opa (static build)
      $(printf '%-18s' "uv ${PIN_UV}")/usr/local/bin/uv and uvx
      $(printf '%-18s' "python ${PIN_PYTHON}")installed by uv under ${PY_DIR},
      $(printf '%-18s' "")with python3 linked into /usr/local/bin
  Docker: when systemd is running, 'systemctl enable --now docker'. Without
  systemd, as in a container, no daemon is started; the host check then
  reports whether one is reachable, for example through a mounted socket. When
  run through sudo, the invoking user is added to the 'docker' group (created
  if needed); that takes effect at the next login.
  Record: everything it installs is listed in
  ${RECORD}
  (appended on re-runs, no duplicates), so it can be removed by hand. There is
  no uninstall mode.
  Like the default mode it first prints what it will change and asks for
  confirmation unless --yes is given. Afterwards it re-runs the host check,
  prints the next command (./install.sh, without sudo) and stops.

Running the lab from a container: mount the host's Docker socket and share the
host network, because the kind cluster's kubeconfig points at 127.0.0.1. Mount
your clone read-only and copy it inside, so that no root-owned files land in
your clone:
    docker run --rm -it --network host \\
      -v /var/run/docker.sock:/var/run/docker.sock -v "\$PWD":/src:ro \\
      ubuntu:24.04 bash
    cp -r /src /nhi-lab && cd /nhi-lab
Then run ./install.sh --install-tools and then ./install.sh.

$(print_statement)

Re-running it on an installed cluster is safe: the cluster is reused, the lab
images are rebuilt from the working tree and the components restarted, and the
data volumes are kept. 'make clean' deletes the cluster.

Exit status: 0 on success; 1 if the host check fails, a step fails, the
confirmation is declined, or --install-tools is run without root or cannot
install a tool; 2 on a usage error.
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
    --install-tools) INSTALL_TOOLS=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    --help|-h)    usage; exit 0 ;;
    *)            die_usage "unknown option '$1'" ;;
  esac
  shift
done

if [ "${INSTALL_TOOLS}" -eq 1 ]; then
  if [ "${MODE}" = "check" ]; then die_usage "--check-only and --install-tools cannot be combined"; fi
  MODE="tools"
fi

# ---------------------------------------------------------------------------
# Host check
# ---------------------------------------------------------------------------

ERRORS=()
WARNINGS=()
# Tools the host check found missing (not on PATH), by the name in its table.
MISSING=()

# ver_ge A B: true when version A >= version B.
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

row() { printf '  %-9s %-12s %-14s %s\n' "$1" "$2" "$3" "$4"; }

# check_exact <tool> <found> <tested>
check_exact() {
  local tool="$1" found="$2" tested="$3"
  if [ -z "${found}" ]; then
    row "${tool}" "missing" "${tested}" "ERROR"
    ERRORS+=("${tool} not found on PATH; the tested version is ${tested}")
    MISSING+=("${tool}")
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
    MISSING+=("${tool}")
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
    MISSING+=("${tool}")
  else
    row "${tool}" "${found}" "any" "ok"
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# check_host [title]: print the table and fill ERRORS, WARNINGS and MISSING.
check_host() {
  ERRORS=(); WARNINGS=(); MISSING=()
  echo "${1:-Host check (nothing is installed or changed)}"
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
  # client and the server must each be at least version 28 (`docker save
  # --platform`), the server on amd64.
  if ! have docker; then
    row "docker" "missing" "${PIN_DOCKER}" "ERROR"
    ERRORS+=("docker not found on PATH; the tested version is ${PIN_DOCKER}")
    MISSING+=("docker")
  else
    local dout dcli dsrv darch dshow dold=0
    if dout="$(docker version --format '{{.Client.Version}} {{.Server.Version}} {{.Server.Arch}}' 2>&1)"; then
      read -r dcli dsrv darch <<<"${dout}"
      # FOUND shows the client version, and the server's too when they differ.
      dshow="${dcli}"; if [ "${dcli}" != "${dsrv}" ]; then dshow="${dcli}/${dsrv}"; fi
      # Each side must be a number, and at least the minimum. A version that is
      # not a number (for example "dev") cannot be checked, so it is an error.
      if ! [[ "${dcli%%.*}" =~ ^[0-9]+$ ]]; then
        dold=1
        ERRORS+=("docker client version '${dcli}' is not a number, so it cannot be checked against the minimum of ${MIN_DOCKER_MAJOR}")
      elif [ "${dcli%%.*}" -lt "${MIN_DOCKER_MAJOR}" ]; then
        dold=1
        ERRORS+=("docker client ${dcli} is older than ${MIN_DOCKER_MAJOR}; image side-loading runs 'docker save --platform', which the docker client has from version ${MIN_DOCKER_MAJOR}. See https://docs.docker.com/engine/install/ for a newer Docker")
      fi
      if ! [[ "${dsrv%%.*}" =~ ^[0-9]+$ ]]; then
        dold=1
        ERRORS+=("docker server version '${dsrv}' is not a number, so it cannot be checked against the minimum of ${MIN_DOCKER_MAJOR}")
      elif [ "${dsrv%%.*}" -lt "${MIN_DOCKER_MAJOR}" ]; then
        dold=1
        ERRORS+=("docker server ${dsrv} is older than ${MIN_DOCKER_MAJOR}; image side-loading runs 'docker save --platform', which needs a Docker daemon of version ${MIN_DOCKER_MAJOR} or later. See https://docs.docker.com/engine/install/ for a newer Docker")
      fi
      if [ "${dold}" -eq 1 ]; then
        row "docker" "${dshow}" "${PIN_DOCKER}" "ERROR"
      elif [ "${dcli}" = "${PIN_DOCKER}" ] && [ "${dsrv}" = "${PIN_DOCKER}" ]; then
        row "docker" "${dshow}" "${PIN_DOCKER}" "ok"
      else
        row "docker" "${dshow}" "${PIN_DOCKER}" "differs (warning)"
        if [ "${dcli}" = "${dsrv}" ]; then
          WARNINGS+=("docker ${dcli} differs from the tested ${PIN_DOCKER}")
        else
          WARNINGS+=("docker client ${dcli} and server ${dsrv} differ from the tested ${PIN_DOCKER}")
        fi
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

# ---------------------------------------------------------------------------
# --install-tools: install the tools the host check found missing, as root
# ---------------------------------------------------------------------------

# confirm: ask for confirmation unless --yes was given. Declining changes
# nothing.
confirm() {
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
}

# in_list <name> <item>...: true when name is one of the items.
in_list() {
  local n="$1" x; shift
  for x in "$@"; do if [ "${x}" = "${n}" ]; then return 0; fi; done
  return 1
}
is_missing() { in_list "$1" "${MISSING[@]+"${MISSING[@]}"}"; }

# path_taken <path>: true when something is there, including a broken link.
path_taken() { [ -e "$1" ] || [ -L "$1" ]; }

# The downloads. The versions are the PIN_* values; the SHA-256 values are
# pinned at the top of this file.
dl_version() {
  case "$1" in
    kind)    echo "${PIN_KIND}" ;;
    kubectl) echo "${PIN_KUBECTL}" ;;
    go)      echo "${PIN_GO}" ;;
    opa)     echo "${PIN_OPA}" ;;
    uv)      echo "${PIN_UV}" ;;
  esac
}
dl_url() {
  case "$1" in
    kind)    echo "https://github.com/kubernetes-sigs/kind/releases/download/${PIN_KIND}/kind-linux-amd64" ;;
    kubectl) echo "https://dl.k8s.io/release/${PIN_KUBECTL}/bin/linux/amd64/kubectl" ;;
    go)      echo "https://go.dev/dl/go${PIN_GO}.linux-amd64.tar.gz" ;;
    opa)     echo "https://github.com/open-policy-agent/opa/releases/download/v${PIN_OPA}/opa_linux_amd64_static" ;;
    uv)      echo "https://github.com/astral-sh/uv/releases/download/${PIN_UV}/uv-x86_64-unknown-linux-musl.tar.gz" ;;
  esac
}
dl_sha256() {
  case "$1" in
    kind)    echo "${SHA256_KIND}" ;;
    kubectl) echo "${SHA256_KUBECTL}" ;;
    go)      echo "${SHA256_GO}" ;;
    opa)     echo "${SHA256_OPA}" ;;
    uv)      echo "${SHA256_UV}" ;;
  esac
}
# Every path a download writes. None may exist before it is installed.
dl_dests() {
  case "$1" in
    kind)    echo "${PREFIX}/bin/kind" ;;
    kubectl) echo "${PREFIX}/bin/kubectl" ;;
    go)      echo "${PREFIX}/go ${PREFIX}/bin/go ${PREFIX}/bin/gofmt" ;;
    opa)     echo "${PREFIX}/bin/opa" ;;
    uv)      echo "${PREFIX}/bin/uv ${PREFIX}/bin/uvx" ;;
  esac
}
dl_dest_text() {
  case "$1" in
    go) echo "${PREFIX}/go, with go and gofmt linked into ${PREFIX}/bin" ;;
    uv) echo "${PREFIX}/bin/uv and ${PREFIX}/bin/uvx" ;;
    *)  dl_dests "$1" ;;
  esac
}

# record_lines <line>...: append lines ("kind value") to the record of what was
# installed, skipping any already there. The file and its directory are created
# on first use. The write is all or nothing; it returns non-zero, and leaves no
# new directory, if it fails.
record_lines() {
  local dir new_dir=0 tmp l
  dir="$(dirname "${RECORD}")"
  tmp="${RECORD}.new"
  if [ ! -d "${dir}" ]; then mkdir -p "${dir}" || return 1; new_dir=1; fi
  if {
    if [ -f "${RECORD}" ]; then
      cat "${RECORD}"
    else
      echo "# nhi-lab install.sh --install-tools: what it installed. Remove it by hand."
      echo "# Dependencies pulled in by the package manager are not listed."
      echo "# Each line is a kind (file, dir, link, package, group, membership or note), then a path or name."
      if [ "${new_dir}" -eq 1 ]; then echo "dir ${dir}"; fi
    fi
    for l in "$@"; do
      if [ ! -f "${RECORD}" ] || ! grep -qxF -- "${l}" "${RECORD}"; then printf '%s\n' "${l}"; fi
    done
  } >"${tmp}" && mv "${tmp}" "${RECORD}"; then
    return 0
  fi
  rm -f "${tmp}"
  if [ "${new_dir}" -eq 1 ]; then rmdir "${dir}" 2>/dev/null || true; fi
  return 1
}

# The directory a download is unpacked in; removed on exit, so a refused or
# failed download leaves nothing behind. It sits inside ${PREFIX} so that moving
# a result into place is a rename.
STAGE=""
cleanup_stage() { if [ -n "${STAGE}" ]; then rm -rf "${STAGE}"; STAGE=""; fi; }
trap cleanup_stage EXIT
# On INT and TERM, clean up and then die by the same signal, so that the exit
# status (130, 143) is the one the shell reports without any trap.
trap 'trap - INT; cleanup_stage; kill -INT $$' INT
trap 'trap - TERM; cleanup_stage; kill -TERM $$' TERM

# CREATED lists the paths one install step has created. If the step fails,
# undo_created removes them, so that the tool leaves nothing behind and nothing
# is recorded for it.
CREATED=()
undo_created() {
  local p
  for p in "${CREATED[@]+"${CREATED[@]}"}"; do
    if [ -n "${p}" ]; then rm -rf -- "${p}"; fi
  done
  CREATED=()
}
# fail_step <tool> <message>: report a failure, undo the step, clean up.
fail_step() { echo "!! $1: $2"; undo_created; cleanup_stage; }

# install_download <tool>: download, verify the pinned SHA-256, then install.
# Nothing is written to ${PREFIX} before the checksum matches. If any later step
# fails, what the tool created is removed and nothing is recorded for it.
install_download() {
  local tool="$1" url sha actual file d lines=()
  CREATED=()
  url="$(dl_url "${tool}")"; sha="$(dl_sha256 "${tool}")"
  for d in $(dl_dests "${tool}"); do
    if path_taken "${d}"; then echo "!! ${tool}: ${d} already exists; not overwriting it."; return 1; fi
  done
  STAGE="$(mktemp -d "${PREFIX}/.nhi-lab-install.XXXXXX")" || return 1
  file="${STAGE}/download"
  echo ">> ${tool} $(dl_version "${tool}"): downloading ${url}"
  if ! curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "${file}" "${url}"; then
    fail_step "${tool}" "the download failed."; return 1
  fi
  actual="$(sha256sum "${file}")" || { fail_step "${tool}" "could not compute the SHA-256."; return 1; }
  actual="${actual%% *}"
  if [ "${actual}" != "${sha}" ]; then
    fail_step "${tool}" "SHA-256 mismatch. Expected ${sha}, got ${actual}. Refused; the download was removed."
    return 1
  fi
  echo ">> ${tool}: SHA-256 ${sha} matches"
  mkdir -p "${PREFIX}/bin" || { fail_step "${tool}" "could not create ${PREFIX}/bin."; return 1; }
  case "${tool}" in
    kind|kubectl|opa)
      CREATED+=("${PREFIX}/bin/${tool}")
      if ! chmod 0755 "${file}" || ! mv "${file}" "${PREFIX}/bin/${tool}"; then
        fail_step "${tool}" "could not install ${PREFIX}/bin/${tool}."; return 1
      fi
      lines=("file ${PREFIX}/bin/${tool}")
      ;;
    go)
      if ! tar -C "${STAGE}" --no-same-owner -xzf "${file}"; then fail_step go "unpacking failed."; return 1; fi
      CREATED+=("${PREFIX}/go")
      if ! mv "${STAGE}/go" "${PREFIX}/go"; then fail_step go "could not move it to ${PREFIX}/go."; return 1; fi
      CREATED+=("${PREFIX}/bin/go")
      if ! ln -s "${PREFIX}/go/bin/go" "${PREFIX}/bin/go"; then fail_step go "could not link ${PREFIX}/bin/go."; return 1; fi
      CREATED+=("${PREFIX}/bin/gofmt")
      if ! ln -s "${PREFIX}/go/bin/gofmt" "${PREFIX}/bin/gofmt"; then fail_step go "could not link ${PREFIX}/bin/gofmt."; return 1; fi
      lines=("dir ${PREFIX}/go" "link ${PREFIX}/bin/go" "link ${PREFIX}/bin/gofmt")
      ;;
    uv)
      if ! tar -C "${STAGE}" --no-same-owner -xzf "${file}" --strip-components=1 uv-x86_64-unknown-linux-musl/uv uv-x86_64-unknown-linux-musl/uvx; then
        fail_step uv "unpacking failed."; return 1
      fi
      CREATED+=("${PREFIX}/bin/uv")
      if ! mv "${STAGE}/uv" "${PREFIX}/bin/uv"; then fail_step uv "could not install ${PREFIX}/bin/uv."; return 1; fi
      CREATED+=("${PREFIX}/bin/uvx")
      if ! mv "${STAGE}/uvx" "${PREFIX}/bin/uvx"; then fail_step uv "could not install ${PREFIX}/bin/uvx."; return 1; fi
      lines=("file ${PREFIX}/bin/uv" "file ${PREFIX}/bin/uvx")
      ;;
  esac
  if ! record_lines "${lines[@]}"; then
    fail_step "${tool}" "could not write the record ${RECORD}; removed what it had installed."; return 1
  fi
  CREATED=()
  cleanup_stage
}

# install_python: Python ${PIN_PYTHON} through uv, into ${PY_DIR}, with python3
# linked into ${PREFIX}/bin. uv keeps its download cache in the staging
# directory, which is removed afterwards. If any step fails, what uv and this
# function created is removed and nothing is recorded.
install_python() {
  local before after n py out parent new_parent=0 new_dir=0 uv_ok=0 lines=()
  CREATED=()
  parent="$(dirname "${PY_DIR}")"
  STAGE="$(mktemp -d "${PREFIX}/.nhi-lab-install.XXXXXX")" || return 1
  if [ ! -d "${parent}" ]; then new_parent=1; fi
  if [ ! -d "${PY_DIR}" ]; then new_dir=1; fi
  before=""; if [ -d "${PY_DIR}" ]; then before="$(ls -A "${PY_DIR}")"; fi
  echo ">> uv python install ${PIN_PYTHON} (into ${PY_DIR})"
  if UV_PYTHON_INSTALL_DIR="${PY_DIR}" UV_CACHE_DIR="${STAGE}/cache" \
       uv python install --no-bin "${PIN_PYTHON}"; then
    uv_ok=1
  fi
  # What uv created, whether or not it succeeded: the new top directory, or,
  # when ${PY_DIR} existed already (even empty), only its new entries.
  if [ "${new_parent}" -eq 1 ]; then
    if [ -d "${parent}" ]; then CREATED+=("${parent}"); lines+=("dir ${parent}"); fi
  elif [ "${new_dir}" -eq 1 ]; then
    if [ -d "${PY_DIR}" ]; then CREATED+=("${PY_DIR}"); lines+=("dir ${PY_DIR}"); fi
  elif [ -d "${PY_DIR}" ]; then
    after="$(ls -A "${PY_DIR}")"
    while IFS= read -r n; do
      if [ -n "${n}" ] && ! grep -qxF -- "${n}" <<<"${before}"; then
        CREATED+=("${PY_DIR}/${n}")
        if [ -d "${PY_DIR}/${n}" ] && [ ! -L "${PY_DIR}/${n}" ]; then lines+=("dir ${PY_DIR}/${n}")
        elif [ -L "${PY_DIR}/${n}" ]; then lines+=("link ${PY_DIR}/${n}")
        else lines+=("file ${PY_DIR}/${n}"); fi
      fi
    done <<<"${after}"
  fi
  if [ "${uv_ok}" -ne 1 ]; then fail_step python3 "uv could not install Python ${PIN_PYTHON}."; return 1; fi
  py=""
  for n in "${PY_DIR}"/cpython-"${PIN_PYTHON}"-linux-x86_64-*/bin/python3; do
    if [ -x "${n}" ]; then py="${n}"; break; fi
  done
  if [ -z "${py}" ]; then fail_step python3 "no interpreter found under ${PY_DIR} after the install."; return 1; fi
  CREATED+=("${PREFIX}/bin/python3")
  if ! ln -s "${py}" "${PREFIX}/bin/python3"; then fail_step python3 "could not link ${PREFIX}/bin/python3."; return 1; fi
  out="$("${PREFIX}/bin/python3" --version 2>&1)" || out=""
  if [ "${out}" != "Python ${PIN_PYTHON}" ]; then
    fail_step python3 "${PREFIX}/bin/python3 reports '${out}', not Python ${PIN_PYTHON}."; return 1
  fi
  lines+=("link ${PREFIX}/bin/python3")
  if ! record_lines "${lines[@]}"; then
    fail_step python3 "could not write the record ${RECORD}; removed what it had installed."; return 1
  fi
  CREATED=()
  cleanup_stage
  echo ">> python3: ${out} (${PREFIX}/bin/python3 -> ${py})"
}

# plan_install: decide what the run will do, from MISSING and the package
# manager. Fills PKGS, BUILDX_PKG, DOCKER_PKGS, DOWNLOADS, WANT_PYTHON,
# NEED_DOCKER, REFUSED and GROUP_USER.
plan_install() {
  PKGS=(); BUILDX_PKG=""; DOCKER_PKGS=(); DOWNLOADS=(); REFUSED=()
  WANT_PYTHON=0; NEED_DOCKER=0; PKG_NEEDED=0; GROUP_USER=""
  local t d taken

  for t in kind kubectl go opa uv; do
    if ! is_missing "${t}"; then continue; fi
    taken=""
    for d in $(dl_dests "${t}"); do
      if path_taken "${d}"; then taken="${d}"; break; fi
    done
    if [ -n "${taken}" ]; then
      REFUSED+=("${t}: ${taken} already exists; it is not overwritten")
    else
      DOWNLOADS+=("${t}")
    fi
  done

  if is_missing python3; then
    if is_missing uv && ! in_list uv "${DOWNLOADS[@]+"${DOWNLOADS[@]}"}"; then
      REFUSED+=("python3: Python ${PIN_PYTHON} is installed through uv, and uv cannot be installed")
    elif path_taken "${PREFIX}/bin/python3"; then
      REFUSED+=("python3: ${PREFIX}/bin/python3 already exists; it is not overwritten")
    elif compgen -G "${PY_DIR}/cpython-${PIN_PYTHON}-*" >/dev/null; then
      REFUSED+=("python3: ${PY_DIR} already holds Python ${PIN_PYTHON}; it is not overwritten")
    else
      WANT_PYTHON=1
    fi
  fi

  # Packages. The names are the distro's.
  for t in make jq; do
    if is_missing "${t}"; then PKGS+=("${t}"); PKG_NEEDED=1; fi
  done
  if is_missing docker; then
    NEED_DOCKER=1; PKG_NEEDED=1
    case "${PM}" in
      apt-get) DOCKER_PKGS=(docker.io) ;;
      dnf)     DOCKER_PKGS=(moby-engine docker-cli) ;;
      pacman)  DOCKER_PKGS=(docker) ;;
    esac
    PKGS+=("${DOCKER_PKGS[@]}")
    BUILDX_PKG="docker-buildx"
  fi
  if [ ${#DOWNLOADS[@]} -gt 0 ]; then
    for t in curl tar gzip; do
      if ! have "${t}"; then PKGS+=("${t}"); PKG_NEEDED=1; fi
    done
    if [ ! -s /etc/ssl/certs/ca-certificates.crt ] && [ ! -s /etc/pki/tls/certs/ca-bundle.crt ]; then
      PKGS+=(ca-certificates); PKG_NEEDED=1
    fi
  fi

  if [ "${NEED_DOCKER}" -eq 1 ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ] \
     && id -u "${SUDO_USER}" >/dev/null 2>&1; then
    GROUP_USER="${SUDO_USER}"
  fi
}

# docker_major <version>: the major number of a package version, without any
# epoch ("1:29.9.3-1" gives 29). Empty if there is none.
docker_major() {
  local v="$1"
  if [[ "${v}" =~ ^[0-9]+: ]]; then v="${v#*:}"; fi
  echo "${v%%[!0-9]*}"
}

# pkg_candidate <package>: the version the package manager would install, read
# from the temporary metadata in STAGE. Empty if it offers none.
pkg_candidate() {
  local out ver=""
  case "${PM}" in
    apt-get)
      out="$(apt-cache -o "Dir::State::Lists=${STAGE}/lists" -o "Dir::Cache=${STAGE}/cache" policy "$1" 2>/dev/null || true)"
      ver="$(awk '/^ *Candidate:/{print $2; exit}' <<<"${out}")"
      if [ "${ver}" = "(none)" ]; then ver=""; fi
      ;;
    dnf)
      out="$(dnf "${DNF_OPTS[@]}" info --available "$1" 2>/dev/null || true)"
      ver="$(awk '/^Version/{print $3}' <<<"${out}" | sort -V | tail -n 1)"
      ;;
    pacman)
      out="$(pacman "${PACMAN_OPTS[@]}" -Si "$1" 2>/dev/null || true)"
      ver="$(awk '/^Version/{print $3; exit}' <<<"${out}")"
      ;;
  esac
  echo "${ver}"
}

# pkg_version <package>: the version read for the statement.
pkg_version() {
  local e
  for e in "${PKG_VERSIONS[@]+"${PKG_VERSIONS[@]}"}"; do
    if [ "${e%% *}" = "$1" ]; then echo "${e#* }"; return; fi
  done
}

# read_package_versions: read the version of every package the run would
# install, and stop if the Docker package is below the minimum. It runs before
# the statement and installs nothing. The package metadata, and every state, log
# and cache file of the read, go into a temporary directory that is removed
# afterwards, so nothing else on the system is written. Fills PKG_VERSIONS, and
# adds BUILDX_PKG to PKGS when the package manager offers it.
read_package_versions() {
  local pkg want=() ver major d low_pkg="" low_ver="" low_major=""
  PKG_VERSIONS=(); BUILDX_OFFERED=0
  STAGE="$(mktemp -d)" || exit 1
  echo ">> Reading the version of each package that ${PM} would install. This downloads the"
  echo "   package metadata into a temporary directory; nothing is installed and nothing else is written."
  case "${PM}" in
    apt-get)
      mkdir -p "${STAGE}/lists/partial" "${STAGE}/cache/archives/partial"
      DEBIAN_FRONTEND=noninteractive apt-get -q -o "Dir::State::Lists=${STAGE}/lists" \
        -o "Dir::Cache=${STAGE}/cache" -o APT::Sandbox::User=root update >/dev/null 2>&1 || true
      ;;
    dnf)
      DNF_OPTS=(-q --setopt=cachedir="${STAGE}/dnf" --setopt=persistdir="${STAGE}/persist"
                --setopt=logdir="${STAGE}/log" --setopt=countme=0)
      ;;
    pacman)
      PACMAN_OPTS=(--dbpath "${STAGE}/db" --logfile "${STAGE}/pacman.log" --cachedir "${STAGE}/pkg")
      # pacman downloads as an unprivileged user, who must be able to write the
      # sync directory. It is mode 1777 (world-writable with the sticky bit), and
      # sits in a directory removed when this step ends.
      mkdir -p "${STAGE}/db/sync" "${STAGE}/pkg"
      chmod 755 "${STAGE}" "${STAGE}/db"; chmod 1777 "${STAGE}/db/sync"
      ln -s /var/lib/pacman/local "${STAGE}/db/local"
      pacman "${PACMAN_OPTS[@]}" -Sy >/dev/null 2>&1 || true
      ;;
  esac
  want=("${PKGS[@]}")
  if [ -n "${BUILDX_PKG}" ]; then want+=("${BUILDX_PKG}"); fi
  for pkg in "${want[@]}"; do
    ver="$(pkg_candidate "${pkg}")"
    if [ -z "${ver}" ]; then
      if [ "${pkg}" = "${BUILDX_PKG}" ]; then continue; fi
      cleanup_stage
      echo
      echo "!! Could not read the version of ${pkg} that ${PM} would install. Nothing was installed or changed."
      exit 1
    fi
    PKG_VERSIONS+=("${pkg} ${ver}")
    if [ "${pkg}" = "${BUILDX_PKG}" ]; then BUILDX_OFFERED=1; PKGS+=("${pkg}"); fi
  done
  cleanup_stage
  # The Docker packages must be Docker 28 or later. A version that is not a
  # number is not accepted.
  for d in "${DOCKER_PKGS[@]+"${DOCKER_PKGS[@]}"}"; do
    ver="$(pkg_version "${d}")"
    major="$(docker_major "${ver}")"
    if [ -z "${major}" ]; then
      echo
      echo "!! The version of ${d} (${ver}) is not a number, so it cannot be checked against the"
      echo "!! minimum of Docker ${MIN_DOCKER_MAJOR}. Nothing was installed or changed."
      exit 1
    fi
    if [ -z "${low_major}" ] || [ "${major}" -lt "${low_major}" ]; then
      low_pkg="${d}"; low_ver="${ver}"; low_major="${major}"
    fi
  done
  if [ -n "${low_major}" ] && [ "${low_major}" -lt "${MIN_DOCKER_MAJOR}" ]; then
    echo
    echo "!! Docker is missing, and the package ${PM} would install is too old: ${low_pkg} ${low_ver}."
    echo "!! The lab needs Docker ${MIN_DOCKER_MAJOR} or later, because image side-loading runs 'docker save --platform'."
    echo "!! See https://docs.docker.com/engine/install/ to install a newer Docker; then re-run sudo ./install.sh --install-tools."
    echo "!! Nothing was installed or changed."
    exit 1
  fi
}

# What the run is about to change. Keep it in step with install_packages,
# install_download, install_python and setup_docker.
print_install_statement() {
  local t p
  echo "What --install-tools will change on this machine (it runs as root):"
  if [ ${#PKGS[@]} -gt 0 ]; then
    echo "  - Packages, installed with ${PM}, plus their dependencies. Versions are as read from the"
    echo "    package metadata just now:"
    for p in "${PKGS[@]}"; do echo "      ${p} $(pkg_version "${p}")"; done
    if [ -n "${BUILDX_PKG}" ] && [ "${BUILDX_OFFERED}" -eq 0 ]; then
      echo "      (${BUILDX_PKG} is not offered by ${PM}; it is skipped)"
    fi
    case "${PM}" in
      apt-get) echo "    The package index is refreshed first ('apt-get update'), and apt also installs the"
               echo "    recommended packages of these." ;;
      dnf)     echo "    The package metadata is refreshed as needed." ;;
      pacman)  echo "    This runs 'pacman -Syu': pacman does not support installing without a"
               echo "    full system upgrade, so every installed package is upgraded too." ;;
    esac
  fi
  if [ ${#DOWNLOADS[@]} -gt 0 ]; then
    echo "  - Downloads. Each is checked against a SHA-256 pinned in this script before"
    echo "    anything is installed; a mismatch refuses that tool and removes the download:"
    for t in "${DOWNLOADS[@]}"; do
      echo "      ${t} $(dl_version "${t}")"
      echo "        from  $(dl_url "${t}")"
      echo "        to    $(dl_dest_text "${t}")"
    done
  fi
  if [ "${WANT_PYTHON}" -eq 1 ]; then
    echo "  - Python ${PIN_PYTHON}, installed by uv. uv downloads the python-build-standalone"
    echo "    build (releases.astral.sh in uv ${PIN_UV}) and checks it against a SHA-256 built into uv:"
    echo "        to    ${PY_DIR}"
    echo "        with  python3 linked at ${PREFIX}/bin/python3"
  fi
  if [ "${NEED_DOCKER}" -eq 1 ]; then
    if [ "$(cat /proc/1/comm 2>/dev/null || true)" = "systemd" ]; then
      echo "  - Starts Docker with 'systemctl enable --now docker' (systemd is running)."
    else
      echo "  - Starts no Docker daemon: systemd is not running here. The host check afterwards"
      echo "    reports whether a daemon is reachable, for example through a mounted socket."
    fi
    if [ -n "${GROUP_USER}" ]; then
      echo "  - Adds user '${GROUP_USER}' to the 'docker' group (created if needed). The"
      echo "    membership takes effect at that user's next login."
    fi
  fi
  if [ ${#PKGS[@]} -gt 0 ] || [ ${#DOWNLOADS[@]} -gt 0 ] || [ "${WANT_PYTHON}" -eq 1 ]; then
    echo "  - Records everything it installs in ${RECORD}"
    echo "    (appended on re-runs), so you can remove it by hand. There is no uninstall mode."
  fi
  echo "  - Leaves every tool the host check found alone, including any at another version."
  echo "  - Looked for tools on this PATH (under sudo, sudo's): one kept only in your own directories, such as ~/.local/bin, counts as missing and is listed above."
  if [ ${#REFUSED[@]} -gt 0 ]; then
    echo "  - Cannot install, reported as errors:"
    for t in "${REFUSED[@]}"; do echo "      ${t}"; done
  fi
}

# install_packages: one non-interactive package manager run for PKGS. The
# record is written only after the install succeeds.
install_packages() {
  local p lines=()
  case "${PM}" in
    apt-get)
      echo ">> apt-get update"
      DEBIAN_FRONTEND=noninteractive apt-get update || return 1
      echo ">> apt-get install -y ${PKGS[*]}"
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${PKGS[@]}" || return 1
      ;;
    dnf)
      echo ">> dnf install -y ${PKGS[*]}"
      dnf install -y "${PKGS[@]}" || return 1
      ;;
    pacman)
      echo ">> pacman -Syu --noconfirm --needed ${PKGS[*]}"
      pacman -Syu --noconfirm --needed "${PKGS[@]}" || return 1
      lines+=("note pacman -Syu upgraded every installed package; that is not undone by removing the packages below")
      ;;
  esac
  for p in "${PKGS[@]}"; do lines+=("package ${PM} ${p}"); done
  if ! record_lines "${lines[@]}"; then
    echo "!! The packages were installed, but ${RECORD} could not be written."
    return 1
  fi
}

# setup_docker: start Docker under systemd, and add the sudo user to the
# docker group.
setup_docker() {
  local lines=()
  if [ "$(cat /proc/1/comm 2>/dev/null || true)" = "systemd" ]; then
    echo ">> systemctl enable --now docker"
    systemctl enable --now docker || { echo "!! docker: 'systemctl enable --now docker' failed."; return 1; }
  else
    echo ">> No systemd: no Docker daemon was started."
  fi
  if [ -n "${GROUP_USER}" ]; then
    if ! getent group docker >/dev/null; then
      echo ">> groupadd docker"
      groupadd docker || return 1
      lines+=("group docker")
    fi
    echo ">> usermod -aG docker ${GROUP_USER}"
    usermod -aG docker "${GROUP_USER}" || return 1
    lines+=("membership docker ${GROUP_USER}")
    if ! record_lines "${lines[@]}"; then echo "!! The group change was made, but ${RECORD} could not be written."; return 1; fi
    echo ">> ${GROUP_USER} is in the 'docker' group. That takes effect at the next login."
  fi
}

install_tools_main() {
  local failed=0 t

  # Root only, and the script never runs sudo itself.
  if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: --install-tools needs root. Nothing was changed." >&2
    echo "Run:  sudo ./install.sh --install-tools" >&2
    echo "or run ./install.sh --install-tools from a root shell." >&2
    exit 1
  fi

  # Debian is not supported: its packages are too old for the lab.
  if [ "$( (. /etc/os-release 2>/dev/null; echo "${ID:-}") )" = "debian" ]; then
    echo "!! Debian is not supported: the packages apt supplies on Debian are too old for the lab (Debian 13's docker.io is 26.1.5; the lab needs Docker ${MIN_DOCKER_MAJOR} or later)."
    echo "!! See \"Prerequisites\" in README.md. Nothing was installed or changed."
    exit 1
  fi
  case ":${PATH}:" in *":${PREFIX}/bin:"*) ;; *) export PATH="${PATH}:${PREFIX}/bin" ;; esac

  check_host "Host check before installing (nothing is changed yet)"
  if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
    echo
    echo "!! Unsupported platform: --install-tools supports Linux on amd64 only. Nothing was changed."
    exit 1
  fi
  if [ ${#MISSING[@]} -eq 0 ]; then
    echo
    echo ">> No tool is missing, so there is nothing to install. Nothing was changed."
    tools_next_steps
    return
  fi

  PM=""
  if have apt-get; then PM="apt-get"; elif have dnf; then PM="dnf"; elif have pacman; then PM="pacman"; fi
  plan_install
  if [ "${PKG_NEEDED}" -eq 1 ] && [ -z "${PM}" ]; then
    echo
    echo "!! This needs distro packages, and none of apt-get, dnf or pacman was found. Other package"
    echo "!! managers are not supported. Install make, jq, Docker Engine, curl, ca-certificates, tar"
    echo "!! and gzip yourself, then re-run. Nothing was changed."
    exit 1
  fi
  if [ "${PKG_NEEDED}" -eq 1 ]; then read_package_versions; fi
  if [ ${#PKGS[@]} -eq 0 ] && [ ${#DOWNLOADS[@]} -eq 0 ] && [ "${WANT_PYTHON}" -eq 0 ]; then
    echo
    print_install_statement
    echo
    echo "!! Nothing can be installed. Nothing was changed."
    exit 1
  fi

  echo
  print_install_statement
  echo
  confirm

  START_ALL=${SECONDS}
  if [ ${#PKGS[@]} -gt 0 ]; then
    echo
    if ! install_packages; then
      echo "!! The package install failed. Stopping; what was recorded so far is in ${RECORD}."
      exit 1
    fi
  fi
  for t in "${DOWNLOADS[@]+"${DOWNLOADS[@]}"}"; do
    echo
    if ! install_download "${t}"; then failed=1; REFUSED+=("${t}: not installed (see above)"); fi
  done
  if [ "${WANT_PYTHON}" -eq 1 ]; then
    echo
    if is_missing uv && ! have uv; then
      echo "!! python3: uv is not installed, so Python ${PIN_PYTHON} cannot be installed."
      failed=1; REFUSED+=("python3: not installed, uv is missing")
    elif ! install_python; then
      failed=1; REFUSED+=("python3: not installed (see above)")
    fi
  fi
  if [ "${NEED_DOCKER}" -eq 1 ] && have docker; then
    echo
    setup_docker || failed=1
  fi

  hash -r
  echo
  check_host "Host check after installing"
  echo
  if [ ${#REFUSED[@]} -gt 0 ]; then
    failed=1
    echo "!! Not installed:"
    for t in "${REFUSED[@]}"; do echo "!!   ${t}"; done
  fi
  if [ ${#ERRORS[@]} -gt 0 ]; then
    failed=1
    echo "!! The host check still reports ${#ERRORS[@]} error(s). Fix them, then re-run."
  fi
  if [ -s "${RECORD}" ]; then echo ">> What was installed is recorded in ${RECORD}"; fi
  if [ "${failed}" -ne 0 ]; then exit 1; fi
  tools_next_steps
}

# tools_next_steps: the --install-tools mode ends here; the lab itself is
# brought up by a second, unprivileged run.
tools_next_steps() {
  if [ ${#ERRORS[@]} -gt 0 ]; then
    echo
    echo "!! The host check reports error(s) above. Fix them, then run ./install.sh."
    exit 1
  fi
  echo
  echo ">> The host tools are in place. Next, run the lab without sudo:"
  echo "     ./install.sh"
  echo "   (In a container where you are root, just ./install.sh.)"
  if [ -n "${GROUP_USER:-}" ]; then
    echo "   Log out and back in first, so the 'docker' group membership applies."
  fi
}

if [ "${MODE}" = "tools" ]; then
  install_tools_main
  exit 0
fi

check_host

if [ ${#ERRORS[@]} -gt 0 ]; then
  echo
  echo "!! The host check failed (${#ERRORS[@]} error(s)). Nothing was changed."
  if [ ${#MISSING[@]} -gt 0 ]; then
    echo "!! To install the missing tools, run: sudo ./install.sh --install-tools"
    echo "!! (from a root shell: ./install.sh --install-tools)"
  fi
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

confirm

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
