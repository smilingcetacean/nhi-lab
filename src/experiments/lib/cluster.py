"""Thin wrappers around `kubectl` used by every experiment suite.

Deliberately not a Kubernetes SDK client: every other verification script in
this repo (verify.sh, verify-resource.sh, verify-policy.sh, verify-vending.sh, demo.sh)
drives the cluster with plain `kubectl` subprocess calls, and this harness
follows the same, already-proven pattern rather than introducing a second way
to talk to the cluster. See verify-vending.sh for the shell version of most of
this file's logic (running_pod, split_status_body, show_audit) — this is a
line-for-line Python port so the two stay comparable.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import re
import dataclasses
from typing import Any

CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "nhi-lab")
KUBECTX = os.environ.get("KUBECTX", f"kind-{CLUSTER_NAME}")
TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "lab.local")

RESOURCE_URL = "http://resource.nhi.svc.cluster.local:8080"
RESOURCE_AUD = f"spiffe://{TRUST_DOMAIN}/svc/resource"


class KubectlError(RuntimeError):
    pass


def kubectl(*args: str, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
    cmd = ["kubectl", "--context", KUBECTX, *args]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and res.returncode != 0:
        raise KubectlError(f"{' '.join(cmd)} failed ({res.returncode}): {res.stderr}")
    return res


def running_pod(ns: str, selector: str) -> str | None:
    """Mirrors verify-vending.sh's running_pod(): the newest Running pod for a label."""
    res = kubectl(
        "get", "pods", "-n", ns, "-l", selector,
        "--field-selector=status.phase=Running",
        "--sort-by=.metadata.creationTimestamp",
        "-o", "jsonpath={.items}",
        check=False,
    )
    if res.returncode != 0 or not res.stdout.strip():
        return None
    try:
        items = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None
    if not items:
        return None
    return items[-1]["metadata"]["name"]


def wait_for_pod(ns: str, selector: str, timeout_s: int = 90, interval_s: float = 2.0) -> str:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        pod = running_pod(ns, selector)
        if pod:
            return pod
        time.sleep(interval_s)
    raise TimeoutError(f"no Running pod for -l {selector} in {ns} within {timeout_s}s")


def exec_pod(ns: str, pod: str, container: str, *cmd: str, timeout: int = 30) -> str:
    """kubectl exec, stdout+stderr merged (2>&1), like the bash harness does."""
    full = ["exec", "-n", ns, pod, "-c", container, "--"] + list(cmd)
    res = kubectl(*full, check=False, timeout=timeout)
    return (res.stdout or "") + (res.stderr or "")


@dataclasses.dataclass
class ParentsimResult:
    code: int | None
    body: str
    raw: str


def split_status_body(raw: str) -> ParentsimResult:
    """Port of verify-vending.sh's split_status_body(): parentsim prints "HTTP
    <code>" on stderr and the JSON body on stdout; kubectl exec ... merges
    both onto one stream, so pull the code out by pattern match rather than
    relying on stream order."""
    m = list(re.finditer(r"HTTP (\d+)", raw))
    code = int(m[-1].group(1)) if m else None
    body_lines = [ln for ln in raw.splitlines() if not ln.startswith("HTTP ")]
    body = " ".join(body_lines).strip()
    return ParentsimResult(code=code, body=body, raw=raw)


def parentsim(ns: str, pod: str, *args: str, timeout: int = 30) -> ParentsimResult:
    raw = exec_pod(ns, pod, "parentsim", "/parentsim", *args, timeout=timeout)
    return split_status_body(raw)


def audit_lines(ns: str, label_selector: str, container: str, tail: int = 100) -> list[dict[str, Any]]:
    res = kubectl(
        "logs", "-n", ns, "-l", label_selector, "-c", container,
        f"--tail={tail}", check=False,
    )
    out: list[dict[str, Any]] = []
    for ln in (res.stdout or "").splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


def find_event(events: list[dict[str, Any]], chain_id: str | None = None,
                stage: str | None = None, outcome: str | None = None) -> dict[str, Any] | None:
    for ev in reversed(events):
        if chain_id is not None and ev.get("chain_id") != chain_id:
            continue
        if stage is not None and ev.get("stage") != stage:
            continue
        if outcome is not None and ev.get("outcome") != outcome:
            continue
        return ev
    return None


def spire_entry_show(spiffe_id: str) -> str:
    res = kubectl(
        "exec", "-n", "spire", "spire-server-0", "-c", "spire-server", "--",
        "/opt/spire/bin/spire-server", "entry", "show", "-spiffeID", spiffe_id,
        check=False,
    )
    return res.stdout or ""


def entry_exists(spiffe_id: str) -> bool:
    return "Entry ID" in spire_entry_show(spiffe_id)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
