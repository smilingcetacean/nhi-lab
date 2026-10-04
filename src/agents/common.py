"""Shared helpers for parent.py and child.py: Workload API access, the
lab-wide audit event shape, and small HTTP conveniences.

Both agents fetch their own credentials from the SPIRE Workload API — no
pre-shared secret, no human action — exactly like cmd/parentsim. This module
exists so that shape is written once instead of twice.
"""

from __future__ import annotations

import datetime
import json
import os
import sys
import time

import requests
from spiffe import JwtSvid, WorkloadApiClient, X509Svid

DEFAULT_SOCKET_PATH = "unix:///run/spire/sockets/agent.sock"

# --- audit events ------------------------------------------------------------
#
# Mirrors src/vending-service/internal/audit.Event /
# src/resource/audit.go / src/policy-engine/audit.go exactly (the schema is
# shared lab-wide): timestamp, stage, chain_id, actor_spiffe_id, outcome,
# detail. Printed to stdout as one JSON object per line — this pod's
# container log is what `make demo` (src/deploy/scripts/demo.sh) gathers into
# the single, unified audit stream.
#
# The vocabulary is spawn|attest|vend|operate|log|dispose; this
# harness only ever emits "spawn" (parent.py, the one stage no other
# component can emit, since it is the parent's own decision to fork) — attest
# /vend/dispose belong to the vending service and policy engine, operate to
# the resource, all of which already emit it themselves and are collected
# from their own pods by demo.sh.
STAGE_SPAWN = "spawn"

OUTCOME_ALLOW = "allow"
OUTCOME_DENY = "deny"
OUTCOME_ERROR = "error"


def emit_audit_event(
    *,
    stage: str,
    chain_id: str,
    actor_spiffe_id: str,
    outcome: str,
    detail: dict,
) -> None:
    event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "stage": stage,
        "chain_id": chain_id,
        "actor_spiffe_id": actor_spiffe_id,
        "outcome": outcome,
        "detail": detail,
    }
    print(json.dumps(event, separators=(",", ":")), flush=True)


def log(msg: str) -> None:
    """Human-readable progress line, kept OFF stdout (which the audit
    collector treats as JSON-lines-or-ignore) and onto stderr instead, so
    `kubectl logs` stdout capture stays a clean audit stream."""
    print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] {msg}", file=sys.stderr, flush=True)


# --- Workload API --------------------------------------------------------


def socket_path() -> str:
    return os.environ.get("SPIFFE_ENDPOINT_SOCKET", DEFAULT_SOCKET_PATH)


def new_workload_client() -> WorkloadApiClient:
    return WorkloadApiClient(socket_path())


def fetch_x509_svid_retrying(client: WorkloadApiClient, *, attempts: int = 30, delay_seconds: float = 2.0) -> X509Svid:
    """Fetches this workload's own X.509-SVID, retrying: the SPIRE agent
    needs a moment to notice a freshly created registration entry (the same
    window verify-vending.sh's exit-criterion-B check retries against), and for
    the CHILD in particular, this call may start racing the entry's very
    creation.
    """
    last_err: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return client.fetch_x509_svid()
        except Exception as err:  # noqa: BLE001 - genuinely want to retry any Workload API failure here
            last_err = err
            log(f"fetch_x509_svid attempt {attempt}/{attempts} failed: {err!r}; retrying")
            time.sleep(delay_seconds)
    assert last_err is not None
    raise last_err


def fetch_jwt_svid_retrying(
    client: WorkloadApiClient, audience: str, *, attempts: int = 30, delay_seconds: float = 2.0
) -> JwtSvid:
    last_err: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return client.fetch_jwt_svid(audience={audience})
        except Exception as err:  # noqa: BLE001
            last_err = err
            log(f"fetch_jwt_svid attempt {attempt}/{attempts} failed: {err!r}; retrying")
            time.sleep(delay_seconds)
    assert last_err is not None
    raise last_err


# --- HTTP ------------------------------------------------------------------


def bearer_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def http_session(timeout_seconds: float = 15.0) -> requests.Session:
    s = requests.Session()
    s.request = _with_default_timeout(s.request, timeout_seconds)  # type: ignore[method-assign]
    return s


def _with_default_timeout(request_fn, timeout_seconds: float):
    def wrapped(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout_seconds)
        return request_fn(method, url, **kwargs)

    return wrapped
