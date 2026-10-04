#!/usr/bin/env python3
"""Child agent.

Created by parent.py via the k8s API, AFTER the vending service has already
minted this pod's SPIRE registration entry (see parent.py's module
docstring — that ordering is what makes "the child obtains its own SVID via
the Workload API with no human action" true of an actual spawn, not merely
of identity issuance into a pre-existing pod).

Does exactly the following and nothing else (negative-path testing lives in
src/experiments, not this harness):

  1. wait for its own SVID via the Workload API (retrying — the SPIRE agent
     needs a moment to notice the freshly created entry).
  2. call the protected resource with a JWT-SVID, audience
     spiffe://lab.local/svc/resource.
  3. do its trivial "task" (read one dataset).
  4. emit one audit event of its own (stage=operate, chain_id from the
     CHAIN_ID env var parent.py set — an untrusted hint the resource itself
     also receives via X-NHI-Chain-Id, exactly the resource's
     chain_id_source contract) and exit.
"""

from __future__ import annotations

import os
import sys

import common


def main() -> int:
    resource_url = os.environ.get("RESOURCE_URL", "http://resource.nhi.svc.cluster.local:8080").rstrip("/")
    resource_audience = os.environ.get("RESOURCE_AUDIENCE", "spiffe://lab.local/svc/resource")
    dataset_path = os.environ.get("DATASET_PATH", "/datasets/A")
    chain_id = os.environ.get("CHAIN_ID", "")

    common.log("child: fetching own SVID from the Workload API")
    wl = common.new_workload_client()
    svid = common.fetch_x509_svid_retrying(wl)
    own_id = str(svid.spiffe_id)
    common.log(f"child: own SPIFFE ID = {own_id} — obtained with no human action")

    common.log(f"child: fetching a JWT-SVID for {resource_audience}")
    jwt = common.fetch_jwt_svid_retrying(wl, resource_audience)

    headers = common.bearer_headers(jwt.token)
    if chain_id:
        # An untrusted hint (the resource's chain_id_source contract:
        # src/resource/audit.go) — the resource's own audit event records
        # actor_spiffe_id from the validated JWT-SVID regardless, this
        # header only helps a human/collector correlate log lines faster.
        headers["X-NHI-Chain-Id"] = chain_id

    common.log(f"child: calling GET {resource_url}{dataset_path}")
    session = common.http_session()
    resp = session.get(f"{resource_url}{dataset_path}", headers=headers)
    common.log(f"child: resource responded {resp.status_code}: {resp.text}")

    ok = resp.status_code == 200
    common.emit_audit_event(
        stage="operate",
        chain_id=chain_id,
        actor_spiffe_id=own_id,
        outcome=common.OUTCOME_ALLOW if ok else common.OUTCOME_DENY,
        detail={
            "reason": f"GET {dataset_path} -> {resp.status_code}",
        },
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
