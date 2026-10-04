#!/usr/bin/env python3
"""Functional test suite.

1. Pi(C) <= Pi(P) across randomized scope sets: repeatedly requests a random
   subset of a scope pool -- the resource's 3 real scopes plus 2 fictitious
   ones, so some runs legitimately have zero overlap with Pi(P) -- against
   the exp-root root parent (Pi(P) = all 3 real scopes) and asserts
   child_scopes == requested_scopes n Pi(P) EXACTLY (not just subset: a
   containment check that only asserted "subset" would also pass a service
   that granted the empty set every time, which is not what attenuation
   means).

2. Credential expiry on child termination: vend, wait for the child's SVID,
   dispose (modelling "task complete" / parent-initiated termination), and
   measure how long the Workload API takes to actually stop renewing the
   credential -- distinct from the negative-test suite's one-shot version of
   this, here run N times to characterise the distribution, since "on
   termination" is a timing claim (observable to auditors, not
   necessarily instantaneous).
"""
from __future__ import annotations

import csv
import itertools
import json
import random
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib import cluster as c  # noqa: E402

NS = "agents"
VS_NS = "nhi"
PARENT_ID = f"spiffe://{c.TRUST_DOMAIN}/agent/parent/exp-root"
PI_P = {"resource:read:datasetA", "resource:read:datasetB", "resource:write:jobs"}
SCOPE_POOL = sorted(PI_P) + ["resource:admin:everything", "resource:delete:everything"]


def scope_containment(n: int, parent_pod: str) -> tuple[list[dict], bool]:
    print(f"== functional: Pi(C) <= Pi(P) across {n} randomized scope sets ==")
    results = []
    rng = random.Random(20260726)
    all_ok = True
    for i in range(n):
        k = rng.randint(1, len(SCOPE_POOL))
        requested = sorted(rng.sample(SCOPE_POOL, k))
        expected = sorted(set(requested) & PI_P)
        rid = uuid.uuid4().hex[:10]
        r = c.parentsim(
            NS, parent_pod, "vend",
            f"-child-path-hint=child/func-scope-{rid}",
            f"-scopes={','.join(requested)}",
            "-task-context=experiment functional: randomized scope containment",
            "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-child",
            "-ttl=120",
            f"-nonce=func_scope_{rid}",
        )
        row = {"run": i, "requested_scopes": requested, "expected_child_scopes": expected}
        if expected:
            got = None
            if r.code == 201:
                body = json.loads(r.body)
                got = sorted(body.get("child_scopes", []))
                # cleanup immediately -- this suite runs many delegations and
                # does not need them to linger
                c.parentsim(NS, parent_pod, "dispose", f"-chain-id={body['chain_id']}")
            ok = (r.code == 201) and (got == expected) and set(got or []) <= PI_P
            row.update(http_code=r.code, got_child_scopes=got, pass_=ok)
        else:
            # requested has zero overlap with Pi(P) -- the vending service
            # must refuse it (403), not silently mint with child_scopes=[]
            ok = (r.code == 403)
            row.update(http_code=r.code, got_child_scopes=None, pass_=ok)
        all_ok = all_ok and ok
        results.append(row)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] run {i}: requested={requested} expected={expected} got_http={r.code} got={row.get('got_child_scopes')}")
    return results, all_ok


def credential_expiry(n: int, parent_pod: str, child_pod: str) -> tuple[list[dict], bool]:
    print(f"\n== functional: credential expiry on child termination ({n} runs) ==")
    results = []
    all_ok = True
    for i in range(n):
        rid = uuid.uuid4().hex[:10]
        child_id = f"{PARENT_ID}/child/func-exp-{rid}"
        r = c.parentsim(
            NS, parent_pod, "vend",
            f"-child-path-hint=child/func-exp-{rid}",
            "-scopes=resource:read:datasetA",
            "-task-context=experiment functional: credential expiry on termination",
            "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-child",
            "-ttl=300",
            f"-nonce=func_exp_{rid}",
        )
        if r.code != 201:
            results.append({"run": i, "pass_": False, "note": "vend failed", "body": r.body})
            all_ok = False
            continue
        chain_id = json.loads(r.body)["chain_id"]

        t_attest_start = time.monotonic()
        got_svid = False
        for _ in range(15):
            out = c.parentsim(NS, child_pod, "x509-check")
            if child_id in out.body:
                got_svid = True
                break
            time.sleep(1)
        t_attest = time.monotonic() - t_attest_start

        t_dispose_start = time.monotonic()
        dispose = c.parentsim(NS, parent_pod, "dispose", f"-chain-id={chain_id}")
        t_dispose = time.monotonic() - t_dispose_start

        t_revoke_start = time.monotonic()
        revoked = False
        for _ in range(15):
            out = c.parentsim(NS, child_pod, "x509-check")
            if child_id not in out.body:  # error, or a DIFFERENT (unrelated) SVID
                revoked = True
                break
            time.sleep(1)
        t_revoke = time.monotonic() - t_revoke_start

        ok = got_svid and (dispose.code == 200) and revoked
        all_ok = all_ok and ok
        row = {
            "run": i, "pass_": ok,
            "attest_latency_s": round(t_attest, 3),
            "dispose_http_code": dispose.code,
            "dispose_call_latency_s": round(t_dispose, 3),
            "revocation_observed_latency_s": round(t_revoke, 3),
        }
        results.append(row)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] run {i}: attest={row['attest_latency_s']}s dispose_call={row['dispose_call_latency_s']}s revoke_observed={row['revocation_observed_latency_s']}s")
    return results, all_ok


def main() -> int:
    parent_pod = c.wait_for_pod(NS, "app=experiments-parent")
    child_pod = c.wait_for_pod(NS, "app=experiments-child")
    print(f"parent={parent_pod} child={child_pod}")

    out_dir = Path(__file__).parent / "results" / "latest"
    out_dir.mkdir(parents=True, exist_ok=True)

    scope_results, scope_ok = scope_containment(30, parent_pod)
    with open(out_dir / "functional_scope_containment.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["run", "requested_scopes", "expected_child_scopes", "http_code", "got_child_scopes", "pass_"])
        w.writeheader()
        for row in scope_results:
            w.writerow({**row, "requested_scopes": json.dumps(row["requested_scopes"]),
                        "expected_child_scopes": json.dumps(row["expected_child_scopes"]),
                        "got_child_scopes": json.dumps(row.get("got_child_scopes"))})

    expiry_results, expiry_ok = credential_expiry(10, parent_pod, child_pod)
    with open(out_dir / "functional_credential_expiry.csv", "w", newline="") as f:
        fieldnames = ["run", "pass_", "attest_latency_s", "dispose_http_code", "dispose_call_latency_s", "revocation_observed_latency_s", "note", "body"]
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for row in expiry_results:
            w.writerow(row)

    summary = {
        "generated_at": c.now_iso(),
        "scope_containment": {"n": len(scope_results), "all_pass": scope_ok,
                               "failures": [r for r in scope_results if not r["pass_"]]},
        "credential_expiry": {"n": len(expiry_results), "all_pass": expiry_ok,
                               "failures": [r for r in expiry_results if not r["pass_"]]},
    }
    (out_dir / "functional_tests_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print(f"\nwrote {out_dir}/functional_scope_containment.csv, functional_credential_expiry.csv, functional_tests_summary.json")

    ok = scope_ok and expiry_ok
    print(f"\n{'PASS' if ok else 'FAIL'}: functional suite ({len(scope_results)} scope-containment runs, {len(expiry_results)} expiry runs)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
