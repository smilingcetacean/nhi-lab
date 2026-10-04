#!/usr/bin/env python3
"""Performance suite: per-stage lifecycle latency over >=100 runs,
storage growth, and a response-payload-size proxy for network load.

CAVEAT: this is a SINGLE-MACHINE kind cluster on a
developer machine, both SPIRE server/agent, OPA, the policy engine, the
vending service and the resource sharing the same 16 cores and the same
container network. These numbers are RELATIVE (useful for comparing stages
against each other, or a future transport change against this baseline)
and NOT representative of any multi-node or production deployment.
No attempt is made to disguise or smooth that.

Measurement overhead vs. measured latency, made explicit per stage:
  - vend_call_wall_s: HARNESS-measured wall clock around the `parentsim vend`
    kubectl exec, i.e. kubectl-exec overhead + network + the full
    attest+vend server-side work. This is an UPPER BOUND on the true
    attest+vend latency, inflated by kubectl exec's own connection setup.
  - attest_stage_server_s / vend_stage_server_s: SERVER-measured, computed
    from the vending service's own audit event timestamps (attest-allow ->
    vend-allow, both within the same HTTP request) -- these are NOT
    contaminated by kubectl-exec overhead, and are the more trustworthy
    figures for the attest/vend split specifically.
  - operate_call_wall_s / dispose_call_wall_s: HARNESS-measured wall clock,
    same kubectl-exec-overhead caveat as vend_call_wall_s.
  - spire_attestation_wall_s: HARNESS-measured polling latency (0.5s poll
    interval) from vend response to the child's SPIRE agent actually
    producing the new SVID via the Workload API -- this is the SPIRE agent's
    own sync-interval-bound behaviour, not vending-service code, and is by
    far the largest and noisiest component of a full cycle (see results).
"""
from __future__ import annotations

import csv
import json
import statistics
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib import cluster as c  # noqa: E402

NS = "agents"
VS_NS = "nhi"
PARENT_ID = f"spiffe://{c.TRUST_DOMAIN}/agent/parent/exp-root"

N_RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 100


def db_footprint_bytes() -> int | None:
    """Sum of vending.db + -wal + -shm, read via an ephemeral debug
    container sharing the vending-service pod's PID namespace (the
    production image is distroless/no-shell by design: the highest-privilege credential in the lab gets no shell to
    attack from -- so this is the only way to inspect the file without
    changing that image)."""
    pod = c.running_pod(VS_NS, "app=vending-service")
    if not pod:
        return None
    # `kubectl debug` without -i/--attach creates the ephemeral container
    # detached and prints nothing but the container's name; the command
    # still runs to completion (a one-shot `sh -c ...`), so read its result
    # back with `kubectl logs` against that ephemeral container name.
    res = c.kubectl(
        "debug", "-n", VS_NS, pod, "--image=busybox:1.36", "--target=vending-service",
        "--", "sh", "-c",
        "cat /proc/1/root/var/lib/vending-service/vending.db* 2>/dev/null | wc -c",
        check=False, timeout=30,
    )
    import re as _re
    m = _re.search(r"debugger-[a-z0-9]+", (res.stdout or "") + (res.stderr or ""))
    if not m:
        return None
    debugger_name = m.group(0)
    for _ in range(10):
        time.sleep(1)
        logs = c.kubectl("logs", "-n", VS_NS, pod, "-c", debugger_name, check=False, timeout=15)
        out = (logs.stdout or "").strip()
        if out.isdigit():
            return int(out)
    return None


def percentile(data: list[float], p: float) -> float:
    if not data:
        return float("nan")
    s = sorted(data)
    k = (len(s) - 1) * p
    f, c_ = int(k), min(int(k) + 1, len(s) - 1)
    if f == c_:
        return s[f]
    return s[f] + (s[c_] - s[f]) * (k - f)


def summarize(name: str, values: list[float]) -> dict:
    if not values:
        return {"stage": name, "n": 0}
    return {
        "stage": name, "n": len(values),
        "mean_s": round(statistics.mean(values), 4),
        "stdev_s": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
        "min_s": round(min(values), 4),
        "p50_s": round(percentile(values, 0.50), 4),
        "p95_s": round(percentile(values, 0.95), 4),
        "p99_s": round(percentile(values, 0.99), 4),
        "max_s": round(max(values), 4),
    }


def main() -> int:
    print(f"== performance suite: {N_RUNS} full lifecycle runs ==")
    parent_pod = c.wait_for_pod(NS, "app=experiments-parent")
    child_pod = c.wait_for_pod(NS, "app=experiments-child")
    print(f"parent={parent_pod} child={child_pod}")

    footprint_before = db_footprint_bytes()
    print(f"delegation store footprint before run: {footprint_before} bytes")

    rows: list[dict] = []
    failures = 0

    for i in range(N_RUNS):
        rid = uuid.uuid4().hex[:10]
        child_id = f"{PARENT_ID}/child/perf-{rid}"
        row: dict = {"run": i}

        t0 = time.monotonic()
        r = c.parentsim(
            NS, parent_pod, "vend",
            f"-child-path-hint=child/perf-{rid}",
            "-scopes=resource:read:datasetA",
            "-task-context=experiment performance run",
            "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-child",
            "-ttl=120",
            f"-nonce=perf_{rid}",
        )
        row["vend_call_wall_s"] = round(time.monotonic() - t0, 4)
        row["vend_http_code"] = r.code
        row["vend_response_bytes"] = len(r.body.encode())

        if r.code != 201:
            row["ok"] = False
            row["error"] = "vend failed: " + r.body[:200]
            rows.append(row)
            failures += 1
            continue
        chain_id = json.loads(r.body)["chain_id"]
        row["chain_id"] = chain_id

        # server-side attest/vend split, from this service's own audit
        # timestamps (RFC3339 nano, UTC) -- avoids kubectl-exec overhead.
        # Retried briefly: `kubectl logs` occasionally lags the container's
        # own stdout flush by a few hundred ms, which otherwise drops a
        # handful of runs' delta out of the sample for a reason unrelated to
        # the system under test.
        ev_attest = ev_vend = None
        for _ in range(10):
            events = c.audit_lines(VS_NS, "app=vending-service", "vending-service", tail=40)
            ev_vend = c.find_event(events, chain_id=chain_id, stage="vend", outcome="allow")
            if ev_vend:
                # the matching attest event is the allow-attest immediately
                # preceding this run's vend event in the same log window
                idx = events.index(ev_vend)
                for j in range(idx - 1, -1, -1):
                    if events[j].get("stage") == "attest" and events[j].get("outcome") == "allow":
                        ev_attest = events[j]
                        break
                break
            time.sleep(0.5)
        if ev_attest and ev_vend:
            try:
                ta = time.strptime(ev_attest["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")
                tv = time.strptime(ev_vend["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")
                # sub-second component from the fractional part, since
                # time.strptime truncates it
                fa = float("0." + ev_attest["timestamp"][20:29]) if "." in ev_attest["timestamp"] else 0.0
                fv = float("0." + ev_vend["timestamp"][20:29]) if "." in ev_vend["timestamp"] else 0.0
                dt = (time.mktime(tv) + fv) - (time.mktime(ta) + fa)
                row["attest_to_vend_audit_delta_s"] = round(max(dt, 0.0), 4)
            except Exception:
                row["attest_to_vend_audit_delta_s"] = None
        else:
            row["attest_to_vend_audit_delta_s"] = None

        # attest: poll until the child pod's SPIRE agent actually presents
        # the new SVID via the Workload API
        t1 = time.monotonic()
        got_svid = False
        for _ in range(30):
            out = c.parentsim(NS, child_pod, "x509-check")
            if child_id in out.body:
                got_svid = True
                break
            time.sleep(0.5)
        row["spire_attestation_wall_s"] = round(time.monotonic() - t1, 4)
        row["got_svid"] = got_svid

        # operate
        t2 = time.monotonic()
        op = c.parentsim(NS, child_pod, "call", f"-call-audience={c.RESOURCE_AUD}", f"-call-url={c.RESOURCE_URL}/datasets/A")
        row["operate_call_wall_s"] = round(time.monotonic() - t2, 4)
        row["operate_http_code"] = op.code
        row["operate_response_bytes"] = len(op.body.encode())

        # dispose
        t3 = time.monotonic()
        dp = c.parentsim(NS, parent_pod, "dispose", f"-chain-id={chain_id}")
        row["dispose_call_wall_s"] = round(time.monotonic() - t3, 4)
        row["dispose_http_code"] = dp.code
        row["dispose_response_bytes"] = len(dp.body.encode())

        row["ok"] = got_svid and (op.code == 200) and (dp.code == 200)
        if not row["ok"]:
            failures += 1
        rows.append(row)
        if (i + 1) % 10 == 0:
            print(f"  ... {i + 1}/{N_RUNS} runs complete ({failures} failures so far)")

    footprint_after = db_footprint_bytes()
    print(f"delegation store footprint after run: {footprint_after} bytes")

    out_dir = Path(__file__).parent / "results" / "latest"
    out_dir.mkdir(parents=True, exist_ok=True)

    fieldnames = ["run", "chain_id", "ok", "error",
                  "vend_call_wall_s", "vend_http_code", "vend_response_bytes",
                  "attest_to_vend_audit_delta_s",
                  "spire_attestation_wall_s", "got_svid",
                  "operate_call_wall_s", "operate_http_code", "operate_response_bytes",
                  "dispose_call_wall_s", "dispose_http_code", "dispose_response_bytes"]
    with open(out_dir / "performance_runs.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)

    ok_rows = [r for r in rows if r.get("ok")]
    summary = {
        "generated_at": c.now_iso(),
        "n_runs": N_RUNS,
        "n_ok": len(ok_rows),
        "n_failures": failures,
        "note": "single-machine kind cluster; figures are RELATIVE, not absolute",
        "storage": {
            "delegation_store_bytes_before": footprint_before,
            "delegation_store_bytes_after": footprint_after,
            "delta_bytes": (footprint_after - footprint_before) if (footprint_before is not None and footprint_after is not None) else None,
            "delta_bytes_per_delegation": round((footprint_after - footprint_before) / len(ok_rows), 1) if (footprint_before is not None and footprint_after is not None and ok_rows) else None,
            "method": "sum of vending.db + vending.db-wal + vending.db-shm (WAL mode -- most recent writes live in the -wal file until a checkpoint), read via an ephemeral busybox debug container sharing the vending-service pod's PID namespace (/proc/1/root), since the production image is distroless with no shell (it holds the lab's highest-privilege credential).",
            "caveat": "SQLite WAL-mode file size is NOT linear in row count between checkpoints -- the -wal file grows in fixed page increments and is periodically truncated on checkpoint, so 'bytes per delegation' from one run's before/after delta is a noisy upper-bound estimate of true marginal row cost, not a precise per-row figure. Reported as measured, not smoothed.",
        },
        "network_load_proxy": {
            "note": "NOT a packet capture. Response body byte counts per stage, as a lower-bound proxy for payload size only -- excludes TLS/HTTP/TCP/IP framing overhead, mTLS handshakes to OPA, the SPIRE Workload API's own gRPC traffic, and kubectl's own transport. Single-node kind uses the loopback/bridge network, not a real multi-host network, so absolute bandwidth numbers would be meaningless anyway.",
            "vend_response_bytes": summarize("vend_response_bytes", [r["vend_response_bytes"] for r in ok_rows]) if ok_rows else None,
            "operate_response_bytes": summarize("operate_response_bytes", [r["operate_response_bytes"] for r in ok_rows]) if ok_rows else None,
            "dispose_response_bytes": summarize("dispose_response_bytes", [r["dispose_response_bytes"] for r in ok_rows]) if ok_rows else None,
        },
        "stage_latency": {
            "vend_call_wall_s (harness-measured, includes kubectl-exec overhead)": summarize("vend_call_wall_s", [r["vend_call_wall_s"] for r in ok_rows]),
            "attest_to_vend_audit_delta_s (server-measured, attest allow -> vend allow)": summarize("attest_to_vend_audit_delta_s", [r["attest_to_vend_audit_delta_s"] for r in ok_rows if r.get("attest_to_vend_audit_delta_s") is not None]),
            "spire_attestation_wall_s (harness-measured, SPIRE agent sync-interval bound)": summarize("spire_attestation_wall_s", [r["spire_attestation_wall_s"] for r in ok_rows]),
            "operate_call_wall_s (harness-measured)": summarize("operate_call_wall_s", [r["operate_call_wall_s"] for r in ok_rows]),
            "dispose_call_wall_s (harness-measured)": summarize("dispose_call_wall_s", [r["dispose_call_wall_s"] for r in ok_rows]),
        },
    }
    (out_dir / "performance_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print(f"\nwrote {out_dir}/performance_runs.csv, performance_summary.json")
    print(f"\n{len(ok_rows)}/{N_RUNS} runs OK, {failures} failures")
    print(json.dumps(summary["stage_latency"], indent=2, default=str))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
