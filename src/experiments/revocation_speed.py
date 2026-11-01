#!/usr/bin/env python3
"""Revocation speed: how long after a parent revokes C does G's next request fail?

`make revocation-speed` is the entry point. Not part of `make experiments`.

Each trial builds the chain P -> C -> G on the experiment fixtures (the same
pods multi_hop.py and verify-disposal.sh use), confirms G is allowed, then has
P revoke C with `DELETE /delegations/{chain_id}` and measures the time from the
moment P sends that DELETE to the moment G's loop receives its first 403.

Why the timing is taken inside the cluster
------------------------------------------
One `kubectl exec` costs 50-70 ms, the same order as the interval being
measured, so neither the polling nor the send timestamp can be taken from
this host. Instead:

  * G's pod runs `parentsim poll`: a loop that sends a request to the resource
    every `--interval-ms` (default 20 ms, so at least every 50 ms) with a JWT-SVID
    captured beforehand, and stops at the first 403.
  * P's pod runs `parentsim dispose-timed`, which stamps the wall clock just
    before it writes the DELETE and just after it reads the response headers.

Both stamp CLOCK_REALTIME in Unix nanoseconds. The kind nodes are containers on
one host and share its kernel clock, so the stamps from different pods are
directly comparable. That assumption would not hold on a cluster whose nodes
are separate machines.

Cross-check
-----------
The resource writes an audit event for every denial. The first `deny` event
for G's SPIFFE ID must fall inside the request that the poller saw denied
(between that request's send and receive stamps). It is the resource's own
account of when it refused G, independent of the poller's clock reads. The
policy engine's `dispose` event for C (the moment C's grant was removed from
OPA) is recorded too, to show where the time goes when a trial is slow.

Output (`results/<run-id>/`)
----------------------------
  revocation_speed.csv           one row per trial
  revocation_speed_summary.json  statistics, pass count, host inventory
  revocation_speed_raw.json      the raw poller / DELETE / audit records
"""
from __future__ import annotations

import argparse
import calendar
import csv
import json
import math
import os
import platform
import queue
import shutil
import statistics
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib import cluster as c  # noqa: E402

NS = "agents"
PARENT_ID = f"spiffe://{c.TRUST_DOMAIN}/agent/parent/exp-root"
THRESHOLD_MS = 1000.0

CSV_FIELDS = [
    "trial", "ok", "error", "c_chain_id", "g_chain_id", "g_spiffe_id",
    "delete_send_ns", "delete_recv_ns", "delete_status", "delete_round_trip_ms",
    "first_deny_send_ns", "first_deny_recv_ns", "first_deny_status",
    "delta_ms",                     # first 403 received - DELETE sent (the measured quantity)
    "delta_send_basis_ms",          # first 403 request sent - DELETE sent (lower bound)
    "poll_gap_mean_ms", "poll_gap_max_ms", "poll_last_gap_ms", "poll_count",
    "poll_latency_mean_ms", "poll_latency_max_ms", "poll_transport_errors",
    "audit_deny_ns", "audit_delta_ms", "audit_inside_denied_request",
    "policy_dispose_c_ms",          # C's grant removed (policy engine event) - DELETE sent
    "g_entry_gone", "c_entry_gone", "g_row_revoked_by_cascade",
    "under_1s",
]


# --------------------------------------------------------------------------
# small helpers

def ms(ns: int | float) -> float:
    return round(ns / 1e6, 3)


def parse_rfc3339_ns(ts: str) -> int:
    """'2026-11-01T02:21:13.383834826Z' -> Unix nanoseconds (UTC)."""
    base, _, frac = ts.rstrip("Z").partition(".")
    secs = calendar.timegm(time.strptime(base, "%Y-%m-%dT%H:%M:%S"))
    return secs * 1_000_000_000 + int((frac + "000000000")[:9])


def nearest_rank(sorted_vals: list[float], p: float) -> float:
    """Nearest-rank percentile: the smallest value with at least p% of the sample at or below it."""
    k = max(1, math.ceil(p / 100.0 * len(sorted_vals)))
    return sorted_vals[k - 1]


def wait_for_svid(pod: str, expect_id: str, timeout_s: float = 60.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if expect_id in c.parentsim(NS, pod, "x509-check").body:
            return True
        time.sleep(1.0)
    return False


def wait_no_identity(pod: str, timeout_s: float = 90.0) -> bool:
    """The agent has stopped issuing the pod any identity, so the next trial starts clean."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if '"error"' in c.parentsim(NS, pod, "x509-check").body:
            return True
        time.sleep(1.0)
    return False


def json_line(raw: str) -> dict | None:
    for ln in raw.splitlines():
        ln = ln.strip()
        if ln.startswith("{"):
            try:
                return json.loads(ln)
            except json.JSONDecodeError:
                continue
    return None


def vend(pod: str, hint: str, nonce: str, sa: str, scopes: str, ttl: int = 600):
    """Vend, retrying a transient policy-engine connect delay on a fresh nonce
    (the nonce is recorded before the policy engine is called)."""
    last = None
    for attempt in range(1, 5):
        n = nonce if attempt == 1 else f"{nonce}_r{attempt}"
        last = c.parentsim(
            NS, pod, "vend", f"-child-path-hint={hint}", f"-nonce={n}", f"-scopes={scopes}",
            "-task-context=revocation speed", f"-selectors=k8s:ns=agents,k8s:sa={sa}", f"-ttl={ttl}",
        )
        if last.code == 502 and "context deadline exceeded" in last.raw:
            time.sleep(3)
            continue
        break
    return last


class Poller:
    """`kubectl exec ... parentsim poll` running in the background, its JSON lines queued."""

    def __init__(self, pod: str, token: str, interval_ms: int, timeout_s: int):
        cmd = ["kubectl", "--context", c.KUBECTX, "exec", "-n", NS, pod, "-c", "parentsim", "--",
               "/parentsim", "poll", f"-call-url={c.RESOURCE_URL}/datasets/A", f"-bearer-token={token}",
               f"-poll-interval={interval_ms}ms", f"-poll-timeout={timeout_s}s"]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.q: "queue.Queue[str | None]" = queue.Queue()
        self.other: list[str] = []
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for ln in self.proc.stdout:
            self.q.put(ln)
        self.q.put(None)

    def next_event(self, timeout_s: float) -> dict | None:
        """The next JSON event, or None on timeout / end of output."""
        deadline = time.monotonic() + timeout_s
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            try:
                ln = self.q.get(timeout=left)
            except queue.Empty:
                return None
            if ln is None:
                return None
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    return json.loads(ln)
                except json.JSONDecodeError:
                    pass
            self.other.append(ln)

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()


def audit_events(selector: str, container: str) -> list[dict]:
    # --tail=-1: the default tail of 10 lines (and any small fixed tail) loses
    # events when the component is busy.
    return c.audit_lines("nhi", selector, container, tail=-1)


# --------------------------------------------------------------------------
# one trial

def run_trial(trial: int, run_id: str, pods: dict[str, str], interval_ms: int, settle_s: float) -> tuple[dict, dict]:
    row: dict = {k: "" for k in CSV_FIELDS}
    row["trial"] = trial
    raw: dict = {"trial": trial}
    tag = f"{run_id}-{trial:02d}"

    def fail(msg: str) -> tuple[dict, dict]:
        row["ok"], row["error"], row["under_1s"] = False, msg, False
        raw["error"] = msg
        return row, raw

    c_hint, g_hint = f"child/rs-c-{tag}", f"child/rs-g-{tag}"
    c_id = f"{PARENT_ID}/{c_hint}"
    g_id = f"{c_id}/{g_hint}"
    row["g_spiffe_id"] = g_id

    # --- P -> C -> G ------------------------------------------------------
    r = vend(pods["p"], c_hint, f"rs_c_{tag}", "nhi-exp-child", "resource:read:datasetA,resource:read:datasetB")
    if r.code != 201:
        return fail(f"vend C failed: {r.code} {r.raw[:200]}")
    c_chain = json.loads(r.body)["chain_id"]
    row["c_chain_id"] = c_chain
    if not wait_for_svid(pods["c"], c_id):
        return fail("C pod never obtained its SVID")
    r = vend(pods["c"], g_hint, f"rs_g_{tag}", "nhi-exp-grandchild", "resource:read:datasetA")
    if r.code != 201:
        return fail(f"vend G failed: {r.code} {r.raw[:200]}")
    g_chain = json.loads(r.body)["chain_id"]
    row["g_chain_id"] = g_chain
    if not wait_for_svid(pods["g"], g_id):
        return fail("G pod never obtained its SVID")

    # --- G is allowed, with a token captured now and replayed after the revoke
    # (once G's registration entry is gone it could not fetch a new one).
    token = c.exec_pod(NS, pods["g"], "parentsim", "/parentsim", "fetch-jwt", f"-call-audience={c.RESOURCE_AUD}").strip()
    if token.count(".") != 2 or " " in token:
        return fail(f"could not capture G's JWT-SVID: {token[:120]}")
    before = c.split_status_body(c.exec_pod(
        NS, pods["g"], "parentsim", "/parentsim", "bearer-call", f"-call-url={c.RESOURCE_URL}/datasets/A", f"-bearer-token={token}"))
    if before.code != 200:
        return fail(f"G was not allowed before the revoke: {before.code}")

    # --- start the in-pod poller and wait until it has been answered 200 -----
    poller = Poller(pods["g"], token, interval_ms, timeout_s=60)
    try:
        ready = poller.next_event(20)
        if not ready or ready.get("event") != "ready":
            return fail(f"poller never reported ready: {ready} {poller.other[-3:]}")
        time.sleep(settle_s)  # let the loop reach steady state before revoking

        # --- P revokes C, stamping the clock around the DELETE inside P's pod
        out = c.exec_pod(NS, pods["p"], "parentsim", "/parentsim", "dispose-timed", f"-chain-id={c_chain}")
        dele = json_line(out)
        raw["delete"] = dele
        if not dele or dele.get("status") != 200:
            return fail(f"timed DELETE failed: {out[:200]}")

        final = poller.next_event(30)
        raw["poll_ready"], raw["poll_final"] = ready, final
        if not final or final.get("event") != "denied":
            return fail(f"poller did not report a denial: {final}")
    finally:
        poller.close()

    send_ns, recv_ns = dele["send_ns"], dele["recv_ns"]
    row.update(
        delete_send_ns=send_ns, delete_recv_ns=recv_ns, delete_status=dele["status"],
        delete_round_trip_ms=ms(dele["round_trip_ns"]),
        first_deny_send_ns=final["send_ns"], first_deny_recv_ns=final["recv_ns"], first_deny_status=final["status"],
        delta_ms=ms(final["recv_ns"] - send_ns),
        delta_send_basis_ms=ms(final["send_ns"] - send_ns),
        poll_gap_mean_ms=ms(final.get("gap_mean_ns", 0)), poll_gap_max_ms=ms(final.get("gap_max_ns", 0)),
        poll_last_gap_ms=ms(final["send_ns"] - final.get("last_allowed_send_ns", final["send_ns"])),
        poll_count=final.get("polls", 0),
        poll_latency_mean_ms=ms(final.get("latency_mean_ns", 0)), poll_latency_max_ms=ms(final.get("latency_max_ns", 0)),
        poll_transport_errors=final.get("transport_errors", 0),
    )

    # --- cross-check: the resource's own first deny audit event for G --------
    deny = None
    for _ in range(10):
        evs = [e for e in audit_events("app=resource", "resource")
               if e.get("actor_spiffe_id") == g_id and e.get("outcome") == "deny"]
        if evs:
            deny = min(evs, key=lambda e: parse_rfc3339_ns(e["timestamp"]))
            break
        time.sleep(0.5)
    raw["resource_first_deny"] = deny
    if deny:
        a_ns = parse_rfc3339_ns(deny["timestamp"])
        slack = 2_000_000  # 2 ms of clock-read skew between the two processes
        row["audit_deny_ns"] = a_ns
        row["audit_delta_ms"] = ms(a_ns - send_ns)
        row["audit_inside_denied_request"] = (final["send_ns"] - slack) <= a_ns <= (final["recv_ns"] + slack)

    # --- where the time went: when C's grant left OPA (policy engine event) --
    pe = [e for e in audit_events("app=policy-engine", "policy-engine")
          if e.get("stage") == "dispose" and e.get("chain_id") == c_chain and e.get("outcome") == "allow"]
    raw["policy_dispose_c"] = pe[0] if pe else None
    if pe:
        row["policy_dispose_c_ms"] = ms(parse_rfc3339_ns(pe[0]["timestamp"]) - send_ns)

    # --- the rest of the cascade state, as it stands once the DELETE returned
    row["g_entry_gone"] = not c.entry_exists(g_id)
    row["c_entry_gone"] = not c.entry_exists(c_id)
    rec = c.parentsim(NS, pods["p"], "get", f"-chain-id={g_chain}")
    body = json.loads(rec.body) if rec.code == 200 else {}
    row["g_row_revoked_by_cascade"] = bool(body.get("revoked_at")) and body.get("revocation_reason") == f"ancestor_revoked: {c_chain}"

    # ok: a valid measurement (DELETE 200, a 403 seen by the poller). Whether the
    # cascade state and the audit cross-check also held is reported separately.
    row["ok"] = True
    row["under_1s"] = row["delta_ms"] < THRESHOLD_MS
    return row, raw


# --------------------------------------------------------------------------
# host inventory and summary

def sh(*cmd: str) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (res.stdout or res.stderr).strip()
    except Exception as exc:  # noqa: BLE001 - inventory is best effort
        return f"unavailable: {exc}"


def host_inventory() -> dict:
    cpu = ""
    try:
        for ln in Path("/proc/cpuinfo").read_text().splitlines():
            if ln.startswith("model name"):
                cpu = ln.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    mem_kb = None
    try:
        for ln in Path("/proc/meminfo").read_text().splitlines():
            if ln.startswith("MemTotal:"):
                mem_kb = int(ln.split()[1])
                break
    except OSError:
        pass
    try:
        kubectl_ver = json.loads(sh("kubectl", "version", "--client", "-o", "json"))["clientVersion"]["gitVersion"]
    except (ValueError, KeyError):
        kubectl_ver = "unavailable"
    return {
        "cpu_model": cpu,
        "cpu_cores": os.cpu_count(),
        "memory_total_gib": round(mem_kb / 1024 / 1024, 1) if mem_kb else None,
        "kernel": platform.release(),
        "os": platform.system(),
        "python": platform.python_version(),
        "docker_server": sh("docker", "version", "--format", "{{.Server.Version}}"),
        "kind": sh("kind", "version"),
        "kubectl_client": kubectl_ver,
        "kube_context": c.KUBECTX,
        "nodes": sh("kubectl", "--context", c.KUBECTX, "get", "nodes", "-o",
                    "custom-columns=NAME:.metadata.name,KUBELET:.status.nodeInfo.kubeletVersion,KERNEL:.status.nodeInfo.kernelVersion"),
        "load_average_start": None,  # filled by main()
        "load_average_end": None,
    }


def summarise(rows: list[dict], args: argparse.Namespace, inv: dict, started: str, finished: str) -> dict:
    deltas = sorted(float(r["delta_ms"]) for r in rows if r["ok"])
    n_ok = len(deltas)
    s: dict = {
        "run_id": args.run_id, "started_at": started, "finished_at": finished,
        "trials_requested": args.trials, "trials_completed": n_ok, "trials_failed": len(rows) - n_ok,
        "poll_interval_target_ms": args.interval_ms, "threshold_ms": THRESHOLD_MS,
        "percentile_method": "nearest-rank", "stdev_method": "sample (n-1)",
        "pass_count": sum(1 for r in rows if r["under_1s"]),
        "target_met": bool(rows) and len(rows) == args.trials and all(r["under_1s"] for r in rows),
    }
    ok_rows = [r for r in rows if r["ok"]]
    s["cascade_state_and_audit_ok_in_every_trial"] = bool(ok_rows) and len(ok_rows) == args.trials and all(
        r["g_entry_gone"] and r["c_entry_gone"] and r["g_row_revoked_by_cascade"]
        and r["audit_inside_denied_request"] is True for r in ok_rows)
    if deltas:
        s.update(
            n=n_ok, p50_ms=nearest_rank(deltas, 50), p95_ms=nearest_rank(deltas, 95), max_ms=deltas[-1],
            min_ms=deltas[0], mean_ms=round(statistics.fmean(deltas), 3),
            stdev_ms=round(statistics.stdev(deltas), 3) if n_ok > 1 else 0.0,
        )
        ok_rows = [r for r in rows if r["ok"]]
        s["achieved_poll_gap_ms"] = {
            "mean_of_trial_means": round(statistics.fmean(float(r["poll_gap_mean_ms"]) for r in ok_rows), 3),
            "max_of_trial_maxes": max(float(r["poll_gap_max_ms"]) for r in ok_rows),
            "max_gap_straddling_the_revoke": max(float(r["poll_last_gap_ms"]) for r in ok_rows),
            "trials_with_mean_gap_over_50ms": sum(1 for r in ok_rows if float(r["poll_gap_mean_ms"]) > 50),
        }
        s["delete_round_trip_ms"] = {
            "p50": nearest_rank(sorted(float(r["delete_round_trip_ms"]) for r in ok_rows), 50),
            "max": max(float(r["delete_round_trip_ms"]) for r in ok_rows),
        }
        audit = [r for r in ok_rows if r["audit_delta_ms"] != ""]
        s["resource_audit_crosscheck"] = {
            "trials_with_audit_event": len(audit),
            "trials_audit_inside_denied_request": sum(1 for r in audit if r["audit_inside_denied_request"]),
            "max_abs_difference_to_poller_ms": max(
                (abs(float(r["audit_delta_ms"]) - float(r["delta_ms"])) for r in audit), default=None),
        }
        s["cascade_state_after_delete"] = {
            "g_entry_gone": sum(1 for r in ok_rows if r["g_entry_gone"]),
            "c_entry_gone": sum(1 for r in ok_rows if r["c_entry_gone"]),
            "g_row_revoked_by_cascade": sum(1 for r in ok_rows if r["g_row_revoked_by_cascade"]),
        }
        pe = [float(r["policy_dispose_c_ms"]) for r in ok_rows if r["policy_dispose_c_ms"] != ""]
        if pe:
            s["policy_dispose_c_after_send_ms"] = {"p50": nearest_rank(sorted(pe), 50), "max": max(pe)}
    s["host"] = inv
    return s


# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--trials", type=int, default=int(os.environ.get("REVOCATION_TRIALS", "30")))
    ap.add_argument("--interval-ms", type=int, default=20, help="G's poll interval (must be <= 50)")
    ap.add_argument("--settle-s", type=float, default=0.5, help="polling time before the DELETE is sent")
    ap.add_argument("--run-id", default=time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-revocation-speed")
    args = ap.parse_args()
    if not 1 <= args.interval_ms <= 50:
        ap.error("--interval-ms must be between 1 and 50 (the measurement requires polling at least every 50 ms)")

    print(f"== revocation speed: {args.trials} trials, G polls every {args.interval_ms} ms ==")
    pods = {
        "p": c.wait_for_pod(NS, "app=experiments-parent"),
        "c": c.wait_for_pod(NS, "app=experiments-child"),
        "g": c.wait_for_pod(NS, "app=experiments-grandchild"),
    }
    print(f"P={pods['p']} C={pods['c']} G={pods['g']}")

    # The fixture pods run a fixed image tag; one started before `poll` existed
    # does not have it.
    probe = c.parentsim(NS, pods["g"], "poll")
    if "poll requires" not in probe.raw:
        print("FATAL: the fixture pods run a parentsim image without the `poll` mode.\n"
              "       Rebuild and recreate them:  make experiments-fixtures-down experiments-fixtures-up", file=sys.stderr)
        return 2
    for who in ("c", "g"):
        if not wait_no_identity(pods[who]):
            print(f"FATAL: {who.upper()} pod still holds an identity from an earlier run", file=sys.stderr)
            return 2

    inv = host_inventory()
    inv["load_average_start"] = [round(x, 2) for x in os.getloadavg()]
    started = c.now_iso()

    run_id = uuid.uuid4().hex[:6]
    rows: list[dict] = []
    raws: list[dict] = []
    for t in range(1, args.trials + 1):
        t0 = time.monotonic()
        try:
            row, raw = run_trial(t, run_id, pods, args.interval_ms, args.settle_s)
        except Exception as exc:  # noqa: BLE001 - one bad trial must not lose the others
            row = {k: "" for k in CSV_FIELDS}
            row.update(trial=t, ok=False, error=f"exception: {exc}", under_1s=False)
            raw = {"trial": t, "error": str(exc)}
        rows.append(row)
        raws.append(raw)
        shown = f"{row['delta_ms']:.1f} ms" if row["ok"] else f"FAILED ({row['error']})"
        print(f"  trial {t:2d}/{args.trials}: {shown}  [{time.monotonic() - t0:.1f}s]", flush=True)
        # Leave both pods without an identity so the next trial starts clean.
        wait_no_identity(pods["c"])
        wait_no_identity(pods["g"])

    inv["load_average_end"] = [round(x, 2) for x in os.getloadavg()]
    summary = summarise(rows, args, inv, started, c.now_iso())

    out_dir = Path(__file__).parent / "results" / args.run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "revocation_speed.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    (out_dir / "revocation_speed_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    (out_dir / "revocation_speed_raw.json").write_text(json.dumps(raws, indent=2, default=str))

    print()
    for k in ("trials_completed", "trials_failed", "p50_ms", "p95_ms", "max_ms", "mean_ms", "stdev_ms", "pass_count"):
        if k in summary:
            print(f"  {k:18s} {summary[k]}")
    print(f"  target (< {THRESHOLD_MS:.0f} ms in {args.trials} of {args.trials}): {'MET' if summary['target_met'] else 'NOT MET'}")
    print(f"results: {out_dir}")
    print(f"  cascade state + resource audit cross-check in every trial: "
          f"{'yes' if summary['cascade_state_and_audit_ok_in_every_trial'] else 'NO'}")
    return 0 if summary["target_met"] and summary["cascade_state_and_audit_ok_in_every_trial"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
