#!/usr/bin/env python3
"""Storage growth: how much state do the lab's stores hold as the number of vended children grows?

Not part of `make experiments`. Run it by hand against a throwaway cluster:

  cd src/experiments && CLUSTER_NAME=nhi-lab KUBECTX=kind-<name> TRUST_DOMAIN=lab.local \\
      uv run python3 storage_growth.py --phase accumulate --n 200 --step 25

The independent variable is N, the number of children the root parent `exp-root`
(pod `experiments-parent`) vends, over `kubectl exec` with the existing
`parentsim` modes `vend` and `dispose -chain-id`. Every child gets inputs of the
same width, so every vend adds a row of the same size:

  -child-path-hint=child/sg-NNNNN   -selectors=k8s:ns=agents,k8s:pod-name=sg-NNNNN
  -scopes=resource:read:datasetA    -task-context="storage growth"   -ttl=3600
  -nonce=sg-<acc|chu>-NNNNN         (5-digit zero-padded index; no such pod exists)

Two phases, each meant for its own fresh cluster:

  accumulate  vend n children with no disposal, then dispose all of them, oldest
              first. Checkpoints at live N = {0, 1, 2} U {k*step} U {n}, then at
              disposed D = {1, 2} U {k*step} U {n} (D = 0 is the N = n checkpoint).
  churn       n cycles of vend-then-dispose with a new child index each cycle.
              Checkpoints at cycles C = {0, 1, 2} U {k*step} U {n}.

What the stores do, from the code:

  SPIRE server   `spire-data` PVC: datastore.sqlite3 (WAL mode) and keys.json. A
                 vend creates one registration entry (BatchCreateEntry) and a
                 dispose deletes it; SPIRE writes an entry-event row for each.
  vending svc    `vending-data` PVC: vending.db (WAL) and audit.jsonl. A vend
                 inserts a `delegations` row and a `used_nonces` row; a dispose
                 only sets `revoked_at`, so delegation rows are never deleted.
  OPA            memory only. The policy engine PUTs one Rego module
                 `nhi_grants_*` per vend and DELETEs it on dispose, and reads all
                 of them back (GET /v1/policies, at most 4 MiB of the response)
                 at the start of every vend.

At every checkpoint (after a short pause so in-flight writes land) it records:

  1. bytes on disk of each PVC directory, from outside the pods
     (`docker exec <node> find ... -exec stat`): apparent and allocated bytes of
     every file, per component and in total;
  2. the logical SQLite content: each database is copied with its -wal/-shm by
     streaming `tar` out of the node into a scratch directory (nothing is written
     on the node) and opened there: page_size, page_count, freelist_count,
     journal_mode, used bytes, a `dbstat` breakdown per table and index, a row
     count for every table and `PRAGMA quick_check` (retaken once on failure);
  3. each relevant container's writable-layer bytes and inodes and its memory
     working set (`crictl stats`);
  4. OPA's grant modules: the live count from OPA's own request log (2xx PUTs
     minus DELETEs of nhi_grants_*), cross-checked against the policy engine's
     audit events and the vending database's unrevoked rows; the size of
     `GET /v1/policies` (`resp_bytes` of OPA's "Sent response." line, one per
     vend); and, when OPA's diagnostic listener can be reached, its Go heap;
  5. `spire-server entry count`, and the host wall time of every vend/dispose.

Idle control: after the first checkpoint (no children yet) and again after the last
one, the run waits --idle-s (30 s) with no operations and takes an ordinary checkpoint
(phase idle-start / idle-end). The summary reports each metric's change over those
windows in bytes per second, so growth from operations can be told from growth over
time (the SPIRE server writes in the background). Idle rows are left out of the fits.

Outputs, in results/<run-id>/:

  storage_growth.csv           one row per checkpoint
  storage_growth_tables.csv    long form: checkpoint x database x table/index
  storage_growth_ops.csv       one row per vend or dispose
  storage_growth_summary.json  fits, rows per child, drain reclaim, OPA bytes per
                               module and the 4 MiB projection, the checks block,
                               host inventory
  storage_growth_raw.json      the raw stat, dbstat, crictl and metrics output and
                               the op responses
  provenance.json              how the run was made
  logs/{vending-service,spire-server,policy-engine,opa}/step-NN.log
                               each container's log lines between consecutive
                               checkpoints (contiguous windows), prefixed with the
                               container runtime's timestamp
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import re
import select
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib import cluster as c  # noqa: E402
from revocation_speed import NS, PARENT_ID, host_inventory, parse_rfc3339_ns, wait_for_svid  # noqa: E402
from vend_to_svid import component_logs  # noqa: E402

SCOPES = "resource:read:datasetA"
TASK_CONTEXT = "storage growth"
OPA_READ_LIMIT = 4 << 20  # src/policy-engine/opa.go: io.LimitReader(resp.Body, 4<<20)

# name -> (namespace, pod selector or fixed pod, container, PVC volume name or None)
COMPONENTS = {
    "spire-server": ("spire", "spire-server-0", "spire-server", "spire-data"),
    "vending-service": ("nhi", "app=vending-service", "vending-service", "vending-data"),
    "policy-engine": ("nhi", "app=policy-engine", "policy-engine", None),
    "opa": ("opa", "app=opa", "opa", None),
}
DBS = {  # database -> (component, file name)
    "spire": ("spire-server", "datastore.sqlite3"),
    "vending": ("vending-service", "vending.db"),
}


def col(s: str) -> str:
    return re.sub(r"\W+", "_", s).strip("_")


def sh(*cmd: str, timeout: int = 60, check: bool = True, text: bool = True) -> subprocess.CompletedProcess:
    res = subprocess.run(cmd, capture_output=True, text=text, timeout=timeout)
    if check and res.returncode != 0:
        err = res.stderr if text else res.stderr.decode(errors="replace")
        raise RuntimeError(f"{' '.join(cmd)} failed ({res.returncode}): {err}")
    return res


def checkpoint_set(n: int, step: int) -> set[int]:
    return {k for k in ({0, 1, 2} | set(range(0, n + 1, step)) | {n}) if k <= n}


# --------------------------------------------------------------------------
# where things are

def discover() -> dict:
    """Pods, nodes and PVC host directories of the four components."""
    out: dict = {}
    for name, (ns, sel, container, vol) in COMPONENTS.items():
        pod = sel if "=" not in sel else c.wait_for_pod(ns, sel, timeout_s=60)
        info = json.loads(c.kubectl("get", "pod", "-n", ns, pod, "-o", "json").stdout)
        d = {"ns": ns, "pod": pod, "container": container, "node": info["spec"]["nodeName"],
             "uid": info["metadata"]["uid"]}
        if vol:
            claim = next(v["persistentVolumeClaim"]["claimName"] for v in info["spec"]["volumes"]
                         if v["name"] == vol and "persistentVolumeClaim" in v)
            pvc = json.loads(c.kubectl("get", "pvc", "-n", ns, claim, "-o", "json").stdout)
            pv = json.loads(c.kubectl("get", "pv", pvc["spec"]["volumeName"], "-o", "json").stdout)
            spec = pv["spec"]
            d["pvc"] = claim
            d["pv"] = pv["metadata"]["name"]
            d["pv_capacity"] = pv["spec"].get("capacity", {}).get("storage")
            d["dir"] = (spec.get("hostPath") or spec.get("local") or {}).get("path")
            if not d["dir"]:
                raise RuntimeError(f"PV {d['pv']} has neither hostPath nor local path")
        out[name] = d
    return out


def restarts(targets: dict) -> dict:
    res = {}
    for name, t in targets.items():
        info = json.loads(c.kubectl("get", "pod", "-n", t["ns"], t["pod"], "-o", "json").stdout)
        cs = {s["name"]: s["restartCount"] for s in info["status"].get("containerStatuses", [])}
        res[name] = {"pod": t["pod"], "uid": info["metadata"]["uid"], "restarts": cs}
    return res


# --------------------------------------------------------------------------
# measurements

def stat_dir(node: str, d: str) -> list[dict]:
    """Apparent (%s) and allocated (%b * %B) bytes of every file of a PVC directory."""
    res = sh("docker", "exec", node, "find", d, "-maxdepth", "1", "-type", "f",
             "-exec", "stat", "-c", "%n|%s|%b|%B", "{}", "+")
    files = []
    for ln in res.stdout.splitlines():
        path, size, blocks, bsize = ln.rsplit("|", 3)
        files.append({"name": os.path.basename(path), "apparent": int(size), "alloc": int(blocks) * int(bsize)})
    return sorted(files, key=lambda f: f["name"])


def snapshot(node: str, d: str, base: str, names: list[str], scratch: Path) -> Path:
    """Copy the database and its -wal/-shm into a fresh scratch directory by streaming
    tar out of the node. Nothing is written on the node."""
    want = [f for f in names if f == base or f in (base + "-wal", base + "-shm")]
    dest = Path(tempfile.mkdtemp(dir=scratch))
    res = sh("docker", "exec", node, "tar", "-C", d, "-cf", "-", *want, text=False, timeout=120)
    with tarfile.open(fileobj=io.BytesIO(res.stdout), mode="r:") as tf:
        tf.extractall(dest, filter="data")
    return dest / base


def inspect_db(path: Path) -> dict:
    """Logical content of a database copy."""
    con = sqlite3.connect(str(path))
    try:
        pragma = lambda p: con.execute(f"PRAGMA {p}").fetchone()[0]  # noqa: E731
        info = {k: pragma(k) for k in ("page_size", "page_count", "freelist_count", "journal_mode")}
        info["used_bytes"] = (info["page_count"] - info["freelist_count"]) * info["page_size"]
        info["freelist_bytes"] = info["freelist_count"] * info["page_size"]
        info["quick_check"] = [r[0] for r in con.execute("PRAGMA quick_check").fetchall()]
        kinds = {n: (t, tbl) for n, t, tbl in con.execute("SELECT name, type, tbl_name FROM sqlite_master")}
        rows = {n: con.execute(f'SELECT count(*) FROM "{n}"').fetchone()[0] for n, (t, _) in kinds.items() if t == "table"}
        extra = {}
        if "delegations" in rows:
            extra["live_delegations"] = con.execute("SELECT count(*) FROM delegations WHERE revoked_at IS NULL").fetchone()[0]
        objs = []
        for name, pages, size, unused in con.execute(
                "SELECT name, count(*), sum(pgsize), sum(unused) FROM dbstat GROUP BY name ORDER BY name"):
            kind, tbl = kinds.get(name, ("schema", name))
            objs.append({"name": name, "type": kind, "table": tbl, "rows": rows.get(name), "pages": pages,
                         "bytes": size, "unused": unused})
        info["dbstat_bytes"] = sum(o["bytes"] for o in objs)
        info["dbstat_unused_bytes"] = sum(o["unused"] for o in objs)
        info["rows"], info["objects"], info["extra"] = rows, objs, extra
        return info
    finally:
        con.close()


def db_snapshot_checked(node: str, d: str, base: str, names: list[str], scratch: Path) -> tuple[dict, list]:
    attempts = []
    info = {}
    for _ in range(2):
        p = snapshot(node, d, base, names, scratch)
        info = inspect_db(p)
        shutil.rmtree(p.parent, ignore_errors=True)
        attempts.append(info["quick_check"])
        if info["quick_check"] == ["ok"]:
            break
    info["quick_check_attempts"] = attempts
    return info, attempts


def crictl(targets: dict) -> dict:
    """Writable layer and memory working set of each component's container."""
    by_node: dict[str, list[dict]] = {}
    for node in {t["node"] for t in targets.values()}:
        by_node[node] = json.loads(sh("docker", "exec", node, "crictl", "stats", "-o", "json").stdout)["stats"]
    out = {}
    for name, t in targets.items():
        for s in by_node[t["node"]]:
            a = s["attributes"]
            if a["labels"].get("io.kubernetes.pod.name") == t["pod"] and a["metadata"]["name"] == t["container"]:
                out[name] = {"container_id": a["id"], "memory": s.get("memory"), "writableLayer": s.get("writableLayer")}
                break
        else:
            out[name] = None
    return out


def spire_entry_count() -> int | None:
    res = c.kubectl("exec", "-n", "spire", "spire-server-0", "-c", "spire-server", "--",
                    "/opt/spire/bin/spire-server", "entry", "count", check=False)
    m = re.search(r"(\d+)", res.stdout or "")
    return int(m.group(1)) if m else None


def opa_metrics(pod: str) -> dict:
    """go_memstats_* from OPA's diagnostic listener, through a port-forward. The listener
    requires a client certificate at the TLS handshake (like the API port), so an
    unauthenticated scrape is expected to fail; the result says why."""
    pf = subprocess.Popen(["kubectl", "--context", c.KUBECTX, "port-forward", "-n", "opa", f"pod/{pod}", ":8282"],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        port = None
        deadline = time.time() + 10
        while time.time() < deadline and port is None:
            if select.select([pf.stdout], [], [], 0.5)[0]:
                m = re.search(r"127\.0\.0\.1:(\d+)", pf.stdout.readline())
                port = int(m.group(1)) if m else None
        if port is None:
            return {"status": "error: port-forward did not come up"}
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with urllib.request.urlopen(f"https://127.0.0.1:{port}/metrics", context=ctx, timeout=5) as r:
                text = r.read().decode()
        except Exception as exc:  # noqa: BLE001 - recorded, not hidden
            return {"status": f"error: {type(exc).__name__}: {exc}"}
        vals = {}
        for ln in text.splitlines():
            m = re.match(r"(go_memstats_heap_inuse_bytes|go_memstats_alloc_bytes)\s+(\S+)$", ln)
            if m:
                vals[m.group(1)] = float(m.group(2))
        return {"status": "ok", **vals}
    finally:
        pf.terminate()
        try:
            pf.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pf.kill()


# --------------------------------------------------------------------------
# log parsing

def json_after_ts(ln: str) -> tuple[int, dict] | None:
    ts, _, rest = ln.partition(" ")
    if not rest.startswith("{"):
        return None
    try:
        return parse_rfc3339_ns(ts), json.loads(rest)
    except (ValueError, json.JSONDecodeError):
        return None


class OpaTracker:
    """Live nhi_grants_* modules, counted from OPA's request log: 2xx PUTs minus 2xx
    DELETEs. Also keeps every GET /v1/policies with its size and the live count at that moment."""

    def __init__(self) -> None:
        self.live = 0
        self.puts = 0
        self.deletes = 0
        self.gets: list[dict] = []
        self.pending: dict[int, tuple[str, str]] = {}
        self.sent = 0

    def feed(self, lines: list[str]) -> None:
        for ln in lines:
            parsed = json_after_ts(ln)
            if not parsed:
                continue
            ts, ev = parsed
            msg = ev.get("msg")
            if msg == "Received request.":
                self.pending[ev["req_id"]] = (ev.get("req_method"), ev.get("req_path"))
            elif msg == "Sent response.":
                self.sent += 1
                method, path = self.pending.pop(ev["req_id"], (ev.get("req_method"), ev.get("req_path")))
                status = ev.get("resp_status")
                ok = isinstance(status, int) and 200 <= status < 300
                if method == "GET" and path in ("/v1/policies", "/v1/policies/"):
                    self.gets.append({"ts_ns": ts, "req_id": ev["req_id"], "status": status,
                                      "resp_bytes": ev.get("resp_bytes"), "live_modules_at_get": self.live})
                elif path and path.startswith("/v1/policies/nhi_grants_") and ok:
                    if method == "PUT":
                        self.puts += 1
                        self.live += 1
                    elif method == "DELETE":
                        self.deletes += 1
                        self.live -= 1


class AuditTracker:
    """Live grants by the policy engine's own audit events: allowed vends minus allowed disposes."""

    def __init__(self) -> None:
        self.vend = self.dispose = 0
        self.denies = 0

    def feed(self, lines: list[str]) -> None:
        for ln in lines:
            parsed = json_after_ts(ln)
            if not parsed:
                continue
            ev = parsed[1]
            if ev.get("stage") not in ("vend", "dispose") or "chain_id" not in ev:
                continue
            if ev.get("outcome") == "allow":
                if ev["stage"] == "vend":
                    self.vend += 1
                else:
                    self.dispose += 1
            else:
                self.denies += 1

    @property
    def live(self) -> int:
        return self.vend - self.dispose


def full_log(t: dict) -> list[str]:
    res = c.kubectl("logs", "-n", t["ns"], t["pod"], "-c", t["container"], "--timestamps", check=False, timeout=120)
    return (res.stdout or "").splitlines()


# --------------------------------------------------------------------------
# operations

class OpError(RuntimeError):
    pass


def vend(pod: str, idx: int, tag: str, ttl: int) -> dict:
    name = f"sg-{idx:05d}"
    t_ns = time.time_ns()
    t0 = time.perf_counter()
    res = c.parentsim(NS, pod, "vend", f"-child-path-hint=child/{name}", f"-nonce=sg-{tag}-{idx:05d}",
                      f"-scopes={SCOPES}", f"-task-context={TASK_CONTEXT}",
                      f"-selectors=k8s:ns={NS},k8s:pod-name={name}", f"-ttl={ttl}")
    ms = (time.perf_counter() - t0) * 1000
    end_ns = time.time_ns()
    try:
        body = json.loads(res.body)
    except json.JSONDecodeError:
        body = {}
    return {"op": "vend", "index": idx, "chain_id": body.get("chain_id", ""), "status": res.code,
            "host_ms": round(ms, 1), "start_ns": t_ns, "end_ns": end_ns, "ok": res.code == 201 and bool(body.get("chain_id")),
            "response": res.body[:1000]}


def dispose(pod: str, idx: int, chain_id: str) -> dict:
    t_ns = time.time_ns()
    t0 = time.perf_counter()
    res = c.parentsim(NS, pod, "dispose", f"-chain-id={chain_id}")
    ms = (time.perf_counter() - t0) * 1000
    end_ns = time.time_ns()
    return {"op": "dispose", "index": idx, "chain_id": chain_id, "status": res.code, "host_ms": round(ms, 1),
            "start_ns": t_ns, "end_ns": end_ns, "ok": res.code == 200, "response": res.body[:1000]}


# --------------------------------------------------------------------------
# the run

class Run:
    def __init__(self, args: argparse.Namespace, out_dir: Path, scratch: Path) -> None:
        self.args, self.out, self.scratch = args, out_dir, scratch
        self.targets = discover()
        self.start_state = restarts(self.targets)
        self.opa = OpaTracker()
        self.audit = AuditTracker()
        self.rows: list[dict] = []
        self.tables: list[dict] = []
        self.raw_steps: list[dict] = []
        self.ops: list[dict] = []
        self.metrics_error: str | None = None
        self.log_counts = {k: 0 for k in COMPONENTS}
        self.log_cursor_ns = 0
        self.step = 0
        for comp in COMPONENTS:
            (out_dir / "logs" / comp).mkdir(parents=True, exist_ok=True)

    def prime_logs(self) -> None:
        """Whole logs up to now give the modules and audit events that exist before the first
        checkpoint; the first step window starts 1 s before it."""
        self.log_cursor_ns = time.time_ns() - 1_000_000_000
        before_opa = [ln for ln in full_log(self.targets["opa"]) if self._before(ln)]
        before_pe = [ln for ln in full_log(self.targets["policy-engine"]) if self._before(ln)]
        self.opa.feed(before_opa)
        self.audit.feed(before_pe)
        self.prior = {"opa_live_modules": self.opa.live, "policy_engine_live_grants": self.audit.live,
                      "opa_gets_before": len(self.opa.gets)}
        self.opa.gets.clear()

    def _before(self, ln: str) -> bool:
        try:
            return parse_rfc3339_ns(ln.partition(" ")[0]) < self.log_cursor_ns
        except ValueError:
            return False

    def collect_logs(self, end_ns: int) -> None:
        for comp, t in self.targets.items():
            lines = component_logs(t["ns"], t["pod"], t["container"], self.log_cursor_ns, end_ns)
            (self.out / "logs" / comp / f"step-{self.step:02d}.log").write_text("\n".join(lines) + ("\n" if lines else ""))
            self.log_counts[comp] += len(lines)
            if comp == "opa":
                self.opa.feed(lines)
            elif comp == "policy-engine":
                self.audit.feed(lines)
        self.log_cursor_ns = end_ns

    def checkpoint(self, phase: str, n_vended: int, n_disposed: int) -> None:
        time.sleep(self.args.pause_s)
        t_meas = time.time()
        row: dict = {"phase": phase, "step": self.step, "measure_epoch_s": round(t_meas, 3), "n_vended_total": n_vended, "n_disposed_total": n_disposed,
                     "n_live": n_vended - n_disposed, "timestamp": c.now_iso()}
        raw: dict = {"step": self.step}
        scratch = self.scratch

        # 1. bytes on disk, and 2. the logical SQLite content
        for dbname, (comp, base) in DBS.items():
            t = self.targets[comp]
            files = stat_dir(t["node"], t["dir"])
            raw[f"stat_{dbname}"] = files
            for f in files:
                row[f"{dbname}_file_{col(f['name'])}_apparent_bytes"] = f["apparent"]
                row[f"{dbname}_file_{col(f['name'])}_alloc_bytes"] = f["alloc"]
            row[f"{dbname}_disk_apparent_bytes"] = sum(f["apparent"] for f in files)
            row[f"{dbname}_disk_alloc_bytes"] = sum(f["alloc"] for f in files)
            info, attempts = db_snapshot_checked(t["node"], t["dir"], base, [f["name"] for f in files], scratch)
            raw[f"dbstat_{dbname}"] = {k: v for k, v in info.items() if k != "objects"} | {"objects": info["objects"]}
            for k in ("page_size", "page_count", "freelist_count", "journal_mode", "used_bytes", "freelist_bytes",
                      "dbstat_bytes", "dbstat_unused_bytes"):
                row[f"{dbname}_db_{k}"] = info[k]
            row[f"{dbname}_db_quick_check"] = ";".join(attempts[0])
            row[f"{dbname}_db_quick_check_retry"] = ";".join(attempts[1]) if len(attempts) > 1 else ""
            for tbl, cnt in info["rows"].items():
                row[f"{dbname}_rows_{col(tbl)}"] = cnt
            for k, v in info["extra"].items():
                row[f"{dbname}_{k}"] = v
            for o in info["objects"]:
                self.tables.append({"step": self.step, "db": dbname, "name": o["name"], "type": o["type"],
                                    "table": o["table"], "rows": "" if o["rows"] is None else o["rows"],
                                    "pages": o["pages"], "bytes": o["bytes"], "unused": o["unused"]})

        # 3. writable layers and memory
        now_ns = time.time_ns()
        cs = crictl(self.targets)
        raw["crictl"] = cs
        for comp, s in cs.items():
            k = col(comp)
            if not s:
                row[f"{k}_writable_used_bytes"] = ""
                continue
            wl, mem = s.get("writableLayer") or {}, s.get("memory") or {}
            row[f"{k}_writable_used_bytes"] = int(wl.get("usedBytes", {}).get("value", -1))
            row[f"{k}_writable_inodes"] = int(wl.get("inodesUsed", {}).get("value", -1))
            row[f"{k}_writable_age_s"] = round((now_ns - int(wl["timestamp"])) / 1e9, 1) if wl.get("timestamp") else ""
            row[f"{k}_mem_working_set_bytes"] = int(mem.get("workingSetBytes", {}).get("value", -1))

        # 4 (part). OPA's diagnostic listener: noisy (GC) when it works
        if self.metrics_error is None:
            m = opa_metrics(self.targets["opa"]["pod"])
            if m["status"] != "ok":
                self.metrics_error = m["status"]
        else:
            m = {"status": f"skipped: {self.metrics_error}"}
        raw["opa_metrics"] = m
        row["opa_metrics_status"] = m["status"]
        row["opa_heap_inuse_bytes"] = m.get("go_memstats_heap_inuse_bytes", "")
        row["opa_alloc_bytes"] = m.get("go_memstats_alloc_bytes", "")

        # 5. cross-check
        row["spire_entry_count"] = spire_entry_count()
        row["measure_s"] = round(time.time() - t_meas, 2)

        # logs of the window that ends here; the OPA and audit counts follow from them
        self.collect_logs(time.time_ns())
        row["opa_live_modules"] = self.opa.live
        row["opa_puts_total"], row["opa_deletes_total"] = self.opa.puts, self.opa.deletes
        row["policy_engine_live_grants"] = self.audit.live
        last = self.opa.gets[-1] if self.opa.gets else None
        row["opa_last_get_resp_bytes"] = last["resp_bytes"] if last else ""
        row["opa_last_get_live_modules"] = last["live_modules_at_get"] if last else ""
        cur = restarts(self.targets)
        row["restarts_unchanged"] = cur == self.start_state
        raw["restarts"] = cur

        self.rows.append(row)
        self.raw_steps.append(raw)
        print(f"  step {self.step:2d} [{phase} live={row['n_live']} vended={n_vended} disposed={n_disposed}] "
              f"spire {row['spire_disk_apparent_bytes']} B/{row['spire_db_used_bytes']} B logical, "
              f"vending {row['vending_disk_apparent_bytes']} B/{row['vending_db_used_bytes']} B logical, "
              f"opa modules {row['opa_live_modules']}, entries {row['spire_entry_count']}  [{row['measure_s']} s]", flush=True)
        self.step += 1

    def idle(self, phase: str, n_vended: int, n_disposed: int) -> None:
        print(f"  idle {self.args.idle_s:g} s, no operations", flush=True)
        time.sleep(self.args.idle_s)
        self.checkpoint(phase, n_vended, n_disposed)

    def do(self, op: dict) -> dict:
        self.ops.append(op)
        if not op["ok"]:
            raise OpError(f"{op['op']} #{op['index']} failed: HTTP {op['status']} {op['response']}")
        return op


def run_accumulate(r: Run, pod: str, a: argparse.Namespace) -> None:
    cps = checkpoint_set(a.n, a.step)
    r.checkpoint("accumulate", 0, 0)
    r.idle("idle-start", 0, 0)
    chains: list[str] = []
    for i in range(1, a.n + 1):
        chains.append(r.do(vend(pod, i, "acc", a.ttl))["chain_id"])
        if i in cps:
            r.checkpoint("accumulate", i, 0)
    for d in range(1, a.n + 1):
        r.do(dispose(pod, d, chains[d - 1]))
        if d in cps:
            r.checkpoint("drain", a.n, d)
    r.idle("idle-end", a.n, a.n)


def run_churn(r: Run, pod: str, a: argparse.Namespace) -> None:
    cps = checkpoint_set(a.n, a.step)
    r.checkpoint("churn", 0, 0)
    r.idle("idle-start", 0, 0)
    for i in range(1, a.n + 1):
        v = r.do(vend(pod, i, "chu", a.ttl))
        r.do(dispose(pod, i, v["chain_id"]))
        if i in cps:
            r.checkpoint("churn", i, i)
    r.idle("idle-end", a.n, a.n)


# --------------------------------------------------------------------------
# statistics

def ols(xs: list[float], ys: list[float]) -> dict | None:
    n = len(xs)
    if n < 2 or len(set(xs)) < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx
    icpt = my - slope * mx
    res = [y - (icpt + slope * x) for x, y in zip(xs, ys)]
    sst = sum((y - my) ** 2 for y in ys)
    r2 = 1 - sum(e * e for e in res) / sst if sst else None
    return {"points": n, "slope": slope, "intercept": icpt, "r_squared": r2,
            "residual_min": min(res), "residual_max": max(res)}


def loglog_exponent(xs: list[float], ys: list[float], base: float) -> dict | None:
    pts = [(math.log(x), math.log(y - base)) for x, y in zip(xs, ys) if x >= 1 and y - base > 0]
    fit = ols([p[0] for p in pts], [p[1] for p in pts])
    return {"points": fit["points"], "exponent": fit["slope"], "r_squared": fit["r_squared"]} if fit else None


HEADLINE = [
    "spire_disk_apparent_bytes", "spire_disk_alloc_bytes", "vending_disk_apparent_bytes", "vending_disk_alloc_bytes",
    "spire_file_datastore_sqlite3_apparent_bytes", "spire_file_datastore_sqlite3_wal_apparent_bytes",
    "spire_file_datastore_sqlite3_alloc_bytes", "spire_file_datastore_sqlite3_wal_alloc_bytes",
    "vending_file_vending_db_alloc_bytes", "vending_file_vending_db_wal_alloc_bytes",
    "spire_file_datastore_sqlite3_shm_apparent_bytes", "vending_file_vending_db_shm_apparent_bytes",
    "vending_file_vending_db_apparent_bytes", "vending_file_vending_db_wal_apparent_bytes",
    "vending_file_audit_jsonl_apparent_bytes",
    "spire_db_used_bytes", "vending_db_used_bytes", "spire_db_dbstat_bytes", "vending_db_dbstat_bytes",
    "spire_server_writable_used_bytes", "vending_service_writable_used_bytes",
    "policy_engine_writable_used_bytes", "opa_writable_used_bytes",
    "spire_server_mem_working_set_bytes", "vending_service_mem_working_set_bytes",
    "policy_engine_mem_working_set_bytes", "opa_mem_working_set_bytes",
]


def num(v) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def fit_phase(rows: list[dict], xkey: str, base_row: dict) -> dict:
    out = {}
    cols = [k for k in HEADLINE if any(k in r for r in rows)]
    for k in cols:
        pts = [(r[xkey], num(r.get(k))) for r in rows if num(r.get(k)) is not None]
        base = num(base_row.get(k))
        xs, ys = [float(p[0]) for p in pts], [p[1] for p in pts]
        out[k] = {"ols_bytes_vs_" + xkey: ols(xs, ys),
                  "loglog_vs_" + xkey: loglog_exponent(xs, ys, base) if base is not None else None,
                  "baseline_step0": base, "last": ys[-1] if ys else None}
    return out


def table_rows_per_child(rows: list[dict], xkey: str) -> dict:
    out = {}
    keys = sorted({k for r in rows for k in r if "_rows_" in k})
    for k in keys:
        pts = [(r[xkey], r[k]) for r in rows if isinstance(r.get(k), int)]
        f = ols([float(p[0]) for p in pts], [float(p[1]) for p in pts])
        out[k] = {"rows_first": pts[0][1], "rows_last": pts[-1][1], "ols_slope_rows_per_" + xkey: f["slope"] if f else None}
    return out


def idle_report(rows: list[dict]) -> dict:
    """Change of each metric over the two idle windows (no operations), per second."""
    ops_rows = [x for x in rows if not x["phase"].startswith("idle")]
    pairs = {}
    start = next((x for x in rows if x["phase"] == "idle-start"), None)
    end = next((x for x in rows if x["phase"] == "idle-end"), None)
    if start:
        pairs["idle_start"] = (rows[0], start)
    if end:
        pairs["idle_end"] = (ops_rows[-1], end)
    out = {}
    for name, (a, b) in pairs.items():
        dt = b["measure_epoch_s"] - a["measure_epoch_s"]
        keys = [k for k in HEADLINE + sorted(k for k in b if "_rows_" in k or k in ("spire_entry_count", "opa_live_modules"))
                if num(a.get(k)) is not None and num(b.get(k)) is not None]
        out[name] = {"from_step": a["step"], "to_step": b["step"], "seconds": round(dt, 1),
                     "change": {k: b[k] - a[k] for k in keys},
                     "per_second": {k: (b[k] - a[k]) / dt for k in keys if b[k] != a[k]},
                     "note": "per_second lists only the metrics that changed; the writable-layer and memory values are runtime samples"}
    return out


def wal_report(rows: list[dict]) -> dict:
    """Growth of each database's -wal file. SQLite checkpoints a WAL after about 1000 frames
    (wal_autocheckpoint) but does not shrink the file, so its size plateaus."""
    out = {}
    for db, wal in (("spire", "spire_file_datastore_sqlite3_wal_apparent_bytes"),
                    ("vending", "vending_file_vending_db_wal_apparent_bytes")):
        ps = rows[0][f"{db}_db_page_size"]
        frame = ps + 24
        threshold = 1000 * frame + 32
        series = [(x["step"], x["phase"], x["n_vended_total"] + x["n_disposed_total"], x.get(wal, 0)) for x in rows]
        ops_series = [t for t in series if not t[1].startswith("idle")]
        reach = next((t for t in ops_series if t[3] >= threshold), None)
        mx = max(ops_series, key=lambda t: t[3])
        plateau = None
        if reach:  # first checkpoint after which the size never changes again
            for i in range(len(ops_series)):
                if all(t[3] == ops_series[i][3] for t in ops_series[i:]):
                    plateau = ops_series[i]
                    break
        out[db] = {
            "frame_bytes": frame, "autocheckpoint_threshold_bytes_1000_frames": threshold,
            "series": [{"step": t[0], "phase": t[1], "ops_so_far": t[2], "wal_apparent_bytes": t[3]} for t in series],
            "first_checkpoint_at_or_over_threshold": ({"step": reach[0], "phase": reach[1], "ops_so_far": reach[2], "wal_apparent_bytes": reach[3]} if reach else None),
            "max_wal_apparent_bytes": mx[3], "max_reached_at_step": mx[0],
            "size_never_changes_after": ({"step": plateau[0], "phase": plateau[1], "ops_so_far": plateau[2], "wal_apparent_bytes": plateau[3]} if plateau else None),
            "decreased_between_checkpoints": any(b[3] < a[3] for a, b in zip(ops_series, ops_series[1:])),
            "note": "ops_so_far = vends + disposes; checkpoints are 25 children apart, so the exact operation is not resolved",
        }
    return out


def build_summary(r: Run, args: argparse.Namespace, inv: dict, started: str, finished: str, ops_with_gets: list[dict],
                  unassigned_gets: int) -> dict:
    rows = r.rows
    base = rows[0]
    s: dict = {"run": args.run_id, "phase": args.phase, "n": args.n, "step": args.step, "started": started,
               "finished": finished, "checkpoints": len(rows), "host": inv,
               "prior_state_before_step0": getattr(r, "prior", {})}
    phases: dict = {}
    if args.phase == "accumulate":
        acc = [x for x in rows if x["phase"] == "accumulate"]
        peak = acc[-1]
        drain = [peak] + [x for x in rows if x["phase"] == "drain"]
        phases["accumulate"] = {"x": "n_live (children vended, none disposed)", "fits": fit_phase(acc, "n_live", base),
                                "rows": table_rows_per_child(acc, "n_live")}
        phases["drain"] = {"x": "n_live (children still live; the first point is the N = n peak)",
                           "fits": fit_phase(drain, "n_live", base), "rows": table_rows_per_child(drain, "n_live")}
        last = [x for x in rows if x["phase"] == "drain"][-1]
        reclaim = {}
        for db in DBS:
            reclaim[db] = {
                "on_disk_alloc_bytes": {"peak": peak[f"{db}_disk_alloc_bytes"], "after_drain": last[f"{db}_disk_alloc_bytes"],
                                         "reclaimed": peak[f"{db}_disk_alloc_bytes"] - last[f"{db}_disk_alloc_bytes"]},
                "on_disk_apparent_bytes": {"peak": peak[f"{db}_disk_apparent_bytes"], "after_drain": last[f"{db}_disk_apparent_bytes"],
                                            "reclaimed": peak[f"{db}_disk_apparent_bytes"] - last[f"{db}_disk_apparent_bytes"]},
                "logical_used_bytes": {"peak": peak[f"{db}_db_used_bytes"], "after_drain": last[f"{db}_db_used_bytes"],
                                        "reclaimed": peak[f"{db}_db_used_bytes"] - last[f"{db}_db_used_bytes"]},
                "logical_freelist_bytes_after_drain": last[f"{db}_db_freelist_bytes"],
                "logical_dbstat_bytes": {"peak": peak[f"{db}_db_dbstat_bytes"], "after_drain": last[f"{db}_db_dbstat_bytes"]},
            }
        s["drain_reclaim"] = reclaim
    else:
        ch = [x for x in rows if x["phase"] == "churn"]
        phases["churn"] = {"x": "n_vended_total (cycles)", "fits": fit_phase(ch, "n_vended_total", base),
                           "rows": table_rows_per_child(ch, "n_vended_total")}
    s["phases"] = phases
    s["idle"] = idle_report(rows)
    s["wal"] = wal_report(rows)

    # OPA: the size of GET /v1/policies against the live modules at that GET
    gets = [(o["opa_get_live_modules"], o["opa_get_resp_bytes"]) for o in ops_with_gets
            if o["op"] == "vend" and o.get("opa_get_resp_bytes") not in ("", None)]
    fit = ols([float(g[0]) for g in gets], [float(g[1]) for g in gets])
    opa: dict = {"gets_matched_to_vends": len(gets), "gets_unassigned": unassigned_gets, "ols_resp_bytes_vs_live_modules": fit}
    if fit and fit["slope"] > 0:
        modules = (OPA_READ_LIMIT - fit["intercept"]) / fit["slope"]
        opa["bytes_per_module"] = fit["slope"]
        opa["projection"] = {
            "label": "PROJECTION by linear extrapolation of the fit above, not measured",
            "read_limit_bytes": OPA_READ_LIMIT,
            "read_limit_source": "io.LimitReader(resp.Body, 4<<20) in src/policy-engine/opa.go",
            "live_modules_at_limit": modules,
            "largest_measured_live_modules": max(g[0] for g in gets),
        }
    s["opa"] = opa
    s["checks"] = build_checks(r, args)
    s["metrics"] = {"opa_diagnostic_listener": r.metrics_error or "ok"}
    return s


def build_checks(r: Run, args: argparse.Namespace) -> dict:
    rows = r.rows
    b = rows[0]

    def check(desc: str, exp, key: str | None = None, fn=None) -> dict:
        bad = []
        for x in rows:
            got = fn(x) if fn else x.get(key)
            want = exp(x)
            if got != want:
                bad.append({"step": x["step"], "phase": x["phase"], "expected": want, "observed": got})
        return {"description": desc, "ok": not bad, "points": len(rows), "mismatches": bad}

    ev = next((k for k in b if k.startswith("spire_rows_") and k.endswith("entries_events") and "registered" in k), None)
    ents = "spire_rows_registered_entries"
    sels = "spire_rows_selectors"
    out = {
        "vending_delegations_plus_1_per_vend_unchanged_on_dispose": check(
            "vending.delegations = baseline + vends so far (a dispose only sets revoked_at)",
            lambda x: b["vending_rows_delegations"] + x["n_vended_total"], "vending_rows_delegations"),
        "vending_used_nonces_plus_1_per_vend": check(
            "vending.used_nonces = baseline + vends so far",
            lambda x: b["vending_rows_used_nonces"] + x["n_vended_total"], "vending_rows_used_nonces"),
        "vending_unrevoked_delegations_equal_live": check(
            "vending.delegations with revoked_at NULL = baseline + live children",
            lambda x: b["vending_live_delegations"] + x["n_live"], "vending_live_delegations"),
        "spire_registered_entries_plus_1_per_vend_minus_1_per_dispose": check(
            "spire registered_entries = baseline + live children", lambda x: b[ents] + x["n_live"], ents),
        "spire_selector_rows_plus_2_per_live_child": check(
            "spire selectors = baseline + 2 x live children (k8s:ns, k8s:pod-name)",
            lambda x: b[sels] + 2 * x["n_live"], sels),
        "opa_modules_plus_1_per_vend_minus_1_per_dispose": check(
            "OPA live nhi_grants_* modules (request log) = modules before step 0 + live children",
            lambda x: r.prior["opa_live_modules"] + x["n_live"], "opa_live_modules"),
        "policy_engine_audit_matches_opa": check(
            "policy engine allowed vends - allowed disposes (audit events) = OPA live modules",
            lambda x: x["opa_live_modules"], "policy_engine_live_grants"),
        "spire_entry_count_consistent": check(
            "`spire-server entry count` = registered_entries rows = baseline + live children",
            lambda x: b["spire_entry_count"] + x["n_live"],
            fn=lambda x: x["spire_entry_count"] if x["spire_entry_count"] == x[ents] else f"{x['spire_entry_count']} != rows {x[ents]}"),
        "all_quick_check_ok": check("PRAGMA quick_check = ok for both databases, first try",
                                    lambda x: "ok", fn=lambda x: x["spire_db_quick_check"] if x["spire_db_quick_check"] == x["vending_db_quick_check"] else f"{x['spire_db_quick_check']}/{x['vending_db_quick_check']}"),
        "no_container_restarts": check("no pod or container restart since the run started", lambda x: True, "restarts_unchanged"),
    }
    if ev:
        out["spire_event_rows_plus_1_per_create_and_per_delete"] = check(
            f"spire {ev[len('spire_rows_'):]} = baseline + vends so far + disposes so far",
            lambda x: b[ev] + x["n_vended_total"] + x["n_disposed_total"], ev)
    else:
        out["spire_event_rows_plus_1_per_create_and_per_delete"] = {"ok": False, "description": "registered-entry events table not found in the live schema"}
    out["op_statuses"] = {
        "description": "every vend answered 201 and every dispose 200",
        "ok": all(o["ok"] for o in r.ops), "vends": sum(o["op"] == "vend" for o in r.ops),
        "disposes": sum(o["op"] == "dispose" for o in r.ops),
        "statuses": {f"{op}_{st}": sum(1 for o in r.ops if o["op"] == op and o["status"] == st)
                     for op in ("vend", "dispose") for st in {o["status"] for o in r.ops if o["op"] == op}},
    }
    out["all_ok"] = all(v.get("ok") for v in out.values() if isinstance(v, dict))
    return out


def assign_gets(r: Run) -> tuple[list[dict], int]:
    """Attach each GET /v1/policies to the vend that was running when OPA answered it."""
    ops = sorted(r.ops, key=lambda o: o["start_ns"])
    for o in ops:
        o["opa_get_resp_bytes"], o["opa_get_live_modules"], o["opa_get_count"] = "", "", 0
    unassigned = 0
    for g in r.opa.gets:
        cand = [o for o in ops if o["start_ns"] <= g["ts_ns"]]
        o = cand[-1] if cand else None
        if not o or o["op"] != "vend" or g["ts_ns"] > o["end_ns"] + 250_000_000:
            unassigned += 1
            continue
        o["opa_get_count"] += 1
        if o["opa_get_count"] == 1:
            o["opa_get_resp_bytes"], o["opa_get_live_modules"] = g["resp_bytes"], g["live_modules_at_get"]
    return ops, unassigned


# --------------------------------------------------------------------------
# outputs

def write_csv(path: Path, rows: list[dict], fields: list[str] | None = None) -> None:
    if fields is None:
        fields = []
        for r in rows:
            fields += [k for k in r if k not in fields]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, 0 if ("_bytes" in k or "_rows_" in k or "_inodes" in k) else "") for k in fields})


def code_state() -> dict:
    def git(*a: str) -> str:
        return sh("git", "-C", str(Path(__file__).parent), *a, check=False).stdout.strip()
    return {"branch": git("rev-parse", "--abbrev-ref", "HEAD"), "base_commit": git("rev-parse", "--short", "HEAD"),
            "state": "uncommitted working tree at run time"}


def write_provenance(r: Run, args: argparse.Namespace, cluster: str, argv_cmd: str) -> None:
    prov = {
        "benchmark": "storage_growth",
        "run": f"{args.phase}, n = {args.n}, checkpoints every {args.step} children plus 0, 1, 2 and n; SPIRE agent sync_interval and server cache_reload_interval both 1 s; MAX_LIVE_CHILDREN = 200",
        "headline": "bytes on disk of the SPIRE server and vending service volumes, and the logical SQLite content (page counts, per-table dbstat bytes, row counts), against the number of children vended by exp-root; accumulate is followed by a drain (dispose all, oldest first), churn is vend-then-dispose cycles",
        "secondary": "container writable-layer bytes and memory working set (crictl), OPA grant-module count from OPA's request log, size of GET /v1/policies per vend (resp_bytes) and its projection to the policy engine's 4 MiB read limit",
        "harness": "src/experiments/storage_growth.py (reusing lib/cluster.py, revocation_speed.py and vend_to_svid.py's parts), parentsim modes vend and dispose",
        "inputs_per_child": {
            "child_path_hint": "child/sg-NNNNN", "selectors": "k8s:ns=agents,k8s:pod-name=sg-NNNNN (no such pod exists)",
            "scopes": SCOPES, "task_context": TASK_CONTEXT, "ttl_seconds": args.ttl,
            "nonce": f"sg-{'acc' if args.phase == 'accumulate' else 'chu'}-NNNNN (NNNNN: 5-digit zero-padded index)"},
        "code": code_state(),
        "command": argv_cmd,
        "cluster": {
            "kind_cluster": f"{cluster} (throwaway, two nodes), created for this run and deleted after it",
            "bring_up": [f"make cluster-up KIND_CLUSTER={cluster}", f"make spire-up KIND_CLUSTER={cluster}",
                         f"make policy-engine-up vending-service-up resource-up experiments-fixtures-up KIND_CLUSTER={cluster}"],
            "note": "the config changes below were made after the last make target, because the make targets re-apply the repository's manifests; make was not run again on the cluster",
            "nodes_and_dirs": {k: {"node": t["node"], "pvc": t.get("pvc"), "pv_capacity": t.get("pv_capacity"),
                                   "dir_on_node": t.get("dir")} for k, t in r.targets.items()},
        },
        "config_changes_on_this_cluster_only": [
            {"component": "spire-server",
             "change": "in the server block of the live spire-server ConfigMap: `audit_log_enabled = true` and `experimental { cache_reload_interval = \"1s\" }` (default 5 s); StatefulSet restarted",
             "repository_manifests_changed": False},
            {"component": "spire-agent",
             "change": "in the agent block of the live spire-agent ConfigMap: `experimental { sync_interval = \"1s\" }` (default 5 s); DaemonSet restarted after the server",
             "repository_manifests_changed": False},
            {"component": "vending-service",
             "change": "`kubectl -n nhi set env deployment/vending-service MAX_LIVE_CHILDREN=200` (manifest default 8); Recreate rollout, the PVC persisted; checked in the running pod's spec",
             "repository_manifests_changed": False},
        ],
        "measurement_notes": {
            "pause": f"{args.pause_s} s before each checkpoint so in-flight writes land",
            "on_disk": "docker exec <node> find <pv dir> -maxdepth 1 -type f -exec stat -c '%n|%s|%b|%B'; apparent = %s, allocated = %b x %B; read from outside the pods",
            "logical": "database + -wal + -shm streamed out of the node with tar into a scratch directory and opened there; dbstat gives pages, pgsize and unused per table and index",
            "writable_layer": "crictl stats; the runtime refreshes writableLayer on its own period, so each value has an age column (<container>_writable_age_s)",
            "opa_modules": "live count = 2xx PUTs minus DELETEs of /v1/policies/nhi_grants_* in OPA's request log (container opa); GET /v1/policies sizes = resp_bytes of its 'Sent response.' lines; no GET happens during the drain",
            "opa_diagnostic_listener": r.metrics_error or "ok",
            "log_bytes": "container log byte counts are not measured",
        },
        "not_populated": {
            "opa_heap_inuse_bytes, opa_alloc_bytes": "OPA's diagnostic listener (--diagnostic-addr, /metrics) also requires a client certificate: --authentication=tls applies to every listener, and the harness holds no SVID that OPA trusts (the TLS error is in opa_metrics_status). OPA's key material was not touched. The OPA in-memory footprint is therefore the crictl memory working set only (opa_mem_working_set_bytes), which is noisy (GC). The headline OPA numbers are the live module count and the GET /v1/policies resp_bytes.",
        },
        "idle_control": f"after checkpoint 0 and after the last checkpoint the run waits {args.idle_s:g} s with no operations and takes a checkpoint (phase idle-start / idle-end); idle rows are excluded from the fits and reported as per-second changes in the summary ('idle')",
        "config_script_output": (Path(args.config_output).read_text().splitlines() if args.config_output else None),
        "logs": {"dir": "logs/", "files": "logs/{vending-service,spire-server,policy-engine,opa}/step-NN.log",
                 "window": "contiguous per step: step 00 starts 1 s before the harness's first action; step NN runs from the end of step NN-1's window to the end of checkpoint NN's measurements",
                 "timestamp": "first field of each line: the container runtime's capture time (kubectl logs --timestamps)",
                 "spire_server_audit_log_enabled": True,
                 "lines": {k.replace("-", "_"): v for k, v in r.log_counts.items()}},
    }
    (r.out / "provenance.json").write_text(json.dumps(prov, indent=2) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--phase", choices=("accumulate", "churn"), required=True)
    ap.add_argument("--n", type=int, required=True, help="children to vend (accumulate) or cycles (churn)")
    ap.add_argument("--step", type=int, default=25, help="checkpoint spacing; checkpoints also at 0, 1, 2 and n")
    ap.add_argument("--ttl", type=int, default=3600)
    ap.add_argument("--pause-s", type=float, default=1.0, help="wait before each checkpoint's measurements")
    ap.add_argument("--idle-s", type=float, default=30.0, help="idle wait before the idle-start and idle-end checkpoints")
    ap.add_argument("--config-output", default=None, help="file with the output of the cluster config script, recorded in provenance.json")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()
    if args.run_id is None:
        args.run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-storage-growth-{args.phase}"
    out_dir = Path(__file__).parent / "results" / args.run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="storage-growth-"))
    cluster = c.KUBECTX.removeprefix("kind-")
    argv_cmd = (f"cd src/experiments && CLUSTER_NAME={c.CLUSTER_NAME} KUBECTX={c.KUBECTX} TRUST_DOMAIN={c.TRUST_DOMAIN} "
                f"uv run python3 storage_growth.py --phase {args.phase} --n {args.n} --step {args.step} --run-id {args.run_id}"
                + (f" --ttl {args.ttl}" if args.ttl != 3600 else "") + (f" --idle-s {args.idle_s:g}" if args.idle_s != 30.0 else "") + (f" --pause-s {args.pause_s:g}" if args.pause_s != 1.0 else ""))

    print(f"== storage growth: {args.phase}, n = {args.n}, checkpoints {sorted(checkpoint_set(args.n, args.step))} ==")
    pod = c.wait_for_pod(NS, "app=experiments-parent")
    if not wait_for_svid(pod, PARENT_ID):
        print("FATAL: P does not hold its own identity", file=sys.stderr)
        return 2
    r = Run(args, out_dir, scratch)
    vs = json.loads(c.kubectl("get", "pod", "-n", "nhi", r.targets["vending-service"]["pod"], "-o", "json").stdout)
    env = {e["name"]: e.get("value") for e in vs["spec"]["containers"][0].get("env", [])}
    cap = int(env.get("MAX_LIVE_CHILDREN", "8"))
    need = args.n if args.phase == "accumulate" else 1
    if cap < need:
        print(f"FATAL: MAX_LIVE_CHILDREN is {cap} in the running vending-service pod; this run needs {need}", file=sys.stderr)
        return 2
    for name, t in r.targets.items():
        print(f"  {name}: pod {t['pod']} on {t['node']}" + (f", {t['pvc']} -> {t['pv']} at {t['dir']}" if t.get("dir") else ""))
    inv = host_inventory()
    inv["load_average_start"] = [round(x, 2) for x in os.getloadavg()]
    inv["max_live_children_in_running_pod"] = cap
    inv["images"] = {k: c.kubectl("get", "pod", "-n", t["ns"], t["pod"], "-o",
                                  f"jsonpath={{.spec.containers[?(@.name=='{t['container']}')].image}}", check=False).stdout.strip()
                     for k, t in r.targets.items()}
    inv["spire_server_audit_log_enabled"] = "audit_log_enabled" in (
        c.kubectl("get", "cm", "-n", "spire", "spire-server", "-o", "jsonpath={.data.server\\.conf}", check=False).stdout or "")
    inv["sqlite_python"] = sqlite3.sqlite_version

    started = c.now_iso()
    r.prime_logs()
    code = 0
    t_start = time.monotonic()
    try:
        (run_accumulate if args.phase == "accumulate" else run_churn)(r, pod, args)
    except Exception as exc:  # noqa: BLE001 - keep what was measured
        print(f"FAILED: {exc}", file=sys.stderr)
        code = 1
    inv["load_average_end"] = [round(x, 2) for x in os.getloadavg()]
    finished = c.now_iso()
    inv["run_seconds"] = round(time.monotonic() - t_start, 1)

    ops, unassigned = assign_gets(r)
    write_csv(out_dir / "storage_growth.csv", r.rows)
    write_csv(out_dir / "storage_growth_tables.csv", r.tables,
              ["step", "db", "name", "type", "table", "rows", "pages", "bytes", "unused"])
    write_csv(out_dir / "storage_growth_ops.csv", [{k: v for k, v in o.items() if k != "response"} for o in ops],
              ["op", "index", "chain_id", "status", "ok", "host_ms", "start_ns", "end_ns", "opa_get_resp_bytes",
               "opa_get_live_modules", "opa_get_count"])
    (out_dir / "storage_growth_raw.json").write_text(json.dumps(
        {"targets": r.targets, "steps": r.raw_steps, "ops": ops, "opa_gets": r.opa.gets}, indent=1) + "\n")
    if r.rows:
        summary = build_summary(r, args, inv, started, finished, ops, unassigned)
        (out_dir / "storage_growth_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"checks all_ok = {summary['checks']['all_ok']}")
    write_provenance(r, args, cluster, argv_cmd)
    shutil.rmtree(scratch, ignore_errors=True)
    print(f"{inv['run_seconds']} s; results in {out_dir}")
    return code


if __name__ == "__main__":
    sys.exit(main())
