#!/usr/bin/env python3
"""Experiment orchestrator: `make experiments`'s entry point.

Order: negative tests first (highest value),
then multi-hop, then functional, then performance (truncated first if the
suite runs short of time -- performance is the only suite of the four this
orchestrator will skip on `--skip-performance`, since a single-machine kind
cluster already frames those numbers as relative/exploratory, not load-bearing for any
correctness claim the way the other three suites are).

Produces `results/<run-id>/` (raw CSV/JSON from every suite plus this file's
own summary.json) and updates `results/latest` as a copy of the same run, so
there is always a stable path to the most recent results.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent


def run_suite(name: str, args: list[str]) -> tuple[int, float]:
    print(f"\n{'=' * 70}\n{name}\n{'=' * 70}")
    t0 = time.monotonic()
    proc = subprocess.run([sys.executable, *args], cwd=HERE)
    return proc.returncode, round(time.monotonic() - t0, 1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--performance-runs", type=int, default=100)
    ap.add_argument("--skip-performance", action="store_true")
    args = ap.parse_args()

    latest = HERE / "results" / "latest"
    if latest.exists():
        shutil.rmtree(latest)
    latest.mkdir(parents=True)

    suites = [
        ("negative_tests", [str(HERE / "negative_tests.py")]),
        ("multi_hop", [str(HERE / "multi_hop.py")]),
        ("functional_tests", [str(HERE / "functional_tests.py")]),
    ]
    if not args.skip_performance:
        suites.append(("performance", [str(HERE / "performance.py"), str(args.performance_runs)]))

    summary = {"suites": {}}
    overall_ok = True
    for name, cmd in suites:
        code, elapsed_s = run_suite(name, cmd)
        summary["suites"][name] = {"exit_code": code, "elapsed_s": elapsed_s, "pass": code == 0}
        overall_ok = overall_ok and (code == 0)

    if args.skip_performance:
        summary["suites"]["performance"] = {"skipped": True, "reason": "--skip-performance"}

    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_dir = HERE / "results" / run_id
    shutil.copytree(latest, run_dir)
    summary["run_id"] = run_id
    (latest / "run_summary.json").write_text(json.dumps(summary, indent=2))
    (run_dir / "run_summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\n{'=' * 70}\nSUMMARY\n{'=' * 70}")
    print(json.dumps(summary, indent=2))
    print(f"\nresults: {run_dir}  (and results/latest)")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
