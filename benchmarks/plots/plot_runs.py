#!/usr/bin/env python3
"""Plot committed benchmark runs from their CSV and JSON result files.

Run from the repository root:

    uv run --with matplotlib python3 benchmarks/plots/plot_runs.py

With no arguments it plots every run in DEFAULT_RUNS and the comparison figure
in COMPARISON, writing PNGs to benchmarks/plots/ as <run-dir>_<kind>.png.
Name run directories to plot only those (the kind of run is read from the
files it holds):

    uv run --with matplotlib python3 benchmarks/plots/plot_runs.py \
        benchmarks/20261107T181324Z-storage-growth-accumulate-1s --out /tmp/plots

The script reads only files committed in each run directory (the *.csv rows
and the *_summary.json percentiles, which it cross-checks). It never
overwrites a PNG in benchmarks/plots/ that belongs to a run outside
DEFAULT_RUNS, so the ad hoc plots of the November 1-7 runs stay as they are;
pass --overwrite to replace them on purpose.

With no arguments it also writes the vending-vs-end-to-end stage figure
(STAGES_NAME, runs in STAGE_RUNS: the clean AWS run against the local 1 s and
5 s runs). To write only that figure, without regenerating the others:

    uv run --with matplotlib python3 benchmarks/plots/plot_runs.py --stages-only

Percentiles use the nearest-rank method, as the harnesses' summaries do.

To add a run: put its directory name in DEFAULT_RUNS (the kind of plot is
detected from the result files, e.g. accumulate vs churn from the phases in
storage_growth.csv) and run the command above.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter, MaxNLocator  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
BENCH = REPO / "benchmarks"
PLOTS = BENCH / "plots"

# Clean AWS run at ea47be3 (1 s SPIRE intervals, unlimited CPU credits), plus the
# accumulate rerun at a69d56f, which differs from ea47be3 only in register-entries.sh.
DEFAULT_RUNS = [
    "20261121T204658Z-vend-to-svid",
    "20261121T205509Z-vend-to-access-poll",
    "20261121T210346Z-vend-to-access-child-py",
    "20261121T211226Z-revoke-to-deny",
    "20261121T212106Z-revocation-speed",
    "20261121T213006Z-storage-growth-churn",
    # Accumulate rerun at a69d56f (same VM and settings; the ea47be3 attempt failed with no data).
    "20261121T215047Z-storage-growth-accumulate",
]

# Superseded AWS run at c1e4dbe (5 s intervals, Standard credits, throttled)
# against the clean run, metric by metric.
COMPARISON = {
    "name": "20261121-aws-c1e4dbe-vs-ea47be3_p50-p95.png",
    "old_label": "c1e4dbe: 5 s intervals, Standard credits",
    "new_label": "ea47be3: 1 s intervals, unlimited credits",
    "metrics": [
        # (panel title, old run, new run, CSV file, column)
        ("Vend → child holds\nits X.509-SVID", "20261121T184346Z-vend-to-svid",
         "20261121T204658Z-vend-to-svid", "vend_to_svid.csv", "vend_to_svid_ms"),
        ("Vend → first 200\n(child polls every 20 ms)", "20261121T190208Z-vend-to-access-poll",
         "20261121T205509Z-vend-to-access-poll", "vend_to_access.csv", "vend_to_access_ms"),
        ("Vend → first 200\n(child.py, 2 s retries)", "20261121T194348Z-vend-to-access-child-py",
         "20261121T210346Z-vend-to-access-child-py", "vend_to_access.csv", "vend_to_access_ms"),
        ("Revoke → first 403", "20261121T192916Z-revoke-to-deny",
         "20261121T211226Z-revoke-to-deny", "revoke_to_deny.csv", "revoke_to_deny_ms"),
        ("Revoke → child's\nSVID gone", "20261121T192916Z-revoke-to-deny",
         "20261121T211226Z-revoke-to-deny", "revoke_to_deny.csv", "revoke_to_identity_gone_ms"),
    ],
}

AWS_CLEAN = "AWS t3a.large (unlimited credits), SPIRE agent sync and server cache reload every 1 s"

# Reference categorical palette (validated light-mode steps).
BLUE, ORANGE, AQUA, VIOLET = "#2a78d6", "#eb6834", "#1baf7a", "#6250d6"
GREEN, RED, YELLOW = "#008300", "#e34948", "#eda100"
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#8a8984"
GRID, AXIS = "#e4e3de", "#b9b8b0"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10.5,
    "axes.edgecolor": AXIS,
    "axes.labelcolor": INK2,
    "axes.labelsize": 11,
    "xtick.color": INK2,
    "ytick.color": INK2,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.frameon": False,
    "legend.fontsize": 10.5,
    "lines.linewidth": 2.0,
    "savefig.dpi": 150,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})


# ---------------------------------------------------------------- data helpers

def read_csv(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def num(v: str | None) -> float | None:
    if v is None or v == "":
        return None
    try:
        x = float(v)
    except ValueError:
        return None
    return None if math.isnan(x) else x


def column(rows: list[dict], name: str) -> list[float]:
    """Non-empty numeric values of a column, in row order."""
    return [x for x in (num(r.get(name)) for r in rows) if x is not None]


def ok_rows(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r.get("ok", "True") == "True"]


def nearest_rank(vals: list[float], p: float) -> float:
    s = sorted(vals)
    k = max(1, math.ceil(p / 100 * len(s)))
    return s[k - 1]


def check_summary(summary: dict, key: str, vals: list[float], where: str) -> None:
    """Warn if the CSV-derived p50/p95/n disagree with the harness summary."""
    block = summary.get(key)
    if not isinstance(block, dict) or "p50" not in block:
        return
    got = {"n": len(vals), "p50": nearest_rank(vals, 50), "p95": nearest_rank(vals, 95)}
    for k, v in got.items():
        if abs(float(block[k]) - v) > 0.01:
            print(f"WARNING {where}: {key} {k} from CSV = {v}, summary = {block[k]}", file=sys.stderr)


def fmt_ms(x: float) -> str:
    return f"{x:,.0f} ms" if x >= 100 else f"{x:.1f} ms"


# ---------------------------------------------------------------- style helpers

def new_fig(w: float, h: float, nrows: int = 1, ncols: int = 1, **kw):
    fig, axes = plt.subplots(nrows, ncols, figsize=(w, h), squeeze=False, **kw)
    for ax in axes.flat:
        style_ax(ax)
    return fig, axes


def style_ax(ax) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color(AXIS)
    ax.spines["bottom"].set_color(AXIS)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(length=3, color=AXIS)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}" if abs(v) >= 10 or v == 0 else f"{v:g}"))


def titles(fig, title: str, subtitle: str, top: float = 0.83) -> None:
    fig.text(0.06, 0.965, title, fontsize=15, color=INK, ha="left", va="top")
    fig.text(0.06, 0.905, subtitle, fontsize=10.5, color=INK2, ha="left", va="top")
    fig.subplots_adjust(top=top, left=0.08, right=0.97, bottom=0.12)


def pct_axis(ax, label: str) -> None:
    ax.set_ylim(0, 1.0)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:.0%}"))
    ax.set_ylabel(label)


def ecdf(ax, vals: list[float], color: str, label: str, lw: float = 2.0, ls: str = "-") -> None:
    s = sorted(vals)
    n = len(s)
    xs = [s[0]] + s
    ys = [0.0] + [(i + 1) / n for i in range(n)]
    ax.step(xs, ys, where="post", color=color, label=label, linewidth=lw, linestyle=ls)


def median_marker(ax, vals: list[float], color: str, text: str, side: str = "left",
                  dy: float = 0.0, offset: float = 10) -> None:
    m = nearest_rank(vals, 50)
    ax.plot([ax.get_xlim()[0], m], [0.5, 0.5], color=MUTED, linestyle=(0, (3, 3)), linewidth=1)
    ax.plot([m, m], [0, 0.5], color=MUTED, linestyle=(0, (3, 3)), linewidth=1)
    ax.plot([m], [0.5], "o", color=color, markersize=7, markeredgecolor="white", markeredgewidth=1.5, zorder=5)
    off = -offset if side == "left" else offset
    ax.annotate(text, (m, 0.5 + dy), xytext=(off, 8 if dy >= 0 else -8), textcoords="offset points",
                ha="right" if side == "left" else "left", va="bottom" if dy >= 0 else "top",
                color=INK2, fontsize=10)


def trial_axis(ax, n: int) -> None:
    ax.set_xlim(0.3, n + 0.7)
    step = 1 if n <= 30 else 5
    ticks = [1] + list(range(step, n + 1, step)) if step > 1 else list(range(1, n + 1))
    ax.set_xticks(sorted(set(ticks)))
    ax.set_xlabel("Trial")


def save(fig, out: Path, written: list[Path]) -> None:
    fig.savefig(out)
    plt.close(fig)
    written.append(out)
    print(f"wrote {out.relative_to(REPO) if out.is_relative_to(REPO) else out}")


# ---------------------------------------------------------------- vend-to-svid

def plot_vend_to_svid(run: Path, out: Path, written: list[Path]) -> None:
    rows = ok_rows(read_csv(run / "vend_to_svid.csv"))
    summary = json.loads((run / "vend_to_svid_summary.json").read_text())
    total = column(rows, "vend_to_svid_ms")
    check_summary(summary, "vend_to_svid_ms", total, run.name)
    n = len(total)
    sub = f"{AWS_CLEAN}; random start per trial; {n} trials"

    # CDF of t0 -> t3, with t0 -> t1 (vend returns: entry registered) for reference.
    t01 = column(rows, "vend_round_trip_ms")
    fig, axes = new_fig(12, 5.6)
    ax = axes[0, 0]
    ecdf(ax, t01, MUTED, "t0 → t1: vend returns 201, registration entry created", lw=1.6, ls="--")
    ecdf(ax, total, BLUE, "t0 → t3: child's Workload API answer holds the new X.509-SVID")
    ax.set_xlim(0, max(total) * 1.08)
    pct_axis(ax, "Share of trials at or below x")
    median_marker(ax, total, BLUE,
                  f"t0 → t3 median {fmt_ms(nearest_rank(total, 50))}; p95 {fmt_ms(nearest_rank(total, 95))}\n"
                  f"range {min(total):,.0f}–{max(total):,.0f} ms", side="right", dy=-0.03)
    ax.annotate(f"t0 → t1 median {fmt_ms(nearest_rank(t01, 50))}", (nearest_rank(t01, 50), 0.5),
                xytext=(14, 40), textcoords="offset points", color=INK2, fontsize=10)
    ax.set_xlabel("Time since the parent sent POST /delegations (ms)")
    ax.legend(loc="upper left", bbox_to_anchor=(0.06, 1.0))
    titles(fig, "Time to create a child identity: vend to SVID in the child, cumulative", sub)
    save(fig, out / f"{run.name}_cdf.png", written)

    # Stage breakdown per trial: t0->t1, t1->t2, t2->t3 stacked.
    trials = [int(r["trial"]) for r in rows]
    s1 = [float(r["vend_round_trip_ms"]) for r in rows]
    s2 = [float(r["agent_log_after_send_ms"]) - float(r["vend_round_trip_ms"]) for r in rows]
    s3 = [float(r["vend_to_svid_ms"]) - float(r["agent_log_after_send_ms"]) for r in rows]
    fig, axes = new_fig(12.5, 5.8)
    ax = axes[0, 0]
    w = 0.72
    ax.bar(trials, s1, w, color=MUTED, label="t0 → t1: vend round trip (entry created on the SPIRE server)",
           edgecolor="white", linewidth=0.6)
    ax.bar(trials, s2, w, bottom=s1, color=BLUE,
           label="t1 → t2: until the child's node agent logs the entry (agent sync)", edgecolor="white", linewidth=0.6)
    b3 = [a + b for a, b in zip(s1, s2)]
    ax.bar(trials, s3, w, bottom=b3, color=ORANGE,
           label="t2 → t3: agent log line to the child's first answer holding the SVID", edgecolor="white",
           linewidth=0.6)
    trial_axis(ax, max(trials))
    ax.set_ylabel("t0 → t3 (ms)")
    ax.set_ylim(0, max(total) * 1.22)
    ax.yaxis.set_major_locator(MaxNLocator(6))
    ax.legend(loc="upper left", ncol=1, fontsize=10)
    titles(fig, "Time to create a child identity, split into stages, by trial",
           sub + f"\nmedians: t0→t1 {nearest_rank(s1, 50):.0f} ms, t1→t2 {nearest_rank(s2, 50):,.0f} ms, "
                 f"t2→t3 {nearest_rank(s3, 50):.0f} ms", top=0.80)
    save(fig, out / f"{run.name}_t0-t3.png", written)


# ---------------------------------------------------------------- vend-to-access

def access_series(rows: list[dict], style: str):
    """(label, column) of the 'created' series: the SVID the child fetches first."""
    if style == "child-py":
        return "created: child holds its X.509-SVID", "vend_to_x509_ms"
    return "created: child holds its JWT-SVID", "vend_to_jwt_ms"


def plot_vend_to_access(run: Path, out: Path, written: list[Path]) -> None:
    rows = ok_rows(read_csv(run / "vend_to_access.csv"))
    summary = json.loads((run / "vend_to_access_summary.json").read_text())
    style = summary.get("style") or rows[0].get("style")
    usable = column(rows, "vend_to_access_ms")
    check_summary(summary, "vend_to_access_ms", usable, run.name)
    c_label, c_col = access_series(rows, style)
    created = column(rows, c_col)
    check_summary(summary, next(k for k in summary if k.startswith(c_col)), created, run.name)
    # created -> usable per trial: first 200 received minus the created stamp.
    by_trial = [(int(r["trial"]), float(r[c_col]), float(r["vend_to_access_ms"]),
                 float(r["vend_to_access_ms"]) - float(r[c_col]), int(r.get("x509_attempts") or 0))
                for r in rows]
    gap = [t[3] for t in by_trial]
    t01 = column(rows, "vend_round_trip_ms")
    t02 = column(rows, "agent_log_after_send_ms")
    n = len(usable)
    if style == "child-py":
        how = ("child follows child.py: X.509 then JWT fetch, up to 30 attempts 2 s apart, then one GET; "
               "the 2 s retry, not SPIRE, sets most of the wait")
    else:
        how = "child fetches a JWT-SVID every 20 ms and calls the resource as soon as it has one"
    sub = f"{AWS_CLEAN}; {n} trials\n{how}"
    u_label = "usable: child receives its first 200 from the resource"
    g_label = f"{c_label.split(': ')[1].replace('child holds its ', '')} held → first 200"

    # CDF
    fig, axes = new_fig(12, 6.0)
    ax = axes[0, 0]
    ecdf(ax, t01, MUTED, "vend returns 201 (registration entry created)", lw=1.6, ls="--")
    ecdf(ax, t02, VIOLET, "child's node agent logs the entry (t2)", lw=1.4, ls=":")
    ecdf(ax, created, BLUE, c_label)
    ecdf(ax, usable, ORANGE, u_label, lw=1.6)
    ax.set_xlim(0, max(usable) * 1.08)
    pct_axis(ax, "Share of trials at or below x")
    side = "left" if style == "child-py" else "right"
    median_marker(ax, usable, ORANGE,
                  f"usable: median {fmt_ms(nearest_rank(usable, 50))}, p95 {fmt_ms(nearest_rank(usable, 95))}\n"
                  f"created: median {fmt_ms(nearest_rank(created, 50))}, p95 {fmt_ms(nearest_rank(created, 95))}\n"
                  f"created → usable: median {fmt_ms(nearest_rank(gap, 50))}\n"
                  f"agent has the entry (t2): median {fmt_ms(nearest_rank(t02, 50))}",
                  side=side, dy=-0.04, offset=22)
    ax.set_xlabel("Time since the parent sent POST /delegations (ms)")
    if style == "child-py":
        ax.legend(loc="upper left", bbox_to_anchor=(0.05, 1.0))
    else:
        ax.legend(loc="lower right")
    titles(fig, "Time to create vs time until usable, cumulative", sub, top=0.80)
    save(fig, out / f"{run.name}_cdf.png", written)

    # By trial: both latencies on the same axes, the gap below.
    tr = [t[0] for t in by_trial]
    fig, axes = new_fig(12.5, 7.4, nrows=2, gridspec_kw={"height_ratios": [3, 1.3], "hspace": 0.32})
    ax, ax2 = axes[0, 0], axes[1, 0]
    ax.plot(tr, [t[1] for t in by_trial], color=BLUE, marker="o", markersize=5, label=c_label,
            markeredgecolor="white", markeredgewidth=0.8)
    ax.plot(tr, [t[2] for t in by_trial], color=ORANGE, marker="o", markersize=3.5, linewidth=1.2,
            linestyle=(0, (4, 2)), label=u_label)
    if style == "child-py":
        for t in by_trial:
            if t[4] == 1:
                ax.annotate(f"trial {t[0]}: SVID present at the first attempt, no 2 s retry "
                            f"({t[2]:,.0f} ms)", (t[0], t[2]), xytext=(12, 4), textcoords="offset points",
                            color=INK2, fontsize=10)
    ax.set_ylabel("Time since vend sent (ms)")
    ax.set_ylim(0, max(usable) * 1.25)
    ax.yaxis.set_major_locator(MaxNLocator(6))
    trial_axis(ax, max(tr))
    ax.set_xlabel("")
    ax.legend(loc="upper left", ncol=2)
    ax2.bar(tr, gap, 0.7, color=AQUA)
    trial_axis(ax2, max(tr))
    ax2.set_ylabel("ms")
    ax2.set_title(f"created → usable ({g_label})", loc="left", fontsize=11, color=INK)
    ax2.yaxis.set_major_locator(MaxNLocator(4))
    titles(fig, "Time to create vs time until usable, by trial", sub, top=0.84)
    fig.subplots_adjust(bottom=0.08)
    save(fig, out / f"{run.name}_by-trial.png", written)


# ---------------------------------------------------------------- revoke-to-deny

def plot_revoke_to_deny(run: Path, out: Path, written: list[Path]) -> None:
    rows = ok_rows(read_csv(run / "revoke_to_deny.csv"))
    summary = json.loads((run / "revoke_to_deny_summary.json").read_text())
    deny = column(rows, "revoke_to_deny_ms")
    gone = column(rows, "revoke_to_identity_gone_ms")
    pol = column(rows, "policy_dispose_after_send_ms")
    check_summary(summary, "revoke_to_deny_ms", deny, run.name)
    check_summary(summary, "revoke_to_identity_gone_ms", gone, run.name)
    n = len(deny)
    sub = f"{AWS_CLEAN}; DELETE at a random point of the sync cycle; {n} trials"
    l_deny = "DELETE → first 403 from the resource"
    l_gone = "DELETE → first failed SVID fetch (identity gone)"

    fig, axes = new_fig(13, 5.6, ncols=2, gridspec_kw={"wspace": 0.12})
    a1, a2 = axes[0, 0], axes[0, 1]
    ecdf(a1, deny, BLUE, l_deny)
    a1.set_xlim(0, max(deny) * 1.3)
    pct_axis(a1, "Share of trials at or below x")
    pm = nearest_rank(pol, 50)
    a1.axvline(pm, color=INK2, linestyle=(0, (5, 3)), linewidth=1.1)
    a1.text(pm - max(deny) * 0.015, 0.93, f"grant removed from OPA\n(median {pm:.1f} ms)", color=INK2, fontsize=10,
            va="top", ha="right")
    median_marker(a1, deny, BLUE, f"median {fmt_ms(nearest_rank(deny, 50))}; p95 {fmt_ms(nearest_rank(deny, 95))}\n"
                                  f"range {min(deny):.1f}–{max(deny):.1f} ms", side="right", dy=-0.04)
    a1.set_xlabel("t0 → first 403 (ms)")
    a1.legend(loc="upper left", bbox_to_anchor=(0, 1.13))
    ecdf(a2, gone, ORANGE, l_gone)
    a2.set_xlim(0, max(gone) * 1.08)
    pct_axis(a2, "")
    a2.set_yticklabels([])
    median_marker(a2, gone, ORANGE, f"median {fmt_ms(nearest_rank(gone, 50))}; p95 {fmt_ms(nearest_rank(gone, 95))}\n"
                                    f"range {min(gone):,.0f}–{max(gone):,.0f} ms", side="left", dy=0.02)
    a2.set_xlabel("t0 → first failed SVID fetch (ms)")
    a2.legend(loc="upper left", bbox_to_anchor=(0, 1.13))
    titles(fig, "Revocation to the revoked child's first 403 and to its SVID being withdrawn, cumulative", sub,
           top=0.78)
    save(fig, out / f"{run.name}_cdf.png", written)

    tr = [int(r["trial"]) for r in rows]
    fig, axes = new_fig(12.5, 7.4, nrows=2, gridspec_kw={"hspace": 0.38})
    a1, a2 = axes[0, 0], axes[1, 0]
    a1.plot(tr, [float(r["revoke_to_deny_ms"]) for r in rows], color=BLUE, marker="o", markersize=5,
            markeredgecolor="white", markeredgewidth=0.8)
    a1.set_ylim(0, max(deny) * 1.2)
    a1.set_ylabel("ms")
    a1.set_title(l_deny, loc="left", fontsize=11.5, color=INK)
    trial_axis(a1, max(tr))
    a1.set_xlabel("")
    a2.plot(tr, [float(r["revoke_to_identity_gone_ms"]) for r in rows], color=ORANGE, marker="o", markersize=5,
            markeredgecolor="white", markeredgewidth=0.8)
    a2.set_ylim(0, max(gone) * 1.15)
    a2.set_ylabel("ms")
    a2.set_title(l_gone, loc="left", fontsize=11.5, color=INK)
    trial_axis(a2, max(tr))
    titles(fig, "Revocation to first 403 and to SVID withdrawn, by trial (note the different y scales)", sub,
           top=0.81)
    fig.subplots_adjust(bottom=0.08)
    save(fig, out / f"{run.name}_by-trial.png", written)


# ---------------------------------------------------------------- revocation-speed

def plot_revocation_speed(run: Path, out: Path, written: list[Path]) -> None:
    rows = ok_rows(read_csv(run / "revocation_speed.csv"))
    summary = json.loads((run / "revocation_speed_summary.json").read_text())
    d = column(rows, "delta_ms")
    pol = column(rows, "policy_dispose_c_ms")
    p50, p95 = nearest_rank(d, 50), nearest_rank(d, 95)
    if abs(p50 - summary["p50_ms"]) > 0.01 or abs(p95 - summary["p95_ms"]) > 0.01 or len(d) != summary["n"]:
        print(f"WARNING {run.name}: p50/p95/n from CSV {p50}/{p95}/{len(d)} differ from the summary", file=sys.stderr)
    under = sum(1 for r in rows if r.get("under_1s") == "True")
    sub = (f"{AWS_CLEAN}\nchain P → C → G, P revokes C, G polls every 20 ms; {len(d)} trials, "
           f"{under}/{len(d)} under the 1 s target")
    label = "DELETE of C → grandchild G's first 403"

    fig, axes = new_fig(12, 5.6)
    ax = axes[0, 0]
    ecdf(ax, d, BLUE, label)
    ax.set_xlim(0, max(d) * 1.15)
    pct_axis(ax, "Share of trials at or below x")
    pm = nearest_rank(pol, 50)
    ax.axvline(pm, color=INK2, linestyle=(0, (5, 3)), linewidth=1.1)
    ax.text(pm - max(d) * 0.012, 0.84, f"C's grant removed from OPA\n(median {pm:.1f} ms)", color=INK2,
            fontsize=10, va="top", ha="right")
    median_marker(ax, d, BLUE, f"median {fmt_ms(p50)}; p95 {fmt_ms(p95)}\nrange {min(d):.1f}–{max(d):.1f} ms",
                  side="right", dy=-0.04)
    ax.set_xlabel("t0 (DELETE sent) → G's first 403 (ms)")
    ax.legend(loc="upper left")
    titles(fig, "Cascade revocation: revoking a child cuts off its grandchild, cumulative", sub, top=0.80)
    save(fig, out / f"{run.name}_cdf.png", written)

    tr = [int(r["trial"]) for r in rows]
    fig, axes = new_fig(12, 5.4)
    ax = axes[0, 0]
    ax.plot(tr, [float(r["delta_ms"]) for r in rows], color=BLUE, marker="o", markersize=6,
            markeredgecolor="white", markeredgewidth=0.8, label=label)
    ax.plot(tr, [float(r["policy_dispose_c_ms"]) for r in rows], color=MUTED, marker="o", markersize=4,
            linewidth=1.2, linestyle=(0, (4, 2)), label="DELETE → policy engine removes C's grant")
    trial_axis(ax, max(tr))
    ax.set_ylim(0, max(d) * 1.3)
    ax.set_ylabel("ms")
    ax.legend(loc="upper left", ncol=2)
    titles(fig, "Cascade revocation, by trial", sub, top=0.80)
    save(fig, out / f"{run.name}_by-trial.png", written)


# ---------------------------------------------------------------- storage growth

MB = 1e6


def mb_axis(ax) -> None:
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / MB:.1f}"))
    ax.set_ylabel("MB (10⁶ bytes)")


def storage_series(prefix: str) -> list[tuple[str, str, str, str]]:
    """(label, column, color, linestyle) for one volume ('spire' or 'vending')."""
    if prefix == "spire":
        main, wal = "spire_file_datastore_sqlite3_apparent_bytes", "spire_file_datastore_sqlite3_wal_apparent_bytes"
    else:
        main, wal = "vending_file_vending_db_apparent_bytes", "vending_file_vending_db_wal_apparent_bytes"
    out = [
        ("on disk, all files (apparent)", f"{prefix}_disk_apparent_bytes", BLUE, "-"),
        ("on disk, all files (allocated)", f"{prefix}_disk_alloc_bytes", ORANGE, (0, (4, 2))),
        ("-wal file", wal, VIOLET, "-"),
        ("main .db file", main, RED, "-"),
        ("logical SQLite used (pages − freelist)", f"{prefix}_db_used_bytes", AQUA, "-"),
    ]
    if prefix == "vending":
        out.append(("audit.jsonl", "vending_file_audit_jsonl_apparent_bytes", YELLOW, "-"))
    return out


VOLUMES = [("spire", "SPIRE server (spire-data)"), ("vending", "Vending service (vending-data)")]


def plot_storage_churn(run: Path, rows: list[dict], out: Path, written: list[Path]) -> None:
    pts = [r for r in rows if r["phase"] == "churn"]
    x = [int(r["n_vended_total"]) for r in pts]
    live = {int(r["n_live"]) for r in pts}
    fig, axes = new_fig(13, 5.8, ncols=2, gridspec_kw={"wspace": 0.2})
    for ax, (prefix, title) in zip(axes[0], VOLUMES):
        for label, col, color, ls in storage_series(prefix):
            ax.plot(x, [float(r[col]) for r in pts], color=color, linestyle=ls, marker="o", markersize=4.5,
                    label=label)
        mb_axis(ax)
        ax.set_title(title, loc="left", fontsize=11.5, color=INK)
        ax.set_xlabel("vend-then-dispose cycles (count)")
        ax.set_ylim(bottom=0)
        ax.legend(loc="center right" if prefix == "spire" else "upper left", fontsize=9.5)
    titles(fig, "Storage after repeated vend-then-dispose cycles (live children stay "
                f"{'/'.join(str(v) for v in sorted(live))})",
           f"{AWS_CLEAN}; checkpoints at 0, 1, 2, 25, 50, 75, 100 cycles; idle checkpoints omitted", top=0.82)
    save(fig, out / f"{run.name}_bytes-vs-cycles.png", written)


def plot_storage_accumulate(run: Path, rows: list[dict], out: Path, written: list[Path],
                            conditions: str) -> None:
    acc = [r for r in rows if r["phase"] == "accumulate"]
    drn = [r for r in rows if r["phase"] == "drain"]
    peak = max(int(r["n_live"]) for r in acc)

    fig, axes = new_fig(13, 7.0, ncols=2, gridspec_kw={"wspace": 0.2})
    for ax, (prefix, title) in zip(axes[0], VOLUMES):
        for label, col, color, ls in storage_series(prefix):
            ax.plot([int(r["n_live"]) for r in acc], [float(r[col]) for r in acc], color=color, linestyle=ls,
                    marker="o", markersize=4.5, label=label)
            if drn:
                ax.plot([int(r["n_live"]) for r in drn], [float(r[col]) for r in drn], color=color,
                        linestyle=":", linewidth=1.4, marker="x", markersize=4.5, alpha=0.8)
        mb_axis(ax)
        ax.set_ylim(bottom=0)
        ax.set_title(title, loc="left", fontsize=11.5, color=INK)
        ax.set_xlabel("live children (count); drain runs right to left")
    # One legend under both panels (the vending panel has every series), clear of the data.
    handles, labels = axes[0, 1].get_legend_handles_labels()
    if drn:
        handles.append(plt.Line2D([], [], color=MUTED, linestyle=":", marker="x"))
        labels.append("dotted, ×: drain (dispose all, oldest first)")
    fig.legend(handles, labels, loc="lower center", ncol=4, fontsize=9.5, bbox_to_anchor=(0.5, 0.0))
    titles(fig, f"Storage while {peak} children accumulate, then drain", conditions, top=0.81)
    fig.subplots_adjust(bottom=0.24)
    save(fig, out / f"{run.name}_bytes-vs-n.png", written)

    # OPA GET /v1/policies response size against live grant modules.
    pts = [(int(r["opa_live_modules"]), num(r["opa_last_get_resp_bytes"])) for r in acc]
    pts = [(a, b) for a, b in pts if b is not None]
    ops_path = run / "storage_growth_ops.csv"
    if ops_path.exists():
        ops = [o for o in read_csv(ops_path) if o["op"] == "vend" and num(o.get("opa_get_resp_bytes")) is not None]
        pts = [(int(float(o["opa_get_live_modules"])), float(o["opa_get_resp_bytes"])) for o in ops
               if num(o.get("opa_get_live_modules")) is not None] or pts
    if pts:
        fig, axes = new_fig(11, 5.4)
        ax = axes[0, 0]
        ax.plot([p[0] for p in pts], [p[1] / 1e3 for p in pts], color=BLUE, marker="o", markersize=3.5,
                linewidth=1.2)
        ax.set_xlabel("live grant modules in OPA when the policy engine read them (count)")
        ax.set_ylabel("GET /v1/policies response (kB)")
        ax.set_ylim(bottom=0)
        titles(fig, "Size of the policy engine's GET /v1/policies, one point per vend", conditions)
        save(fig, out / f"{run.name}_opa-resp-bytes.png", written)

    # Per-table dbstat bytes: step 0, peak, end of drain; only tables whose size changed.
    tpath = run / "storage_growth_tables.csv"
    if tpath.exists():
        trows = read_csv(tpath)
        steps = {int(r["step"]): r for r in rows}
        s0 = min(int(r["step"]) for r in acc)
        s_peak = max((int(r["step"]) for r in acc if int(r["n_live"]) == peak))
        s_end = max(int(r["step"]) for r in drn) if drn else None
        size = defaultdict(dict)
        for t in trows:
            size[(t["db"], t["name"])][int(t["step"])] = float(t["bytes"])
        cols = [(s0, f"N = {steps[s0]['n_live']}", MUTED), (s_peak, f"N = {peak} (peak)", BLUE)]
        if s_end is not None:
            cols.append((s_end, "after drain", ORANGE))
        fig, axes = new_fig(14, 6.4, ncols=2, gridspec_kw={"wspace": 0.15})
        for ax, (db, title) in zip(axes[0], [("spire", "SPIRE server"), ("vending", "Vending service")]):
            names = [nm for (d, nm), v in size.items() if d == db and len({v.get(s) for s, _, _ in cols}) > 1]
            names.sort(key=lambda nm: -size[(db, nm)].get(s_peak, 0))
            w = 0.8 / len(cols)
            for i, (s, lab, color) in enumerate(cols):
                ax.bar([j + (i - (len(cols) - 1) / 2) * w for j in range(len(names))],
                       [size[(db, nm)].get(s, 0) / 1e3 for nm in names], w, color=color, label=lab,
                       edgecolor="white", linewidth=0.6)
            ax.set_xticks(range(len(names)))
            ax.set_xticklabels(names, rotation=35, ha="right", fontsize=8.5)
            ax.set_ylabel("dbstat bytes (kB, pages × page size)")
            ax.set_title(f"{title}: tables and indexes whose size changed", loc="left", fontsize=11.5, color=INK)
            ax.legend(loc="upper right", fontsize=9.5)
        titles(fig, "Per-table SQLite size at the start, at the peak and after the drain", conditions, top=0.81)
        fig.subplots_adjust(bottom=0.3)
        save(fig, out / f"{run.name}_per-table-bytes.png", written)


def storage_conditions(run: Path) -> str:
    """Interval and cap conditions as recorded by the run, not as the template text says."""
    s = run / "storage_growth_summary.json"
    cap = None
    if s.exists():
        cap = json.loads(s.read_text()).get("host", {}).get("max_live_children_in_running_pod")
    where = AWS_CLEAN if run.name in DEFAULT_RUNS else "Local kind cluster; SPIRE intervals 1 s (per-cluster override)"
    return where + (f"; MAX_LIVE_CHILDREN = {cap} in the running pod" if cap is not None else "")


def plot_storage(run: Path, out: Path, written: list[Path]) -> None:
    rows = read_csv(run / "storage_growth.csv")
    phases = {r["phase"] for r in rows}
    if "accumulate" in phases:
        plot_storage_accumulate(run, rows, out, written, storage_conditions(run))
    if "churn" in phases:
        plot_storage_churn(run, rows, out, written)


# ---------------------------------------------------------------- comparison

def plot_comparison(out: Path, written: list[Path]) -> None:
    ms = COMPARISON["metrics"]
    fig, axes = new_fig(15, 6.8, ncols=len(ms), gridspec_kw={"wspace": 0.35})
    for ax, (title, old, new, fname, col) in zip(axes[0], ms):
        vals = {}
        for key, run in (("old", old), ("new", new)):
            v = column(ok_rows(read_csv(BENCH / run / fname)), col)
            vals[key] = (nearest_rank(v, 50), nearest_rank(v, 95), len(v))
        xs = [0, 1]
        w = 0.36
        for i, (key, color, label) in enumerate((("old", ORANGE, COMPARISON["old_label"]),
                                                 ("new", BLUE, COMPARISON["new_label"]))):
            p50, p95, n = vals[key]
            bars = ax.bar([x + (i - 0.5) * w for x in xs], [p50, p95], w, color=color, label=label,
                          edgecolor="white", linewidth=0.8)
            for b, v in zip(bars, (p50, p95)):
                txt = f"{v / 1000:.2f} s" if v >= 1000 else f"{v:.0f} ms"
                ax.text(b.get_x() + b.get_width() / 2, v, txt, ha="center", va="bottom", fontsize=8.5,
                        color=INK2, rotation=0)
        ax.set_xticks(xs)
        ax.set_xticklabels(["p50", "p95"])
        top = max(vals["old"][1], vals["new"][1])
        ax.set_ylim(0, top * 1.15)
        ax.yaxis.set_major_locator(MaxNLocator(5))
        if top >= 1000:
            ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1000:g}"))
            ax.set_ylabel("seconds")
        else:
            ax.set_ylabel("ms")
        ax.set_title(title, loc="left", fontsize=10.5, color=INK)
        ax.text(0, -0.17, f"n = {vals['old'][2]} / {vals['new'][2]}", transform=ax.transAxes, fontsize=9,
                color=MUTED)
    h, l = axes[0, 0].get_legend_handles_labels()
    fig.legend(h, l, loc="upper left", bbox_to_anchor=(0.06, 0.80), ncol=2, fontsize=10.5)
    fig.text(0.06, 0.965, "Superseded AWS run vs clean AWS run: p50 and p95 of the shared metrics", fontsize=15,
             color=INK, ha="left", va="top")
    fig.text(0.06, 0.915,
             "Caution: the SPIRE intervals (5 s → 1 s) AND the CPU credit mode (Standard, throttled at a zero "
             "balance → unlimited) changed together,\nso this figure cannot separate their effects. "
             "The VM instance and its Docker build (29.6.2 → 29.1.3, per host.txt) also differ.\n"
             "Same instance type and harness code; 50 trials per metric, one run each.",
             fontsize=10.5, color=INK, fontweight="bold", ha="left", va="top")
    fig.subplots_adjust(top=0.66, left=0.05, right=0.99, bottom=0.12)
    save(fig, out / COMPARISON["name"], written)


# ---------------------------------------------------------------- vending vs end to end

# Each stage is computed per trial from the CSV's nanosecond stamps, so the stages of a
# trial add up exactly to its end-to-end time (no subtraction of percentiles).
STAGES_NAME = "20261121-vend-vs-end-to-end_stages.png"
STAGE_COLORS = {"vend": MUTED, "prop": BLUE, "issue": ORANGE, "retry": VIOLET, "use": AQUA}
STAGE_LABELS = {
    "vend": "Vending t0 → t1: vend POST until the SPIRE entry exists",
    "prop": "Propagation t1 → t2: until the child's node agent logs the entry",
    "issue": "Issuance t2 → child holds its SVID (X.509, or JWT in the poll runs)",
    "retry": "child.py idle t2 → its next 2 s retry returns the X.509-SVID",
    "use": "Use: SVID held → first HTTP 200 from the resource",
}
# (label, run directory, kind)
STAGE_RUNS = [
    ("Clean AWS, 1 s · to X.509-SVID", "20261121T204658Z-vend-to-svid", "svid"),
    ("Local, 1 s · to X.509-SVID", "20261101T234407Z-vend-to-svid-random-phase-1s", "svid"),
    ("Local, 5 s · to X.509-SVID", "20261101T223329Z-vend-to-svid-random-phase", "svid"),
    ("Clean AWS, 1 s · to first 200, poll", "20261121T205509Z-vend-to-access-poll", "poll"),
    ("Local, 1 s · to first 200, poll", "20261102T040134Z-vend-to-access-poll-1s", "poll"),
    ("Clean AWS, 1 s · to first 200, child.py", "20261121T210346Z-vend-to-access-child-py", "child-py"),
    ("Local, 1 s · to first 200, child.py", "20261102T040601Z-vend-to-access-child-py-1s", "child-py"),
]


def stage_rows(run: str, kind: str) -> tuple[list[dict], str]:
    """Per-trial stage durations (ms) of one run, and the end-to-end column they add up to."""
    def d(r: dict, a: str, b: str) -> float:
        return (int(r[b]) - int(r[a])) / 1e6

    if kind == "svid":
        rows = ok_rows(read_csv(BENCH / run / "vend_to_svid.csv"))
        out = [{"vend": d(r, "vend_send_ns", "vend_recv_ns"), "prop": d(r, "vend_recv_ns", "agent_log_ns"),
                "issue": d(r, "agent_log_ns", "svid_obtained_recv_ns"),
                "total": d(r, "vend_send_ns", "svid_obtained_recv_ns")} for r in rows]
        return out, "vend_to_svid_ms"
    rows = ok_rows(read_csv(BENCH / run / "vend_to_access.csv"))
    if kind == "poll":
        out = [{"vend": d(r, "vend_send_ns", "vend_recv_ns"), "prop": d(r, "vend_recv_ns", "agent_log_ns"),
                "issue": d(r, "agent_log_ns", "jwt_obtained_recv_ns"),
                "use": d(r, "jwt_obtained_recv_ns", "access_recv_ns"),
                "total": d(r, "vend_send_ns", "access_recv_ns")} for r in rows]
    else:  # child-py: X.509 (after the retry wait), then JWT, then one GET
        out = [{"vend": d(r, "vend_send_ns", "vend_recv_ns"), "prop": d(r, "vend_recv_ns", "agent_log_ns"),
                "retry": d(r, "agent_log_ns", "x509_obtained_recv_ns"),
                "use": d(r, "x509_obtained_recv_ns", "access_recv_ns"),
                "total": d(r, "vend_send_ns", "access_recv_ns")} for r in rows]
    return out, "vend_to_access_ms"


def plot_stage_breakdown(out: Path, written: list[Path]) -> None:
    """Vending (t0 -> t1) against end to end, stage by stage: latest AWS vs local 1 s vs local 5 s."""
    data = []
    for label, run, kind in STAGE_RUNS:
        rows, col = stage_rows(run, kind)
        summary_file = next((BENCH / run).glob("*_summary.json"))
        check_summary(json.loads(summary_file.read_text()), col, [r["total"] for r in rows], run)
        for r in rows:  # the stages of each trial must add up to its end-to-end time
            if abs(sum(v for k, v in r.items() if k != "total") - r["total"]) > 0.01:
                print(f"WARNING {run}: stages do not add up in a trial", file=sys.stderr)
        data.append((label, run, kind, rows))

    fig = plt.figure(figsize=(14, 10.5))
    gs = fig.add_gridspec(2, 1, height_ratios=[1.25, 1.0], hspace=0.42)
    ax = fig.add_subplot(gs[0])
    style_ax(ax)
    ax.grid(axis="y", visible=False)
    ax.grid(axis="x", color=GRID, linewidth=0.8)

    # Panel A: mean of each stage (means add up to the mean end-to-end time), linear seconds.
    ys = list(range(len(data)))[::-1]
    seen: set[str] = set()
    for y, (label, run, kind, rows) in zip(ys, data):
        left = 0.0
        n = len(rows)
        mean_total = sum(r["total"] for r in rows) / n
        for key in ("vend", "prop", "issue", "retry", "use"):
            if key not in rows[0]:
                continue
            m = sum(r[key] for r in rows) / n
            ax.barh(y, m / 1000, left=left / 1000, height=0.62, color=STAGE_COLORS[key],
                    edgecolor="white", linewidth=1.5, label=STAGE_LABELS[key] if key not in seen else None)
            seen.add(key)
            if m / mean_total >= 0.12:
                ax.text((left + m / 2) / 1000, y, f"{m / mean_total:.0%}", ha="center", va="center",
                        fontsize=9.5, color="white", fontweight="bold")
            left += m
        tot = [r["total"] for r in rows]
        vend = [r["vend"] for r in rows]
        ax.text(left / 1000 + 0.08, y,
                f"end to end p50 {nearest_rank(tot, 50) / 1000:.2f} s, p95 {nearest_rank(tot, 95) / 1000:.2f} s"
                f"  ·  vending p50 {nearest_rank(vend, 50):.0f} ms ({sum(vend) / sum(tot):.1%})  ·  n = {n}", va="center", ha="left", fontsize=9.5, color=INK2)
    ax.set_yticks(ys)
    ax.set_yticklabels([d[0] for d in data], fontsize=10)
    ax.set_xlim(0, 10.5)
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    ax.set_xlabel("Mean time per stage, stacked (s). White labels and (%): share of the mean end-to-end time. "
                  "All stages per trial from the CSV stamps")
    ax.set_title("A. Where the time goes: mean per stage, each run's own trials", loc="left", fontsize=11.5,
                 color=INK)
    ax.legend(loc="upper left", bbox_to_anchor=(-0.02, -0.13), ncol=2, fontsize=9.5)

    # Panel B: every trial's stage durations on a log axis, X.509 runs plus the poll runs' use step.
    bx = fig.add_subplot(gs[1])
    style_ax(bx)
    bx.grid(axis="y", visible=False)
    bx.grid(axis="x", color=GRID, linewidth=0.8, which="major")
    groups = [("Clean AWS, 1 s", data[0][3], data[3][3]), ("Local, 1 s", data[1][3], data[4][3]),
              ("Local, 5 s", data[2][3], None)]
    offsets = {"vend": 0.27, "prop": 0.09, "issue": -0.09, "use": -0.27}
    for gi, (glabel, svid_rows, poll_rows) in enumerate(groups):
        y0 = len(groups) - 1 - gi
        for key in ("vend", "prop", "issue", "use"):
            src = poll_rows if key == "use" else svid_rows
            if src is None:
                bx.text(1.2, y0 + offsets[key], "use step not measured at 5 s locally", va="center", fontsize=9,
                        color=MUTED)
                continue
            vals = [r[key] for r in src]
            bx.scatter(vals, [y0 + offsets[key]] * len(vals), s=18, color=STAGE_COLORS[key], alpha=0.75,
                       edgecolor="white", linewidth=0.5, zorder=3)
            med = nearest_rank(vals, 50)
            bx.plot([med, med], [y0 + offsets[key] - 0.07, y0 + offsets[key] + 0.07], color=INK, linewidth=2,
                    zorder=4)
            bx.annotate(fmt_ms(med), (med, y0 + offsets[key]), xytext=(4, 3), textcoords="offset points",
                        fontsize=8.5, color=INK, va="bottom")
    aws_hold = [r["issue"] for r in groups[0][1] if r["issue"] > 300]
    bx.annotate(f"{len(aws_hold)} of {len(groups[0][1])} trials: the agent held the child's\n"
                "X.509 fetch about 0.5 s before answering", (min(aws_hold), len(groups) - 1 + offsets["issue"]),
                xytext=(-12, -4), textcoords="offset points", ha="right", va="top", fontsize=8.5, color=INK2)
    bx.set_xscale("log")
    bx.set_xlim(0.8, 15000)
    bx.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1000:g} s" if v >= 1000 else f"{v:g} ms"))
    bx.set_yticks(range(len(groups)))
    bx.set_yticklabels([g[0] for g in groups][::-1], fontsize=10)
    bx.set_ylim(-0.5, len(groups) - 0.5)
    for y in range(len(groups) - 1):
        bx.axhline(y + 0.5, color=GRID, linewidth=0.8)
    bx.set_xlabel("Stage duration per trial (log scale); black tick = median. Stage colours as in panel A; "
                  "use step from the poll runs")
    bx.set_title("B. Every trial, every stage: vending takes tens of ms, propagation takes about a second "
                 "(1 s) or seconds (5 s)", loc="left", fontsize=11.5, color=INK)

    fig.text(0.06, 0.975, "SPIRE vending vs end-to-end acquisition by the child", fontsize=15, color=INK,
             ha="left", va="top")
    fig.text(0.06, 0.945,
             "Clean AWS = t3a.large, 2 vCPU, unlimited credits, SPIRE server audit log off, 1 s intervals from the "
             "manifests (ea47be3). Local = 16-thread Ryzen 7 9800X3D, audit log on,\nintervals set per cluster "
             "(1 s, or the 5 s default). All runs: 50 trials, random 0–5 s start. Different hosts: compare the "
             "shape, not the milliseconds.", fontsize=9.8, color=INK2, ha="left", va="top")
    fig.subplots_adjust(top=0.88, left=0.2, right=0.98, bottom=0.07)
    save(fig, out / STAGES_NAME, written)


# ---------------------------------------------------------------- dispatch

def plot_run(run: Path, out: Path, written: list[Path]) -> bool:
    if (run / "vend_to_svid.csv").exists():
        plot_vend_to_svid(run, out, written)
    elif (run / "vend_to_access.csv").exists():
        plot_vend_to_access(run, out, written)
    elif (run / "revoke_to_deny.csv").exists():
        plot_revoke_to_deny(run, out, written)
    elif (run / "revocation_speed.csv").exists():
        plot_revocation_speed(run, out, written)
    elif (run / "storage_growth.csv").exists():
        plot_storage(run, out, written)
    else:
        print(f"skip {run.name}: no result CSV to plot", file=sys.stderr)
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs", nargs="*", help="run directories (default: DEFAULT_RUNS and the comparison figure)")
    ap.add_argument("--out", default=str(PLOTS), help="output directory (default: benchmarks/plots)")
    ap.add_argument("--overwrite", action="store_true",
                    help="allow replacing existing PNGs of runs outside DEFAULT_RUNS in benchmarks/plots")
    ap.add_argument("--no-compare", action="store_true", help="skip the comparison figures")
    ap.add_argument("--stages-only", action="store_true",
                    help="write only the vending-vs-end-to-end stage figure (" + STAGES_NAME + ")")
    ap.add_argument("--dpi", type=int, default=None,
                    help="resolution of the written PNGs (default: " + str(plt.rcParams["savefig.dpi"]) + ")")
    args = ap.parse_args()
    if args.dpi:
        plt.rcParams["savefig.dpi"] = args.dpi

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if args.stages_only:
        plot_stage_breakdown(out, [])
        return 0
    runs = [Path(r).resolve() for r in args.runs] if args.runs else [BENCH / r for r in DEFAULT_RUNS]
    for run in runs:
        if not run.is_dir():
            print(f"error: {run} is not a directory", file=sys.stderr)
            return 2
        if out == PLOTS.resolve() and run.name not in DEFAULT_RUNS and not args.overwrite:
            existing = sorted(out.glob(f"{run.name}_*.png"))
            if existing:
                print(f"skip {run.name}: {len(existing)} existing PNG(s) in {out} belong to a run outside "
                      f"DEFAULT_RUNS; use --out or --overwrite", file=sys.stderr)
                continue
        written: list[Path] = []
        plot_run(run, out, written)
    if not args.runs and not args.no_compare:
        plot_comparison(out, [])
        plot_stage_breakdown(out, [])
    return 0


if __name__ == "__main__":
    sys.exit(main())
