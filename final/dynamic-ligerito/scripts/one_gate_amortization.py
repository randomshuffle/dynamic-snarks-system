#!/usr/bin/env python3
"""Measure a fixed-size update trajectory and chart initialization-inclusive speedup.

The sampled-baseline curve is n * mean(baseline) / (initial + sum(updates[:n])).
It never extrapolates dynamic updates or repeats a short update-time sequence.
Use --baseline-every 1 to measure every baseline and use its actual prefix sum.
Plotting requires matplotlib; measurement and analysis use the standard library.
The command defaults to one gate; use --update-gates 128 for 128 gates.
"""

import argparse
import csv
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
from run import resource_arguments, resource_options


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def open_samples(directory):
    """Stream raw or gzip-compressed publication records as UTF-8 JSONL."""
    path = Path(directory) / "samples.jsonl"
    if path.is_file():
        return path.open(encoding="utf-8")
    return gzip.open(path.with_suffix(path.suffix + ".gz"), "rt", encoding="utf-8")


def read_run(directory):
    """Reject incomplete, unverified, or mismatched runs before reporting results."""
    directory = Path(directory)
    meta = json.loads((directory / "run.json").read_text())
    require(meta["exit_code"] == 0, "benchmark did not exit successfully")
    monitor = meta["memory_monitor"]
    require(not monitor["error"] and not monitor["limit_exceeded"], "memory guard failed")
    with (directory / "stdout.log").open() as log:
        require(any(line.strip() == "EXPERIMENT_COMPLETE" for line in log), "missing completion marker")
    require(meta["baseline_every"] > 0, "baseline measurements are required")
    selected = str(meta["update_logs"])
    require(selected.isdecimal() and int(selected) <= 30, "expected exactly one update size")
    update_gates = 1 << int(selected)
    hierarchy_base = meta.get("hierarchy_base", 2)
    require(hierarchy_base in (2, 4, 8), "invalid hierarchy base")
    initial, updates, baselines = [], [], []
    gates = set()
    with open_samples(directory) as source:
        for line in source:
            row = json.loads(line)
            require(row["verified"] is True, "an unverified sample was found")
            require(row.get("hierarchy_base", 2) == hierarchy_base, "sample hierarchy base does not match run metadata")
            require(math.isfinite(row["prove_s"]) and row["prove_s"] > 0, "invalid prover time")
            gates.add(row["gates"])
            phase = row["phase"]
            if phase == "initial":
                require(row["revision"] == 0 and row["update_gates"] == 0, "invalid initialization")
                initial.append(row["prove_s"])
                continue
            require(row["update_gates"] == update_gates, "sample update size does not match the run configuration")
            require(phase in ("update", "baseline"), "unknown sample phase")
            # Discard large per-proof index arrays while streaming the raw log.
            sample = {key: row[key] for key in ("revision", "prove_s", "serialized_bytes")}
            if phase == "update":
                sample["mode"] = row["update_statistics"]["mode"]
                require(sample["mode"] in ("direct", "polynomial"), "unknown update mode")
                sample["polynomial_gates"] = row["update_statistics"]["polynomial_gates"]
                updates.append(sample)
            else:
                baselines.append(sample)
    require(len(initial) == 1 and len(gates) == 1, "expected one initialization and circuit size")
    require(update_gates <= next(iter(gates)), "update size exceeds circuit size")
    count = meta["sequence_length"]
    require(count > 0, "empty update sequence")
    require([row["revision"] for row in updates] == list(range(1, count + 1)),
            "updates must cover every revision exactly once, in order")
    cadence = meta["baseline_every"]
    expected = sorted({1, count, *range(cadence, count + 1, cadence)})
    require([row["revision"] for row in baselines] == expected, "baseline snapshot schedule mismatch")
    return initial[0], updates, baselines, meta, gates.pop()


def cumulative_curve(initial_s, updates, baselines):
    """Return every integer prefix, keeping promotion spikes in the denominator."""
    require(math.isfinite(initial_s) and initial_s > 0, "invalid initialization time")
    require(bool(updates) and bool(baselines), "updates and baselines are required")
    require([row["revision"] for row in updates] == list(range(1, len(updates) + 1)),
            "non-contiguous update sequence")
    baseline_times = {row["revision"]: row["prove_s"] for row in baselines}
    require(len(baseline_times) == len(baselines), "duplicate baseline revision")
    require(all(1 <= n <= len(updates) for n in baseline_times), "baseline revision out of range")
    require(all(math.isfinite(row["prove_s"]) and row["prove_s"] > 0
                for row in updates + baselines), "invalid prover time")
    baseline_mean = statistics.mean(baseline_times.values())
    measured = set(baseline_times) == set(range(1, len(updates) + 1))
    update_total, baseline_total, rows = 0.0, 0.0, []
    for update in updates:
        n = update["revision"]
        update_total += update["prove_s"]
        baseline_total = baseline_total + baseline_times[n] if measured else n * baseline_mean
        total = initial_s + update_total
        rows.append(dict(
            updates=n, update_prove_s=update["prove_s"], mode=update["mode"],
            cumulative_update_s=update_total, initial_s=initial_s,
            dynamic_total_s=total, baseline_total_s=baseline_total,
            amortized_initial_s=initial_s / n, average_update_s=update_total / n,
            amortized_dynamic_s=total / n, speedup=baseline_total / total,
        ))
    maximum = max(rows, key=lambda row: row["speedup"])
    break_even = next((row["updates"] for row in rows if row["speedup"] >= 1), None)
    # A carry can erase an early crossover; report the sustained one as well.
    last_below = max((row["updates"] for row in rows if row["speedup"] < 1), default=0)
    sustained = last_below + 1 if last_below < len(rows) else None
    summary = dict(
        updates=len(rows), initial_s=initial_s, baseline_mean_s=baseline_mean,
        baseline_samples=len(baselines), baseline_revisions=sorted(baseline_times),
        baseline_stdev_s=statistics.stdev(baseline_times.values()) if len(baselines) > 1 else None,
        baseline_total_method="measured prefix sum" if measured else "update count times sampled baseline mean",
        formula="sum(baseline[1:n]) / (initial + sum(update[1:n]))" if measured else
                "n * mean(sampled baseline) / (initial + sum(update[1:n]))",
        first_break_even_update=break_even, sustained_break_even_update=sustained,
        maximum=maximum, final=rows[-1],
        promotions=[dict(revision=u["revision"], prove_s=u["prove_s"],
                         polynomial_gates=u.get("polynomial_gates"))
                    for u in updates if u["mode"] == "polynomial"],
    )
    return rows, summary


def plot_curve(rows, summary, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "svg.fonttype": "none", "pdf.fonttype": 42})
    fig, (ax, cost) = plt.subplots(2, 1, figsize=(11.5, 8), sharex=True,
                                  gridspec_kw={"height_ratios": [2.3, 1]})
    x = [row["updates"] for row in rows]
    y = [row["speedup"] for row in rows]
    ax.plot(x, y, color="#146b86", linewidth=1.8, label="Includes full initialization")
    ax.plot(x, [row["speedup_with_setup"] for row in rows], color="#6b7591",
            linewidth=1.2, linestyle="--", label="Also includes circuit setup on both sides")
    peak = summary["maximum"]
    right = peak["updates"] > len(rows) * .6
    ax.legend(loc="upper left" if right else "upper right", fontsize=8, frameon=False)
    ax.axhline(1, color="#666666", linestyle=":", linewidth=1)
    # Dense promotion schedules otherwise obscure the speedup curve.
    for promotion in summary["promotions"]:
        ax.axvline(promotion["revision"], color="#bd6b26",
                   alpha=min(.25, 10 / max(1, len(summary["promotions"]))), linewidth=.8)
    ax.scatter([peak["updates"]], [peak["speedup"]], color="#b44b28", s=45, zorder=4)
    ax.annotate(f"Maximum: {peak['speedup']:.2f}× at {peak['updates']:,} updates",
                (peak["updates"], peak["speedup"]),
                xytext=(-15 if right else 15, 22), textcoords="offset points",
                ha="right" if right else "left", color="#8d3b20",
                arrowprops={"arrowstyle": "-", "color": "#b44b28"})
    ax.set_ylim(0, max(max(y), max(row["speedup_with_setup"] for row in rows)) * 1.22)
    ax.set_ylabel("Cumulative prover speedup (×)")
    update_gates = summary["update_gates"]
    ax.set_title(f"{update_gates}-gate updates: speedup including initialization", loc="left", fontsize=17, pad=40)
    estimated = summary["baseline_total_method"] != "measured prefix sum"
    detail = (f"2^{summary['trace_log']} gates · {summary['threads']} workers · "
              f"{summary['plaintext_cap_kib'] / 1024:g} MiB direct-tail cap · "
              f"base {summary.get('hierarchy_base', 2)} · {summary['baseline_samples']} baseline samples")
    ax.text(0, 1.04, detail, transform=ax.transAxes, color="#555555")
    cost.plot(x, [1000 * row["amortized_dynamic_s"] for row in rows],
              color="#146b86", label="Dynamic: initialization + updates")
    cost.plot(x, [1000 * row["amortized_initial_s"] for row in rows],
              color="#777777", linestyle="--", label="Initialization / update count")
    cost.axhline(1000 * summary["baseline_mean_s"], color="#bd6b26", linestyle=":",
                 label="Baseline mean")
    cost.set_yscale("log")
    cost.set_ylabel("Amortized prover ms/update")
    cost.set_xlabel(f"Number of consecutive {update_gates}-gate updates")
    cost.legend(loc="upper right", fontsize=8, frameon=True, facecolor="white", framealpha=.95)
    for axes in (ax, cost):
        axes.grid(axis="y", color="#dddddd", linewidth=.6)
        axes.set_xlim(1, max(2, len(rows)))
        axes.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:,.0f}"))
    note = ("Baseline total is estimated as n × sampled mean; all dynamic updates are measured."
            if estimated else "Every baseline and dynamic update is measured; totals are actual prefix sums.")
    note += (f"\nOrange lines: polynomial promotions. Break-even: {summary['first_break_even_update']} updates. "
             "Verification and I/O excluded.")
    fig.text(.09, .025, note, fontsize=9, color="#555555")
    fig.subplots_adjust(left=.09, right=.97, top=.86, bottom=.15, hspace=.16)
    for extension in ("png", "svg", "pdf"):
        fig.savefig(output / f"speedup.{extension}", dpi=180)
    plt.close(fig)


def analyze(directory, output, no_plot=False):
    initial, updates, baselines, meta, gates = read_run(directory)
    rows, summary = cumulative_curve(initial, updates, baselines)
    setup = json.loads((Path(directory) / "setup.json").read_text())
    require(setup.get("hierarchy_base", 2) == meta.get("hierarchy_base", 2), "setup hierarchy base mismatch")
    for key in ("baseline_s", "dynamic_s"):
        require(math.isfinite(setup[key]) and setup[key] >= 0, "invalid setup time")
    for row in rows:
        row["dynamic_total_with_setup_s"] = setup["dynamic_s"] + row["dynamic_total_s"]
        row["baseline_total_with_setup_s"] = setup["baseline_s"] + row["baseline_total_s"]
        row["speedup_with_setup"] = row["baseline_total_with_setup_s"] / row["dynamic_total_with_setup_s"]
    summary["maximum_with_setup"] = max(rows, key=lambda row: row["speedup_with_setup"])
    summary["first_break_even_with_setup"] = next(
        (row["updates"] for row in rows if row["speedup_with_setup"] >= 1), None)
    update_gates = 1 << int(meta["update_logs"])
    summary.update(gates=gates, update_gates=update_gates,
                   hierarchy_base=meta.get("hierarchy_base", 2),
                   tables_per_level=meta.get("hierarchy_base", 2) - 1,
                   trace_log=gates.bit_length() - 1, threads=meta["threads"],
                   plaintext_cap_kib=meta["plaintext_cap_kib"], run_metadata=meta,
                   verified_samples=1 + len(updates) + len(baselines),
                   setup=setup)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with (output / "curve.csv").open("w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if not no_plot:
        plot_curve(rows, summary, output)
    peak, final = summary["maximum"], summary["final"]
    setup_peak = summary["maximum_with_setup"]
    report = [
        f"# {update_gates}-gate update amortization", "",
        f"The maximum over revisions 1–{len(rows):,} is **{peak['speedup']:.3f}× at "
        f"{peak['updates']:,} updates**. At {len(rows):,} updates the speedup is "
        f"**{final['speedup']:.3f}×**. This is the observed maximum in this run and window, "
        "not a claim about larger update counts or a noise-free optimum.", "",
        f"Including circuit setup on both sides as well, the maximum is "
        f"**{setup_peak['speedup_with_setup']:.3f}× at {setup_peak['updates']:,} updates**, "
        f"and the final speedup is **{final['speedup_with_setup']:.3f}×**. "
        f"This adds {setup['dynamic_s']:.6f} s to the dynamic total and "
        f"{setup['baseline_s']:.6f} s to the baseline total. The first setup-inclusive "
        f"break-even is revision {summary['first_break_even_with_setup']}. "
        "The dashed curve includes these costs; the solid curve follows the existing "
        "prover-time convention.", "",
        "![Initialization-inclusive cumulative speedup](speedup.png)" if not no_plot else "", "",
        f"Formula: `{summary['formula']}`. The numerator uses {summary['baseline_total_method']}. "
        f"The baseline mean is {summary['baseline_mean_s'] * 1000:.3f} ms from "
        f"{len(baselines)} fresh proofs of this same update trajectory. "
        "With a sampled baseline, its mean is fixed across the curve, so it scales the speedup "
        "but does not determine the maximizing revision.", "",
        f"Initialization took {initial:.6f} s. Every one of the {len(rows):,} dynamic updates "
        f"was measured, including {len(summary['promotions'])} polynomial promotions and their "
        "hierarchy merges. No dynamic timings are extrapolated. One full dynamic initialization "
        "is charged to the sequence; the baseline proves each updated state and is charged no "
        "extra initial-state proof, matching the preceding baseline comparison.", "",
        f"First break-even: **{summary['first_break_even_update']} updates**. "
        f"Speedup stays at least 1× through the end from revision "
        f"**{summary['sustained_break_even_update']}**.", "",
        "| Prefix | Baseline total (s) | Dynamic including init (s) | Amortized dynamic (ms/update) | Speedup |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    checkpoints = sorted({1, peak["updates"], len(rows), *[n for n in (10, 40, 100, 400, 1000, 2000, 5000) if n <= len(rows)]})
    for n in checkpoints:
        row = rows[n - 1]
        report.append(f"| {n:,} | {row['baseline_total_s']:.3f} | {row['dynamic_total_s']:.3f} | "
                      f"{row['amortized_dynamic_s'] * 1000:.3f} | {row['speedup']:.3f}× |")
    report += ["", f"Circuit: 2^{gates.bit_length() - 1} = {gates:,} gates, half addition and half "
               "multiplication, identity wiring, 256 public inputs, seed 20260909. Each revision "
               f"selects {update_gates} distinct gates uniformly without replacement and supplies "
               "the complete three-wire tuple of every selected gate. "
               "A gate can recur in later revisions. Full ordinary HyperPlonk and the dynamic "
               "system both use the existing native GF(2^128) / Ligerito Fast configuration.", "",
               f"The run used {meta['threads']} workers, a {meta['plaintext_cap_kib']} KiB direct-tail cap, "
               f"and a base-{meta.get('hierarchy_base', 2)} hierarchy with up to {meta.get('hierarchy_base', 2)-1} tables per size level, "
               f"and baseline cadence {meta['baseline_every']} (also including both endpoints). "
               "Sampled-pair execution order alternates. Timers include witness construction and "
               "hierarchy work; setup/indexing, verification, serialization, statistics, workload "
               "generation and I/O are outside the prover timers. `setup.json` records indexing "
               "costs separately; the setup-inclusive curve adds these measured costs once on "
               "each side. All timings are retained; there are no discarded warmups.", "",
               f"All {summary['verified_samples']:,} measured proofs verified. The existing runner "
               "also serializes, decodes and reverifies initialization, baseline snapshots, "
               "polynomial promotions, and first/final dynamic proofs. `curve.csv` contains all "
               "integer prefixes; `summary.json` contains the exact maximum, promotion revisions, "
               "memory measurements and run metadata. `run-a/` retains raw evidence.", ""]
    (output / "README.md").write_text("\n".join(report))
    print(json.dumps({key: summary[key] for key in (
        "maximum", "final", "first_break_even_update", "sustained_break_even_update", "verified_samples")}, indent=2))
    return summary


def run(args):
    require(args.updates > 0 and args.baseline_every > 0, "updates and baseline cadence must be positive")
    require(9 <= args.trace_log <= 30, "trace log must be between 9 and 30 (256 fixed public inputs)")
    require(args.update_gates > 0 and args.update_gates & (args.update_gates - 1) == 0,
            "update gates must be a positive power of two")
    require(args.update_gates <= 1 << args.trace_log, "update size exceeds circuit size")
    update_log = str(args.update_gates.bit_length() - 1)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = (args.binary or HERE.parent / "target/release/whole_system").resolve()
    shutil.copy2(binary, output / "whole-system")
    sources = {}
    for root in (REPO / "final/dynamic-ligerito",
                 REPO / "final/poseidon2b-compress-ligerito", REPO / "vendor/flock-core"):
        for folder, directories, filenames in os.walk(root):
            directories[:] = [d for d in directories if d not in ("target", ".git", "__pycache__")]
            for filename in filenames:
                file = Path(folder) / filename
                if file.suffix in (".rs", ".inc", ".toml", ".lock", ".py", ".json"):
                    sources[str(file.relative_to(REPO))] = hashlib.sha256(file.read_bytes()).hexdigest()
    monitor_source = REPO / "scripts/experiment_memory.py"
    sources[str(monitor_source.relative_to(REPO))] = hashlib.sha256(monitor_source.read_bytes()).hexdigest()
    (output / "source-sha256.json").write_text(json.dumps(sources, indent=2) + "\n")
    command = [sys.executable, str(HERE / "run.py"), str(args.trace_log), str(output / "run-a"),
               "--binary", str(output / "whole-system"), "--sequence", str(args.updates),
               "--update-log", update_log, "--update-logs", update_log, "--plaintext-kib", str(args.plaintext_kib),
               "--baseline-every", str(args.baseline_every), "--hierarchy-base", str(args.hierarchy_base)]
    command += resource_options(args)
    if args.baseline_first:
        command.append("--baseline-first")
    with (output / "launcher.log").open("w") as log:
        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
    analyze(output / "run-a", output, args.no_plot)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    measure = commands.add_parser("run", help="run a fresh trajectory, then analyze it")
    measure.add_argument("output", type=Path)
    measure.add_argument("--trace-log", type=int, default=19)
    measure.add_argument("--updates", type=int, default=10000)
    measure.add_argument("--update-gates", type=int, default=1, help="gates changed per revision (power of two)")
    measure.add_argument("--hierarchy-base", type=int, choices=[2, 4, 8], default=2,
                         help="size-level base; retains up to base-1 tables per level")
    measure.add_argument("--plaintext-kib", type=int, choices=[0, 64, 128, 256, 512, 1024, 2048], default=2048)
    measure.add_argument("--baseline-every", type=int, default=100)
    measure.add_argument("--baseline-first", action="store_true")
    measure.add_argument("--binary", type=Path)
    measure.add_argument("--no-plot", action="store_true")
    resource_arguments(measure)
    existing = commands.add_parser("analyze", help="validate and chart a completed run")
    existing.add_argument("directory", type=Path)
    existing.add_argument("--output", type=Path, required=True)
    existing.add_argument("--no-plot", action="store_true")
    args = parser.parse_args()
    if args.command == "run":
        run(args)
    else:
        analyze(args.directory, args.output, args.no_plot)


if __name__ == "__main__":
    main()
