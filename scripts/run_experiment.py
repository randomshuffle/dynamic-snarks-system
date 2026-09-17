#!/usr/bin/env python3
"""Build, run, validate and archive the BN254 EC2 experiment. Python stdlib only."""

import argparse
import datetime
import json
import math
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from experiment_support import ROOT, pack_results, sha256, snapshot, summarize, write_json
from experiment_memory import MemoryMonitor, memory_reader


def capture(command):
    try:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except OSError:
        return None


def memory_limit():
    candidates = []
    if sys.platform == "darwin":
        value = capture(["sysctl", "-n", "hw.memsize"])
        if value and value.isdigit():
            candidates.append(int(value))
        else:
            pressure = capture(["/usr/bin/memory_pressure"]) or ""
            match = re.search(r"The system has (\d+)", pressure)
            if match:
                candidates.append(int(match.group(1)))
    elif sys.platform.startswith("linux"):
        text = Path("/proc/meminfo").read_text()
        candidates.append(int(re.search(r"MemTotal:\s+(\d+)", text).group(1)) * 1024)
        paths = [Path("/sys/fs/cgroup/memory.max"), Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")]
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            if line.startswith("0::"):
                current = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
                while current.is_relative_to("/sys/fs/cgroup"):
                    paths.append(current / "memory.max")
                    if current == Path("/sys/fs/cgroup"):
                        break
                    current = current.parent
        for path in paths:
            try:
                value = path.read_text().strip()
                if value.isdigit() and int(value) > 0:
                    candidates.append(int(value))
            except OSError:
                pass
    if not candidates:
        raise RuntimeError("Cannot determine physical/cgroup RAM; refusing an unguarded run")
    return min(candidates)


def build(output, offline, features):
    command = ["cargo", "bench", "--locked", "--no-run", "--bench", "ec2_experiment",
               "--features", ",".join(features), "--message-format=json"]
    if offline:
        command.append("--offline")
    print("Building the experiment (subsequent launches reuse Cargo's cache)", flush=True)
    with (output / "build.log").open("w") as errors, (output / "build-artifacts.jsonl").open("w") as artifacts:
        result = subprocess.run(command, cwd=ROOT, text=True, stdout=artifacts, stderr=errors)
    if result.returncode:
        raise RuntimeError(f"Build failed; inspect {output / 'build.log'}")
    executable = None
    for line in (output / "build-artifacts.jsonl").read_text().splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "ec2_experiment":
            executable = item.get("executable") or executable
    if not executable:
        raise RuntimeError("Cargo did not return the benchmark executable")
    return Path(executable)


def child(command, env, output, rss_limit_bytes=0):
    """Keep logs incrementally and collect this child's own peak RSS with wait4."""
    interrupted = []
    reader = memory_reader() if rss_limit_bytes else None
    monitor = None
    started = time.monotonic()
    with (output / "run.log").open("w", buffering=1) as log:
        process = subprocess.Popen(command, env=env, cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
        if reader:
            monitor = MemoryMonitor(process.pid, rss_limit_bytes, output, reader)
            monitor.start()
        def forward(signum, _frame):
            interrupted.append(signum)
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass
        previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            for line in process.stdout:
                log.write(line)
                # Keep the terminal readable; full cryptographic checkpoints remain in run.log.
                if not any(marker in line for marker in ("checkpoint:", "profile checkpoint:")):
                    print(line, end="", flush=True)
            _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            process.stdout.close()
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait()
            if monitor:
                monitor.stop()
    metrics = {"exit_code": process.returncode, "wall_seconds": time.monotonic() - started,
               "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
               "max_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
               "signals_forwarded": interrupted}
    if monitor:
        metrics["memory_monitor"] = monitor.metrics
        if metrics["max_rss_bytes"] > rss_limit_bytes:
            monitor.metrics["limit_exceeded"] = True
        if monitor.metrics["error"] or monitor.metrics["limit_exceeded"]:
            metrics["exit_code"] = process.returncode or 1
        print("Memory monitor: " + json.dumps(monitor.metrics), flush=True)
    write_json(output / "resources.json", metrics)
    return metrics["exit_code"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-log", type=int, default=24)
    parser.add_argument("--update-logs", default="0,1,2,3,4,5,6,7,8,9,10")
    parser.add_argument("--sequence-len", type=int, default=40,
                        help="Consecutive revisions per update size and measured baseline case (default: 40)")
    parser.add_argument("--seed", type=int, default=20260909)
    parser.add_argument("--baseline-mode", choices=("paired", "shared"), default="shared",
                        help="paired: baseline after every update; shared: baseline only for the first update size")
    parser.add_argument("--threads", type=int, required=True)
    parser.add_argument("--initial-interleaving", type=int, choices=(16, 64), default=64,
                        help="First WHIR interleaving; later rounds use 16 (default: 64 for earlier-run compatibility)")
    parser.add_argument("--rss-limit-gb", type=float,
                        help="Opt-in monitored trial: decimal-GB RSS cutoff permits exceeding the conservative preflight estimate; sampling may overshoot briefly")
    parser.add_argument("--output", type=Path, required=True, help="New result directory; existing directories are never overwritten")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--numa-interleave", action="store_true", help="Linux: distribute allocations over all NUMA nodes")
    args = parser.parse_args()
    if args.threads < 1:
        parser.error("--threads must be positive")
    if args.rss_limit_gb is not None and (not math.isfinite(args.rss_limit_gb) or args.rss_limit_gb <= 0):
        parser.error("--rss-limit-gb must be finite and positive")
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    state = {"state": "preparing", "started_utc": started, "command": sys.argv}
    write_json(output / "status.json", state)
    code = 1
    try:
        memory = memory_limit()
        rss_limit_bytes = int(args.rss_limit_gb * 1_000_000_000) if args.rss_limit_gb is not None else 0
        if args.rss_limit_gb is not None:
            if not 0 < rss_limit_bytes <= memory * 7 // 10:
                raise ValueError("RSS cutoff must be positive and at most 70% of detected host memory")
            memory_reader()
        features = ["parallel", "poseidon-gkr", "compact-merkle"]
        if args.initial_interleaving == 64:
            features.append("whir-initial-64")
        metadata = {"started_utc": started, "platform": platform.platform(), "machine": platform.machine(),
                    "logical_cpus": os.cpu_count(), "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
                    "memory_limit_bytes": memory, "rss_limit_bytes": rss_limit_bytes,
                    "requested_rayon_threads": args.threads,
                    "lscpu": capture(["lscpu", "--json"]), "numactl_hardware": capture(["numactl", "--hardware"]),
                    "rustc": capture(["rustc", "-Vv"]), "cargo": capture(["cargo", "-V"]),
                    "git_head": capture(["git", "rev-parse", "HEAD"]), "git_status": capture(["git", "status", "--short"]),
                    "rustflags": os.environ.get("RUSTFLAGS", ""), "features": features,
                    "argv": sys.argv, "source": snapshot(output / "source.tar.gz")}
        write_json(output / "metadata.json", metadata)
        executable = build(output, args.offline, features)
        metadata["binary"] = str(executable)
        metadata["binary_sha256"] = sha256(executable)
        write_json(output / "metadata.json", metadata)
        if args.build_only:
            state["state"] = "build_complete"
            code = 0
        else:
            env = {key: value for key, value in os.environ.items() if not key.startswith("EXPERIMENT_")}
            env.update(EXPERIMENT_TRACE_LOG=str(args.trace_log), EXPERIMENT_UPDATE_LOGS=args.update_logs,
                       EXPERIMENT_SEQUENCE_LEN=str(args.sequence_len), EXPERIMENT_SEED=str(args.seed),
                       EXPERIMENT_OUTPUT=str(output), EXPERIMENT_MEMORY_BYTES=str(memory),
                       EXPERIMENT_RSS_LIMIT_BYTES=str(rss_limit_bytes),
                       EXPERIMENT_BASELINE_MODE=args.baseline_mode,
                       EXPERIMENT_PREFLIGHT_ONLY="1" if args.preflight_only else "0", RAYON_NUM_THREADS=str(args.threads))
            command = [str(executable)]
            if args.numa_interleave:
                if not sys.platform.startswith("linux") or not shutil.which("numactl"):
                    raise RuntimeError("--numa-interleave requires Linux and numactl")
                command = ["numactl", "--interleave=all", *command]
            state["state"] = "running"
            write_json(output / "status.json", state)
            code = child(command, env, output, rss_limit_bytes)
            if (output / "experiment.json").exists() and not args.preflight_only:
                validation = summarize(output, require_complete=code == 0)
                state["verified_samples"] = validation["verified_samples"]
            state["state"] = ("preflight_complete" if args.preflight_only else "complete") if code == 0 else "failed"
    except Exception as error:
        state.update(state="failed", error=str(error))
        print(f"ERROR: {error}", file=sys.stderr)
        code = 1
    finally:
        state.update(finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), exit_code=code)
        write_json(output / "status.json", state)
        archive = pack_results(output)
        print(f"Status: {state['state']}\nResults: {output}\nArchive: {archive}", flush=True)
    return code if 0 <= code <= 255 else 1


if __name__ == "__main__":
    raise SystemExit(main())
