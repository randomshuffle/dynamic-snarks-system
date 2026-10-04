#!/usr/bin/env python3
"""Run a full-system sweep with external Linux/macOS memory measurement."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / 'scripts'))
from experiment_memory import MemoryMonitor, memory_reader, memory_limit

GIB = 1 << 30


def maximum_rss_bytes(value, platform=sys.platform):
    return int(value) * (1024 if platform.startswith('linux') else 1)


def resource_arguments(parser):
    parser.add_argument('--threads', type=int, default=8)
    parser.add_argument('--memory-limit-gib', type=float,
                        help='RSS cutoff; defaults to 8 GiB on macOS, 80%% of RAM/cgroup on Linux')
    parser.add_argument('--footprint-limit-gib', type=float,
                        help='macOS physical-footprint cutoff (default 12 GiB)')


def resource_options(args):
    result = ['--threads', str(args.threads)]
    for name in ('memory_limit_gib', 'footprint_limit_gib'):
        if getattr(args, name) is not None:
            result += ['--' + name.replace('_', '-'), str(getattr(args, name))]
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=int)
    p.add_argument('output', type=Path)
    p.add_argument('--sequence', type=int, default=12)
    p.add_argument('--update-log', type=int, default=6)
    p.add_argument('--binary', type=Path)
    p.add_argument('--update-logs')
    p.add_argument('--small-oracle', choices=['hybrid', 'ligerito'], default='hybrid')
    p.add_argument('--hash-checkpoints', type=int, choices=[1, 3, 7], default=1)
    p.add_argument('--hash-kernel', choices=['coefficients', 'factored', 'evaluations'], default='factored')
    p.add_argument('--plaintext-kib', type=int, choices=[0, 64, 128, 256, 512, 1024, 2048], default=64)
    p.add_argument('--baseline-every', type=int, default=1)
    p.add_argument('--baseline-first', action='store_true')
    p.add_argument('--hierarchy-base', type=int, choices=[2, 4, 8], default=2)
    resource_arguments(p)
    a = p.parse_args()
    if not (9 <= a.log <= 30 and a.sequence > 0 and 0 <= a.update_log <= a.log
            and a.baseline_every >= 0 and a.threads > 0):
        p.error('invalid circuit, sequence, update size, baseline cadence, or worker count')
    selected = list(range(a.update_log + 1)) if a.update_logs is None else [int(x) for x in a.update_logs.split(',')]
    if not selected or len(set(selected)) != len(selected) or any(x < 0 or x > a.update_log for x in selected):
        p.error('update logs must be unique and between zero and --update-log')
    ram = memory_limit()
    rss_limit = a.memory_limit_gib if a.memory_limit_gib is not None else (8 if sys.platform == 'darwin' else .8 * ram / GIB)
    footprint_limit = a.footprint_limit_gib if a.footprint_limit_gib is not None else 12
    if not all(math.isfinite(x) and x > 0 for x in (rss_limit, footprint_limit)):
        p.error('memory limits must be finite and positive')
    if rss_limit * GIB > .9 * ram:
        p.error('RSS cutoff exceeds 90% of detected RAM/cgroup limit')
    binary = (a.binary or REPO / 'final/dynamic-ligerito/target/release/whole_system').resolve()
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    reader = memory_reader()
    a.output.mkdir(parents=True, exist_ok=False)
    cmd = [str(binary), str(a.log), str(a.output.resolve()), str(a.sequence), str(a.update_log), str(a.hash_checkpoints)]

    def guarded(pid):
        rss, footprint = reader(pid)
        if footprint is not None and footprint > footprint_limit * GIB:
            raise RuntimeError(f'physical footprint exceeded {footprint_limit:g} GiB')
        return rss, footprint

    extra_env = {
        'DYNAMIC_HIERARCHY_BASE': str(a.hierarchy_base), 'DYNAMIC_SMALL_ORACLE': a.small_oracle,
        'DYNAMIC_PLAINTEXT_KIB': str(a.plaintext_kib), 'DYNAMIC_BASELINE_EVERY': str(a.baseline_every),
        'DYNAMIC_BASELINE_FIRST': '1' if a.baseline_first else '0',
        'DYNAMIC_UPDATE_LOGS': ','.join(map(str, selected)),
        'RAYON_NUM_THREADS': str(a.threads), 'DYNAMIC_GKR_KERNEL': a.hash_kernel,
    }
    load_start = os.getloadavg()
    start = time.monotonic()
    interrupted = []
    with (a.output / 'stdout.log').open('w') as out, (a.output / 'stderr.log').open('w') as err:
        child = subprocess.Popen(cmd, stdout=out, stderr=err,
                                 env={**os.environ, **extra_env}, start_new_session=True)

        def stop_child(signum, _frame):
            interrupted.append(signum)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        previous = {sig: signal.signal(sig, stop_child) for sig in (signal.SIGINT, signal.SIGTERM)}
        monitor = MemoryMonitor(child.pid, int(rss_limit * GIB), a.output, guarded, .1)
        monitor.start()
        try:
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
        finally:
            memory = monitor.stop()
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    metadata = dict(
        command=cmd, exit_code=child.returncode, wall_seconds=time.monotonic() - start,
        user_seconds=usage.ru_utime, system_seconds=usage.ru_stime,
        maximum_rss_bytes=maximum_rss_bytes(usage.ru_maxrss), memory_monitor=memory,
        binary_sha256=binary_hash, threads=a.threads, rustflags=os.environ.get('RUSTFLAGS'),
        sequence_length=a.sequence, trace_log=a.log, platform=sys.platform,
        detected_memory_bytes=ram, footprint_limit_bytes=int(footprint_limit * GIB) if sys.platform == 'darwin' else None,
        security_profile='Ligerito Fast (100 bits per round, JohnsonOod, rate 1/2)',
        hash_input_bytes=64, digest_bytes=32, gkr_segments=a.hash_checkpoints + 1,
        gkr_depth=(66 + a.hash_checkpoints) // (a.hash_checkpoints + 1),
        load_average_start=load_start, load_average_end=os.getloadavg(),
        hash_checkpoints=a.hash_checkpoints, initial_hash_checkpoints=1, hash_kernel=a.hash_kernel,
        update_logs=','.join(map(str, selected)), small_oracle=a.small_oracle,
        plaintext_cap_kib=a.plaintext_kib if a.small_oracle == 'hybrid' else 0,
        baseline_every=a.baseline_every, baseline_first=a.baseline_first,
        hierarchy_base=a.hierarchy_base, tables_per_level=a.hierarchy_base - 1,
        interrupted_by_signals=interrupted,
    )
    (a.output / 'run.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata), flush=True)
    if child.returncode or memory['error'] or memory['limit_exceeded'] or interrupted:
        sys.exit(1)


if __name__ == '__main__':
    main()
