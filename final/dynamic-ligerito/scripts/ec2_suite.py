#!/usr/bin/env python3
"""Sequential EC2 sweep + two initialization-inclusive amortization experiments."""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

from one_gate_amortization import analyze, require, open_samples
from ec2_memory_plan import estimate
from run import memory_limit

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def write_json(path, data):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, indent=2) + '\n')
    temporary.replace(path)


def summarize_sweep(directory, output, no_plot=False):
    meta = json.loads((directory / 'run.json').read_text())
    require(meta['exit_code'] == 0, 'sweep failed')
    require(not meta['memory_monitor']['error'] and not meta['memory_monitor']['limit_exceeded'], 'memory guard failed')
    with (directory / 'stdout.log').open() as source:
        require(any(line.strip() == 'EXPERIMENT_COMPLETE' for line in source), 'sweep incomplete')
    require(meta['baseline_every'] == 1, 'sweep requires paired baselines')
    groups, observed = {}, set()
    expected = {('initial', 0, 0)}
    logs = [int(x) for x in meta['update_logs'].split(',')]
    for log in logs:
        for phase in ('update', 'baseline'):
            expected.update((phase, 1 << log, r) for r in range(1, meta['sequence_length'] + 1))
    with open_samples(directory) as source:
        for line in source:
            sample = json.loads(line)
            key = sample['phase'], sample['update_gates'], sample['revision']
            require(key in expected and key not in observed and sample['verified'] is True, 'invalid/duplicate/unverified sample')
            require(sample['gates'] == 1 << meta['trace_log'], 'circuit size mismatch')
            require(sample.get('hierarchy_base', 2) == meta['hierarchy_base'], 'hierarchy mismatch')
            for metric in ('prove_s', 'verify_s', 'serialized_bytes'):
                require(math.isfinite(sample[metric]) and sample[metric] > 0, 'invalid measurement')
            observed.add(key)
            groups.setdefault(key[:2], []).append({k: sample[k] for k in ('prove_s', 'verify_s', 'serialized_bytes', 'revision')})
    require(observed == expected, 'missing sweep samples')
    initial = groups['initial', 0][0]
    rows = []
    for log in logs:
        k = 1 << log
        row = dict(update_gates=k, updates=meta['sequence_length'], initial_prove_s=initial['prove_s'],
                   initial_verify_s=initial['verify_s'], initial_serialized_bytes=initial['serialized_bytes'])
        for phase in ('update', 'baseline'):
            samples = groups[phase, k]
            for metric in ('prove_s', 'verify_s', 'serialized_bytes'):
                row[f'{phase}_{metric}_mean'] = statistics.mean(s[metric] for s in samples)
                row[f'{phase}_{metric}_max'] = max(s[metric] for s in samples)
            row[f'{phase}_final_serialized_bytes'] = max(samples, key=lambda s: s['revision'])['serialized_bytes']
        row['prover_speedup'] = row['baseline_prove_s_mean'] / row['update_prove_s_mean']
        rows.append(row)
    output.mkdir(parents=True, exist_ok=True)
    with (output / 'comparison.csv').open('w', newline='') as target:
        writer = csv.DictWriter(target, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    validation = dict(complete=True, verified_samples=len(observed), expected_samples=len(expected), comparisons=rows)
    write_json(output / 'validation.json', validation)
    if not no_plot:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        fig, axes = plt.subplots(1, 3, figsize=(14, 4.8))
        x = [str(r['update_gates']) for r in rows]
        for ax, metric, title, factor in zip(axes, ('prove_s', 'verify_s', 'serialized_bytes'),
                ('Prover time (ms)', 'Verifier time (ms)', 'Full retained proof (MiB)'), (1000, 1000, 1 / 2**20)):
            for phase, color in (('baseline', '#bd6b26'), ('update', '#146b86')):
                ax.plot(x, [r[f'{phase}_{metric}_mean'] * factor for r in rows], 'o-', color=color, label=f'{phase}: mean')
                ax.plot(x, [r[f'{phase}_{metric}_max'] * factor for r in rows], ':', color=color, alpha=.6, label=f'{phase}: maximum')
            ax.set_yscale('log')
            ax.set_title(title)
            ax.set_xlabel('Gates changed per update')
            ax.grid(axis='y', alpha=.2)
        axes[0].legend(fontsize=8)
        fig.suptitle(f"2^{meta['trace_log']} gates · {meta['sequence_length']} consecutive updates per size · {meta['threads']} workers")
        fig.tight_layout()
        for ext in ('png', 'svg', 'pdf'):
            fig.savefig(output / f'sweep.{ext}', dpi=180)
        plt.close(fig)
    return validation


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('output', type=Path)
    p.add_argument('--trace-log', type=int, default=23)
    p.add_argument('--threads', type=int, default=32)
    p.add_argument('--memory-limit-gib', type=float, default=216)
    p.add_argument('--hierarchy-base', type=int, choices=[2, 4, 8], default=2)
    p.add_argument('--binary', type=Path)
    p.add_argument('--smoke', action='store_true', help='2^10 gates, 64 KiB tail, short trajectories; forces promotions')
    p.add_argument('--resume', action='store_true', help='skip validated completed stages; cannot resume a partial trajectory')
    p.add_argument('--no-plot', action='store_true')
    p.add_argument('--plan-only', action='store_true')
    a = p.parse_args()
    log = 10 if a.smoke else a.trace_log
    require(9 <= log <= 30 and a.threads > 0, 'invalid trace log or worker count')
    memory = estimate(log)
    config = dict(trace_log=log, threads=a.threads, memory_limit_gib=a.memory_limit_gib,
                  hierarchy_base=a.hierarchy_base, plaintext_kib=64 if a.smoke else 2048,
                  sweep_revisions=40, one_gate_revisions=80 if a.smoke else 10000,
                  large_gate_revisions=40 if a.smoke else 1000,
                  one_gate_baseline_every=10 if a.smoke else 100, large_gate_baseline_every=10,
                  smoke=a.smoke, seed=20260909, no_plot=a.no_plot)
    if a.plan_only:
        print(json.dumps(dict(config=config, memory=memory), indent=2))
        return
    if not a.no_plot:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot  # Fail before proving if plotting dependencies are unavailable.
    ram = memory_limit()
    require(math.isfinite(a.memory_limit_gib) and 0 < a.memory_limit_gib * 2**30 <= .9 * ram,
            'cutoff must be positive and at most 90% of detected RAM/cgroup')
    require(a.smoke or memory['suite_planning_peak_gib'] * 2**30 < min(.8 * ram, a.memory_limit_gib * 2**30),
            'planning estimate exceeds available allowance')
    if sys.platform.startswith('linux'):
        require(len(Path('/proc/swaps').read_text().splitlines()) <= 1, 'swap is enabled; disable it before measurement')
        available = next(int(s.split()[1]) * 1024 for s in Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:'))
        require(a.smoke or memory['suite_planning_peak_gib'] * 2**30 < .9 * available, 'insufficient currently available RAM')
    binary = (a.binary or HERE.parent / 'target/release/whole_system').resolve()
    config['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    out = a.output.resolve()
    if a.resume:
        require(json.loads((out / 'suite-config.json').read_text()) == config, 'resume configuration/binary mismatch')
    else:
        out.mkdir(parents=True, exist_ok=False)
        write_json(out / 'suite-config.json', config)
        write_json(out / 'memory-plan.json', memory)
        shutil.copy2(binary, out / 'whole-system')
    require(hashlib.sha256((out / 'whole-system').read_bytes()).hexdigest() == config['binary_sha256'], 'frozen binary changed')
    common = ['--binary', str(out / 'whole-system'), '--threads', str(a.threads),
              '--memory-limit-gib', str(a.memory_limit_gib), '--hierarchy-base', str(a.hierarchy_base),
              '--plaintext-kib', str(config['plaintext_kib'])]
    stages = [
        ('sweep', 40, '0,1,2,3,4,5,6,7', 1),
        ('one-gate', config['one_gate_revisions'], '0', config['one_gate_baseline_every']),
        ('128-gate', config['large_gate_revisions'], '7', config['large_gate_baseline_every']),
    ]
    started = time.time()
    total = 0
    try:
        for name, count, logs, cadence in stages:
            write_json(out / 'status.json', dict(status='running', stage=name, started=started))
            raw = out / name / 'run-a'
            if not raw.exists():
                raw.parent.mkdir(parents=True, exist_ok=True)
                command = [sys.executable, str(HERE / 'run.py'), str(log), str(raw), '--sequence', str(count),
                           '--update-log', str(max(map(int, logs.split(',')))), '--update-logs', logs,
                           '--baseline-every', str(cadence), *common]
                print(f'Starting {name}: {count} revisions at 2^{log} gates', flush=True)
                with (raw.parent / 'launcher.log').open('w') as target:
                    subprocess.run(command, check=True, stdout=target, stderr=subprocess.STDOUT)
            else:
                require(a.resume, 'stage already exists')
            raw_meta = json.loads((raw / 'run.json').read_text())
            for key, expected in dict(sequence_length=count, update_logs=logs, baseline_every=cadence,
                                      binary_sha256=config['binary_sha256'], threads=a.threads,
                                      hierarchy_base=a.hierarchy_base, trace_log=log,
                                      plaintext_cap_kib=config['plaintext_kib']).items():
                require(raw_meta[key] == expected, f'stage {name}: {key} mismatch')
            summary = (summarize_sweep(raw, raw.parent, a.no_plot) if name == 'sweep'
                       else analyze(raw, raw.parent, a.no_plot))
            total += summary['verified_samples']
        write_json(out / 'status.json', dict(status='complete', verified_samples=total, started=started, finished=time.time()))
        print(f'SUITE_COMPLETE: {total} verified samples', flush=True)
    except BaseException as error:
        write_json(out / 'status.json', dict(status='failed', stage=name, error=str(error), started=started))
        raise


if __name__ == '__main__':
    main()
