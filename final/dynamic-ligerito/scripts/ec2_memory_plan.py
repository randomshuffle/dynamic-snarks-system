#!/usr/bin/env python3
"""Allocation-based planning estimates, not measured Linux peaks or hard bounds."""
import argparse
import json
from pathlib import Path

GIB = 1 << 30
# Preserve the historical footprint observations independently of pruned raw logs.
CALIBRATION_FILE = 'final/dynamic-ligerito/scripts/CALIBRATION.json'
CALIBRATION_RECORDS = json.loads(Path(__file__).with_name('CALIBRATION.json').read_text())['records']
CALIBRATION = [(CALIBRATION_FILE, row['trace_log'], row['peak_macos_footprint_bytes'])
               for row in CALIBRATION_RECORDS]


def power2(x):
    return 1 << (max(1, x) - 1).bit_length()


def transition_bound(log, touched_gates):
    """Bound the shape of ANY gate-closed subset of this size, identity wiring.

    Each gate contributes three leaves, two level-one nodes, one level-two
    node. At higher levels there are at most min(K, N/2**j) active nodes.
    Computed records have four claims; boundaries have three. A binary tree's
    boundary count is internal_count + 1 - selected_leaf_count. These formulas
    upper-bound each shape even if every revision changes fresh gates.
    The allocation multiplier is the current dynamic::transition_resource_estimate.
    """
    n = 1 << log
    k = min(n, touched_gates)
    top = sum(min(k, n >> j) for j in range(log + 1))
    hashes = power2(4 * (5 * k + top))
    boundaries = power2(max(2, 3 * (top - k + 1)))
    auxiliary = power2(4 * k) * power2(22 + max(log - 1, 8))
    committed = 20 * hashes + 8 * boundaries + auxiliary
    retained_states = 70 if hashes <= 32768 else 28
    scratch = (12 * committed + retained_states * 4 * hashes) * 16
    # Planning reserves, not source-derived strict byte bounds: dense keys,
    # assignment/tree clones, allocator retention, and sparse overlay maps.
    resident = n * 4096
    overlays = touched_gates * 3 * (log + 3) * 256
    return dict(max_distinct_gates=k, padded_hash_rows_bound=hashes,
                padded_boundary_rows_bound=boundaries, auxiliary_fields_bound=auxiliary,
                transition_allocation_estimate_gib=scratch / GIB,
                retained_state_reserve_gib=resident / GIB,
                overlay_reserve_gib=overlays / GIB,
                planning_peak_gib=1.25 * (scratch + resident + overlays) / GIB)


def estimate(log):
    scaled = [size * 2 ** (log - old_log) / GIB for _, old_log, size in CALIBRATION]
    updates = {name: transition_bound(log, gates * revisions) for name, gates, revisions in (
        ('sweep_worst_case', 128, 40), ('one_gate_10000', 1, 10000), ('128_gate_1000', 128, 1000))}
    return dict(trace_log=log, gates=1 << log,
                initialization_extrapolated_gib=[min(scaled), max(scaled)],
                initialization_with_25_percent_margin_gib=max(scaled) * 1.25,
                initial_round_states_alone_gib=22 * 8 * (1 << log) * 64 / GIB,
                updates=updates,
                suite_planning_peak_gib=max(max(scaled) * 1.25,
                                            *(row['planning_peak_gib'] for row in updates.values())))


def report():
    return dict(instance='r7a.8xlarge', memory_gib=256, vcpus=32, physical_cores=32, workers=32,
                selected_trace_log=23, runtime_rss_cutoff_gib=216,
                prelaunch_planning_allowance_fraction=.8,
                candidates=[estimate(log) for log in (22, 23, 24)],
                calibration=[dict(path=CALIBRATION_FILE, **row) for row in CALIBRATION_RECORDS],
                caveats=[
                    'historical macOS footprint values are embedded in CALIBRATION.json; original raw logs were pruned',
                    'macOS footprint extrapolated to Linux; allocator, PCS padding and CPU schedules can differ',
                    'transition shape bounds cover all revisions; allocation multipliers and resident reserves are estimates',
                    'initialization, baseline, and updates execute serially; their peaks are not added',
                    'input size means arithmetic gates; 256 public inputs are held fixed',
                    '2^23 is the estimated largest power-of-two input for this implementation, subject to EC2 calibration',
                ])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trace-log', type=int)
    a = p.parse_args()
    print(json.dumps(estimate(a.trace_log) if a.trace_log is not None else report(), indent=2))
