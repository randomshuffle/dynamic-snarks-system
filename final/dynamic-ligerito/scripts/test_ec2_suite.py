"""Regression checks for memory planning, Linux accounting, and sweep integrity."""
import itertools
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from ec2_memory_plan import estimate, power2, transition_bound
from ec2_suite import summarize_sweep
from run import maximum_rss_bytes


class MemoryTests(unittest.TestCase):
    def test_linux_rusage_units(self):
        self.assertEqual(maximum_rss_bytes(4096, 'linux'), 4194304)
        self.assertEqual(maximum_rss_bytes(4096, 'darwin'), 4096)

    def test_capacity_boundary(self):
        self.assertLess(estimate(23)['suite_planning_peak_gib'], 256 * .8)
        self.assertGreater(estimate(24)['initialization_extrapolated_gib'][0], 256)
        self.assertEqual(transition_bound(23, 128000)['transition_allocation_estimate_gib'], 56)

    def test_gate_support_bound_against_exhaustive_small_trees(self):
        # Count actual active and boundary nodes independently for every subset.
        log = 3
        for size in range(1, 9):
            bound = transition_bound(log, size)
            for gates in itertools.combinations(range(8), size):
                active = {4 * g + j for g in gates for j in range(3)}
                hashes, boundaries = len(active), 0
                for _ in range(log + 2):
                    boundaries += sum((x ^ 1) not in active for x in active)
                    active = {x >> 1 for x in active}
                    hashes += len(active)
                self.assertLessEqual(power2(4 * hashes), bound['padded_hash_rows_bound'])
                self.assertLessEqual(power2(3 * boundaries), bound['padded_boundary_rows_bound'])


class SweepTests(unittest.TestCase):
    def fixture(self, root):
        meta = dict(exit_code=0, memory_monitor=dict(error=None, limit_exceeded=False),
                    baseline_every=1, update_logs='0,7', sequence_length=2, trace_log=10,
                    threads=2, hierarchy_base=2)
        (root / 'run.json').write_text(json.dumps(meta))
        (root / 'stdout.log').write_text('EXPERIMENT_COMPLETE\n')
        rows = [dict(phase='initial', update_gates=0, revision=0, prove_s=10)]
        rows += [dict(phase=p, update_gates=k, revision=r, prove_s=r if p == 'update' else 6)
                 for k in (1, 128) for r in (1, 2) for p in ('update', 'baseline')]
        for row in rows:
            row.update(gates=1024, verified=True, verify_s=.1, serialized_bytes=100)
        self.write(root, rows)
        return rows

    def write(self, root, rows):
        (root / 'samples.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))

    def test_complete_paired_sweep_statistics(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            self.fixture(root)
            result = summarize_sweep(root, root / 'report', no_plot=True)
            self.assertEqual(result['verified_samples'], 9)
            self.assertEqual(result['comparisons'][0]['prover_speedup'], 4)
            self.assertEqual(result['comparisons'][1]['update_prove_s_max'], 2)

    def test_compressed_publication_samples(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            self.fixture(root)
            samples = root / 'samples.jsonl'
            with gzip.open(root / 'samples.jsonl.gz', 'wb') as target:
                target.write(samples.read_bytes())
            samples.unlink()
            result = summarize_sweep(root, root / 'report', no_plot=True)
            self.assertEqual(result['verified_samples'], 9)
            self.assertEqual(result['comparisons'][0]['prover_speedup'], 4)

    def test_partial_duplicate_unverified_and_wrong_circuit_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            rows = self.fixture(root)
            bad_variants = [rows[:-1], rows + [rows[-1]],
                            rows[:-1] + [{**rows[-1], 'verified': False}],
                            rows[:-1] + [{**rows[-1], 'gates': 2048}]]
            for invalid in bad_variants:
                self.write(root, invalid)
                with self.assertRaises(ValueError):
                    summarize_sweep(root, root / 'report', no_plot=True)


if __name__ == '__main__':
    unittest.main()
