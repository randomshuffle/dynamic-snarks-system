"""Accounting and input-integrity regressions for the amortization benchmark."""

import json
import gzip
import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from one_gate_amortization import analyze, cumulative_curve, read_run


def updates(times):
    return [dict(revision=i, prove_s=t, mode="polynomial" if t >= 10 else "direct")
            for i, t in enumerate(times, 1)]


class CurveTests(unittest.TestCase):
    def test_initial_cost_and_carry_can_create_an_interior_maximum(self):
        rows, summary = cumulative_curve(2, updates([1, 1, 20, 1]),
                                         [dict(revision=1, prove_s=10), dict(revision=4, prove_s=10)])
        self.assertEqual([r["dynamic_total_s"] for r in rows], [3, 4, 24, 25])
        self.assertEqual([r["baseline_total_s"] for r in rows], [10, 20, 30, 40])
        self.assertEqual(summary["maximum"]["updates"], 2)
        self.assertEqual(summary["maximum"]["speedup"], 5)
        self.assertEqual(summary["promotions"][0]["revision"], 3)

    def test_full_baseline_uses_actual_prefix_sums(self):
        rows, summary = cumulative_curve(2, updates([1, 1, 1]),
                                         [dict(revision=i, prove_s=t) for i, t in enumerate([2, 4, 9], 1)])
        self.assertEqual([r["baseline_total_s"] for r in rows], [2, 6, 15])
        self.assertEqual(summary["baseline_total_method"], "measured prefix sum")
        self.assertEqual(summary["first_break_even_update"], 2)

    def test_break_even_can_be_lost_after_a_carry(self):
        _, summary = cumulative_curve(2, updates([1, 1, 10, 1, 1]),
                                      [dict(revision=1, prove_s=4), dict(revision=5, prove_s=4)])
        self.assertEqual(summary["first_break_even_update"], 1)
        self.assertEqual(summary["sustained_break_even_update"], 4)

    def test_no_break_even(self):
        _, summary = cumulative_curve(100, updates([1, 1]), [dict(revision=1, prove_s=1)])
        self.assertIsNone(summary["first_break_even_update"])
        self.assertIsNone(summary["sustained_break_even_update"])

    def test_bad_samples_are_rejected(self):
        for times in ([0], [-1], [float("nan")], [float("inf")]):
            with self.subTest(times=times), self.assertRaises(ValueError):
                cumulative_curve(1, updates(times), [dict(revision=1, prove_s=1)])
        with self.assertRaisesRegex(ValueError, "non-contiguous"):
            cumulative_curve(1, [dict(revision=2, prove_s=1)], [dict(revision=1, prove_s=1)])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            cumulative_curve(1, updates([1]), [dict(revision=1, prove_s=1)] * 2)


class RunIntegrityTests(unittest.TestCase):
    def make_run(self, root, update_log=0):
        meta = dict(exit_code=0, memory_monitor=dict(error=None, limit_exceeded=False),
                    sequence_length=3, baseline_every=2, update_logs=str(update_log), threads=8,
                    plaintext_cap_kib=2048)
        (root / "run.json").write_text(json.dumps(meta))
        (root / "setup.json").write_text(json.dumps(dict(baseline_s=2, dynamic_s=3)))
        (root / "stdout.log").write_text("EXPERIMENT_COMPLETE\n")
        rows = [dict(phase="initial", revision=0, update_gates=0)]
        for revision in range(1, 4):
            rows += [dict(phase="update", revision=revision, update_gates=1 << update_log,
                          update_statistics=dict(mode="direct", polynomial_gates=0)),
                     dict(phase="baseline", revision=revision, update_gates=1 << update_log)]
        for row in rows:
            row.update(prove_s=1, serialized_bytes=100, gates=512, verified=True)
        self.write_rows(root, rows)
        return rows

    def write_rows(self, root, rows):
        (root / "samples.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))

    def test_complete_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_run(root)
            initial, dynamic, baseline, _, gates = read_run(root)
            self.assertEqual((initial, len(dynamic), len(baseline), gates), (1, 3, 3, 512))

    def test_compressed_publication_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_run(root)
            samples = root / "samples.jsonl"
            with gzip.open(root / "samples.jsonl.gz", "wb") as target:
                target.write(samples.read_bytes())
            samples.unlink()
            initial, dynamic, baseline, _, gates = read_run(root)
            self.assertEqual((initial, len(dynamic), len(baseline), gates), (1, 3, 3, 512))

    def test_missing_revision_or_unverified_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = self.make_run(root)
            self.write_rows(root, [r for r in rows if not (r["phase"] == "update" and r["revision"] == 2)])
            with self.assertRaisesRegex(ValueError, "every revision"):
                read_run(root)
            rows[-1]["verified"] = False
            self.write_rows(root, rows)
            with self.assertRaisesRegex(ValueError, "unverified"):
                read_run(root)

    def test_report_charges_setup_once_to_each_side(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_run(root)
            with contextlib.redirect_stdout(io.StringIO()):
                result = analyze(root, root / "report", no_plot=True)
            self.assertEqual(result["final"]["speedup"], 3 / 4)
            self.assertEqual(result["final"]["speedup_with_setup"], 5 / 7)
            self.assertEqual(result["maximum_with_setup"]["updates"], 3)
            self.assertTrue((root / "report/curve.csv").is_file())
            self.assertEqual(json.loads((root / "report/summary.json").read_text())["verified_samples"], 7)

    def test_64_gate_report_and_mixed_size_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = self.make_run(root, update_log=6)
            with contextlib.redirect_stdout(io.StringIO()):
                result = analyze(root, root / "report", no_plot=True)
            self.assertEqual(result["update_gates"], 64)
            self.assertIn("selects 64 distinct gates", (root / "report/README.md").read_text())
            rows[-1]["update_gates"] = 1
            self.write_rows(root, rows)
            with self.assertRaisesRegex(ValueError, "sample update size"):
                read_run(root)

    def test_hierarchy_base_is_checked_against_measured_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = self.make_run(root)
            metadata = json.loads((root / "run.json").read_text())
            metadata["hierarchy_base"] = 4
            (root / "run.json").write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError, "sample hierarchy base"):
                read_run(root)
            for row in rows:
                row["hierarchy_base"] = 4
            self.write_rows(root, rows)
            setup = json.loads((root / "setup.json").read_text())
            setup["hierarchy_base"] = 4
            (root / "setup.json").write_text(json.dumps(setup))
            with contextlib.redirect_stdout(io.StringIO()):
                report = analyze(root, root / "report", no_plot=True)
            self.assertEqual(report["hierarchy_base"], 4)
            self.assertEqual(report["tables_per_level"], 3)


if __name__ == "__main__":
    unittest.main()
