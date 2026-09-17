"""Check completeness and timing integrity, including interrupted runs."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from experiment_support import summarize


class ResultValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        (self.path / "experiment.json").write_text(json.dumps({
            "update_logs": list(range(11)), "sequence_len": 12,
        }))
        self.rows = [["initial", 0, 0, 100, 0.1, "true", 0]]
        for log in range(11):
            for revision in range(1, 13):
                self.rows.extend([
                    ["baseline", 1 << log, revision, 24, 0.1, "true", revision],
                    ["update", 1 << log, revision, revision, 0.1, "true", revision],
                ])

    def write_samples(self):
        with (self.path / "samples.csv").open("w", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(("phase", "update_gates", "revision", "prove_seconds",
                             "verify_seconds", "verified", "cumulative_distinct_gates"))
            writer.writerows(self.rows)

    def test_all_265_samples_include_first_revision_in_average(self):
        self.write_samples()
        result = summarize(self.path, require_complete=True)
        self.assertTrue(result["complete"])
        self.assertEqual(result["verified_samples"], 265)
        with (self.path / "comparison.csv").open() as source:
            comparison = list(csv.DictReader(source))
        self.assertEqual(len(comparison), 11)
        self.assertEqual(float(comparison[0]["update_mean_seconds"]), 6.5)
        self.assertEqual(float(comparison[0]["first_update_seconds"]), 1)

    def test_interruption_retains_complete_cases_but_fails_full_validation(self):
        self.rows.pop()
        self.write_samples()
        result = summarize(self.path)
        self.assertFalse(result["complete"])
        self.assertEqual(result["verified_samples"], 264)
        with (self.path / "comparison.csv").open() as source:
            self.assertEqual(len(list(csv.DictReader(source))), 10)
        with self.assertRaisesRegex(ValueError, "Incomplete experiment"):
            summarize(self.path, require_complete=True)

    def test_shared_baseline_has_145_samples_and_eleven_comparisons(self):
        (self.path / "baseline.json").write_text(json.dumps({"mode": "shared", "reference_gates": 1}))
        self.rows = [row for row in self.rows if row[0] != "baseline" or row[1] == 1]
        self.write_samples()
        result = summarize(self.path, require_complete=True)
        self.assertEqual(result["verified_samples"], 145)
        with (self.path / "comparison.csv").open() as source:
            comparison = list(csv.DictReader(source))
        self.assertEqual(len(comparison), 11)
        self.assertTrue(all(float(row["baseline_mean_seconds"]) == 24 for row in comparison))

    def test_forty_revisions_report_all_prover_and_verifier_means_and_maxima(self):
        (self.path / "experiment.json").write_text(json.dumps({
            "update_logs": list(range(11)), "sequence_len": 40,
        }))
        (self.path / "baseline.json").write_text('{"mode":"shared","reference_gates":1}')
        self.rows = [["initial", 0, 0, 100, 0.25, "true", 0]]
        for revision in range(1, 41):
            self.rows.append(["baseline", 1, revision, 41 - revision, revision / 10, "true", revision])
            for log in range(11):
                self.rows.append(["update", 1 << log, revision, revision, (41 - revision) / 10, "true", revision])
        self.write_samples()
        result = summarize(self.path, require_complete=True)
        self.assertEqual(result["verified_samples"], 481)
        self.assertEqual(result["expected_samples"], 481)
        with (self.path / "comparison.csv").open() as source:
            comparison = list(csv.DictReader(source))
        self.assertEqual(len(comparison), 11)
        for row in comparison:
            for phase in ("baseline", "update"):
                self.assertEqual(float(row[f"{phase}_mean_seconds"]), 20.5)
                self.assertEqual(float(row[f"{phase}_max_seconds"]), 40)
                self.assertEqual(float(row[f"{phase}_mean_verify_seconds"]), 2.05)
                self.assertEqual(float(row[f"{phase}_max_verify_seconds"]), 4)
            self.assertEqual(float(row["initial_prove_seconds"]), 100)
            self.assertEqual(float(row["initial_verify_seconds"]), 0.25)
        with (self.path / "summary.csv").open() as source:
            summary = list(csv.DictReader(source))
        self.assertEqual(len(summary), 13)
        for row in summary:
            initial = row["phase"] == "initial"
            self.assertEqual(float(row["mean_verify_seconds"]), 0.25 if initial else 2.05)
            self.assertEqual(float(row["max_verify_seconds"]), 0.25 if initial else 4)

    def test_partial_last_write_does_not_discard_prior_verified_samples(self):
        self.rows.pop()
        self.write_samples()
        with (self.path / "samples.csv").open("a") as output:
            output.write("update,1024,12,0.")
        result = summarize(self.path)
        self.assertEqual(result["verified_samples"], 264)
        self.assertTrue(result["ignored_incomplete_tail"])
        self.assertFalse(result["complete"])

    def test_duplicates_unverified_and_invalid_timings_are_rejected(self):
        for modification in ("duplicate", "unverified", "nan"):
            original = [row.copy() for row in self.rows]
            with self.subTest(modification=modification):
                if modification == "duplicate":
                    self.rows.append(self.rows[-1])
                elif modification == "unverified":
                    self.rows[-1][5] = "false"
                else:
                    self.rows[-1][3] = "nan"
                self.write_samples()
                with self.assertRaises(ValueError):
                    summarize(self.path)
            self.rows = original


if __name__ == "__main__":
    unittest.main()
