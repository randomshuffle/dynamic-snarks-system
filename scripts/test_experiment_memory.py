"""Exercise memory sampling, actual cutoff termination and fail-closed behavior."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experiment_memory import MemoryMonitor, memory_reader


class MemoryTrialTests(unittest.TestCase):
    def test_small_process_completes_with_measurements(self):
        with tempfile.TemporaryDirectory() as temp:
            process = subprocess.Popen([sys.executable, "-c",
                "import time; x=bytearray(16*1024**2); time.sleep(.5)"], start_new_session=True)
            monitor = MemoryMonitor(process.pid, 96 * 1024**2, temp, memory_reader(), interval=.02)
            monitor.start()
            self.assertEqual(process.wait(timeout=5), 0)
            result = monitor.stop()
            self.assertGreater(result["samples"], 0)
            self.assertFalse(result["limit_exceeded"])
            self.assertIsNone(result["error"])
            self.assertTrue((Path(temp) / "memory-samples.csv").is_file())

    def test_actual_rss_cutoff_stops_large_process(self):
        with tempfile.TemporaryDirectory() as temp:
            process = subprocess.Popen([sys.executable, "-c",
                "import time; x=bytearray(128*1024**2); time.sleep(10)"], start_new_session=True)
            monitor = MemoryMonitor(process.pid, 48 * 1024**2, temp, memory_reader(), interval=.02)
            monitor.start()
            try:
                self.assertNotEqual(process.wait(timeout=5), 0)
                result = monitor.stop()
                self.assertTrue(result["limit_exceeded"])
                self.assertGreater(result["peak_sampled_rss_bytes"], 48 * 1024**2)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                monitor.stop()

    def test_sampling_error_stops_process(self):
        def broken(_pid):
            raise RuntimeError("fixture sampling failure")
        with tempfile.TemporaryDirectory() as temp:
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"],
                                       start_new_session=True)
            monitor = MemoryMonitor(process.pid, 96 * 1024**2, temp, broken)
            monitor.start()
            try:
                self.assertNotEqual(process.wait(timeout=5), 0)
                result = monitor.stop()
                self.assertIn("fixture sampling failure", result["error"])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                monitor.stop()


if __name__ == "__main__":
    unittest.main()
