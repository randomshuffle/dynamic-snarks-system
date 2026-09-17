"""Optional out-of-process RSS sampling and cutoff for local memory trials."""

import csv
import ctypes
import errno
import os
import signal
import sys
import threading
import time
from pathlib import Path


def memory_reader():
    if sys.platform == "darwin":
        # Darwin rusage_info_v0, including compressed-memory accounting in
        # phys_footprint. This reads one child process without enumerating apps.
        class Usage(ctypes.Structure):
            _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
                (name, ctypes.c_uint64) for name in (
                    "user_time", "system_time", "package_wakeups", "interrupt_wakeups",
                    "pageins", "wired_size", "resident_size", "phys_footprint",
                    "start_time", "exit_time")]
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        library.proc_pid_rusage.restype = ctypes.c_int

        def read(pid):
            usage = Usage()
            if library.proc_pid_rusage(pid, 0, ctypes.byref(usage)):
                error = ctypes.get_errno()
                if error == errno.ESRCH:
                    raise ProcessLookupError(pid)
                raise OSError(error, os.strerror(error))
            return usage.resident_size, usage.phys_footprint
    elif sys.platform.startswith("linux"):
        def read(pid):
            try:
                status = (Path("/proc") / str(pid) / "status").read_text()
            except FileNotFoundError as error:
                raise ProcessLookupError(pid) from error
            for line in status.splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024, None
            # A zombie has no resident pages while waiting to be reaped.
            if "State:\tZ" in status:
                return 0, None
            raise RuntimeError("Cannot read benchmark RSS")
    else:
        raise RuntimeError("RSS monitoring requires macOS or Linux")
    read(os.getpid())  # Fail before launching a benchmark if sampling is unavailable.
    return read


class MemoryMonitor:
    def __init__(self, pid, limit_bytes, output, reader, interval=0.2):
        self.pid, self.limit, self.output, self.reader = pid, limit_bytes, Path(output), reader
        self.interval = interval
        self.stop_event = threading.Event()
        self.metrics = {"rss_limit_bytes": limit_bytes, "sampling_interval_seconds": interval,
                        "samples": 0, "peak_sampled_rss_bytes": 0,
                        "peak_sampled_phys_footprint_bytes": None,
                        "limit_exceeded": False, "error": None}
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join()
        return self.metrics

    def _kill(self):
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _run(self):
        started = time.monotonic()
        try:
            with (self.output / "memory-samples.csv").open("w", buffering=1) as target:
                writer = csv.writer(target)
                writer.writerow(("elapsed_seconds", "rss_bytes", "phys_footprint_bytes"))
                while not self.stop_event.is_set():
                    try:
                        rss, footprint = self.reader(self.pid)
                    except ProcessLookupError:
                        break
                    writer.writerow((time.monotonic() - started, rss, footprint))
                    self.metrics["samples"] += 1
                    self.metrics["peak_sampled_rss_bytes"] = max(self.metrics["peak_sampled_rss_bytes"], rss)
                    if footprint is not None:
                        self.metrics["peak_sampled_phys_footprint_bytes"] = max(
                            self.metrics["peak_sampled_phys_footprint_bytes"] or 0, footprint)
                    if rss > self.limit:
                        self.metrics["limit_exceeded"] = True
                        self._kill()
                        break
                    self.stop_event.wait(self.interval)
        except Exception as error:
            # Sampling failures must not leave an unguarded trial running.
            self.metrics["error"] = str(error)
            self._kill()
