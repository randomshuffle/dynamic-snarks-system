"""Summarize the verified thread-count sweep, excluding each process's warmup."""

from collections import defaultdict
import csv
from pathlib import Path
import re
import statistics

root = Path(__file__).resolve().parent
latencies = []
phases = []
for threads in (1, 2, 4, 8):
    lines = (root / f"threads-{threads}.csv").read_text().splitlines()
    assert f"threads={threads},parallel=true,initial_folding=4" in lines[0]
    rows = list(csv.DictReader(lines[1:]))
    for phase in ("baseline", "update"):
        selected = [row for row in rows if row["phase"] == phase]
        assert len(selected) == 6
        assert all(int(row["threads"]) == threads for row in selected)
        times = [float(row["prove_ms"]) for row in selected]
        latencies.append(dict(threads=threads, phase=phase, samples=len(times),
                              mean_ms=statistics.mean(times), median_ms=statistics.median(times),
                              min_ms=min(times), max_ms=max(times)))
    active = None
    timings = defaultdict(lambda: [0.0] * 6)
    seen = defaultdict(set)

    def record(label, ms):
        phase, sample = active
        timings[phase, label][sample - 1] += ms
        seen[phase, label].add(sample)

    for line in (root / f"threads-{threads}.log").read_text().splitlines():
        match = re.fullmatch(r"parallel-scaling,(baseline|update),(\d+),(begin|end)", line)
        if match:
            active = (match[1], int(match[2])) if match[3] == "begin" and int(match[2]) > 0 else None
        if active is None:
            continue
        match = re.fullmatch(r"profile checkpoint: (.+) complete in ([\d.]+)s", line)
        if match:
            record(match[1], float(match[2]) * 1000)
        match = re.fullmatch(r"transition CAIR (main|product) checkpoint: WHIR opening proof complete \(([\d.]+)s opening elapsed: ([\d.]+)s evaluations, ([\d.]+)s proof\)", line)
        if match:
            record(f"WHIR {match[1]} opening", float(match[2]) * 1000)
    for (phase, label), times in timings.items():
        assert seen[phase, label] == set(range(1, 7)), (threads, phase, label)
        phases.append(dict(threads=threads, phase=phase, component=label,
                           mean_ms=statistics.mean(times)))

for filename, rows in (("summary.csv", latencies), ("phases.csv", phases)):
    with (root / filename).open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
for row in latencies:
    print(row)
