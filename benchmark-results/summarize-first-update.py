"""Summarize the first-update CSVs and instrumented phase logs (stdlib only)."""

import csv
from collections import defaultdict
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parent


def write_csv(name, rows):
    with (ROOT / name).open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


summary = []
phases = []
for kind in ("leaf", "gate"):
    lines = (ROOT / f"first-update-n16-{kind}.csv").read_text().splitlines()
    samples = list(csv.DictReader(lines[2:]))
    times = [float(row["update_ms"]) for row in samples]
    summary.append(dict(
        kind=kind, samples=len(times), first_ms=times[0],
        mean_ms=statistics.mean(times), median_ms=statistics.median(times),
        min_ms=min(times), max_ms=max(times), stdev_ms=statistics.stdev(times),
        verify_mean_ms=statistics.mean(float(row["verify_ms"]) for row in samples),
    ))
    values = defaultdict(list)
    for line in (ROOT / f"first-update-n16-{kind}-profile.log").read_text().splitlines():
        match = re.fullmatch(r"profile checkpoint: (.+) complete in ([\d.]+)s", line)
        if match:
            values[match[1]].append(float(match[2]) * 1000)
        match = re.fullmatch(r"transition CAIR checkpoint: (.+ commitment) complete in ([\d.]+)s", line)
        if match:
            values[match[1]].append(float(match[2]) * 1000)
        match = re.fullmatch(
            r"transition CAIR (main|product) checkpoint: WHIR opening proof complete "
            r"\(([\d.]+)s opening elapsed: ([\d.]+)s evaluations, ([\d.]+)s proof\)", line,
        )
        if match:
            for label, value in zip(("opening total", "evaluations", "proof"), match.groups()[1:]):
                values[f"WHIR {match[1]} {label}"].append(float(value) * 1000)
    for phase, durations in values.items():
        assert len(durations) == len(samples), (kind, phase, len(durations))
        phases.append(dict(kind=kind, phase=phase, samples=len(durations),
                           mean_ms=statistics.mean(durations), median_ms=statistics.median(durations)))

detail = defaultdict(list)
for line in (ROOT / "first-update-n16-leaf-detail.log").read_text().splitlines():
    match = re.fullmatch(r"profile checkpoint: (WHIR initial .+) complete in ([\d.]+)s", line)
    if match:
        detail[match[1]].append(float(match[2]) * 1000)

write_csv("first-update-n16-summary.csv", summary)
write_csv("first-update-n16-phases.csv", phases)
write_csv("first-update-n16-whir.csv", [
    dict(phase=phase, samples=len(times), mean_ms=statistics.mean(times), median_ms=statistics.median(times))
    for phase, times in detail.items()
])
for row in summary:
    print(row)
for row in phases:
    if row["kind"] == "leaf" and row["mean_ms"] >= 1:
        print(row)
for phase, times in detail.items():
    print(phase, "mean_ms", statistics.mean(times))
