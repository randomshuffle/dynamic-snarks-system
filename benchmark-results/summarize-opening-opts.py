"""Regenerate the matched opening-optimization timing and phase summaries."""

from collections import defaultdict
import csv
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parent


def write_csv(filename, rows):
    with (ROOT / filename).open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


summary = []
phases = []
for kind in ("leaf", "gate"):
    for version in ("control", "after"):
        name = f"opening-opts-{version}-{kind}"
        lines = (ROOT / f"{name}.csv").read_text().splitlines()
        rows = list(csv.DictReader(lines[2:]))
        times = [float(row["update_ms"]) for row in rows]
        assert len(times) == 30, (name, len(times))
        summary.append(dict(
            kind=kind, version=version, samples=len(times), first_ms=times[0],
            mean_ms=statistics.mean(times), median_ms=statistics.median(times),
            min_ms=min(times), max_ms=max(times), stdev_ms=statistics.stdev(times),
            verify_mean_ms=statistics.mean(float(row["verify_ms"]) for row in rows),
        ))
        values = defaultdict(list)
        for line in (ROOT / f"{name}.log").read_text().splitlines():
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
            assert len(durations) == len(times), (name, phase, len(durations))
            phases.append(dict(kind=kind, version=version, phase=phase,
                               mean_ms=statistics.mean(durations), median_ms=statistics.median(durations)))

write_csv("opening-opts-summary.csv", summary)
write_csv("opening-opts-phases.csv", phases)
for row in summary:
    print(row)
for row in phases:
    if row["kind"] == "leaf" and (row["mean_ms"] >= 1 or "WHIR initial" in row["phase"]):
        print(row)
