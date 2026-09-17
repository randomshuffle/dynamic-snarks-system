"""Summarize nested first-update profiling timers without double counting."""

from collections import defaultdict
import csv
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parent


def write(name, rows):
    with (ROOT / name).open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


latencies = []
for mode in ("control", "detail"):
    rows = list(csv.DictReader((ROOT / f"internals-{mode}.csv").read_text().splitlines()[2:]))
    times = [float(row["update_ms"]) for row in rows]
    assert len(times) == 30
    latencies.append(dict(mode=mode, samples=len(times), first_ms=times[0],
                          median_ms=statistics.median(times), mean_ms=statistics.mean(times),
                          min_ms=min(times), max_ms=max(times)))

sample = None
section = "relation"
events = []
for line in (ROOT / "internals-detail.log").read_text().splitlines():
    match = re.fullmatch(r"first-update sample (\d+) (begin|end)", line)
    if match:
        sample = int(match[1]) if match[2] == "begin" else None
        section = "relation"
    if sample is None:
        continue
    if line.startswith("detail-begin,opening,"):
        section = {"n15": "main_opening", "n12": "product_opening"}[line.rsplit(",", 1)[1]]
    match = re.fullmatch(r"profile checkpoint: WHIR initial claim weights \(variables=(\d+), claims=(\d+)\) complete in ([\d.]+)s", line)
    if match:
        events.append(dict(sample=sample, section=section, component="initial_claims",
                           phase="weights", context=f"n{match[1]}-claims{match[2]}", ms=float(match[3])*1000))
    if not line.startswith("detail,"):
        continue
    _, component, phase, context, ms = line.split(",")
    events.append(dict(sample=sample, section=section, component=component,
                       phase=phase, context=context, ms=float(ms)))

totals = defaultdict(lambda: [0.0] * 30)
rounds = defaultdict(list)
for event in events:
    key = (event["section"], event["component"], event["phase"])
    totals[key][event["sample"]] += event["ms"]
    rounds[(*key, event["context"])].append(event["ms"])
summary = [dict(section=key[0], component=key[1], phase=key[2],
                mean_ms=statistics.mean(times), median_ms=statistics.median(times))
           for key, times in totals.items()]
by_round = [dict(section=key[0], component=key[1], phase=key[2], context=key[3],
                 count=len(times), mean_ms=statistics.mean(times))
            for key, times in rounds.items()]
write("internals-latency.csv", latencies)
write("internals-events.csv", events)
write("internals-summary.csv", summary)
write("internals-rounds.csv", by_round)
coarse = []
for mode in ("control", "detail"):
    values = defaultdict(list)
    for line in (ROOT / f"internals-{mode}.log").read_text().splitlines():
        match = re.fullmatch(r"profile checkpoint: (.+) complete in ([\d.]+)s", line)
        if match:
            values[match[1]].append(float(match[2])*1000)
        match = re.fullmatch(r"transition CAIR (main|product) checkpoint: WHIR opening proof complete \(([\d.]+)s opening elapsed: ([\d.]+)s evaluations, ([\d.]+)s proof\)", line)
        if match:
            values[f"WHIR {match[1]} opening"].append(float(match[2])*1000)
    coarse.extend(dict(mode=mode, phase=phase, mean_ms=statistics.mean(times)) for phase, times in values.items())
write("internals-coarse.csv", coarse)
for row in latencies:
    print(row)
for row in summary:
    print(row)
