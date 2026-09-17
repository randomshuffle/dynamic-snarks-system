"""Validate matched samples and exact proof fingerprints, then summarize latency."""
from pathlib import Path
from collections import defaultdict
import csv
import json
import re
import statistics

root = Path(__file__).resolve().parent
summary = []
components = []
hashes = defaultdict(set)
for mode in ('before', 'after'):
    for workers in (1, 8):
        lines = (root/f'{mode}-{workers}.csv').read_text().splitlines()
        assert f'threads={workers},parallel=true,initial_folding=4,samples=5' in lines[0]
        rows = list(csv.DictReader(lines[1:]))
        for phase in ('initial', 'baseline', 'update'):
            records = [r for r in rows if r['phase'] == phase]
            assert len(records) == (1 if phase == 'initial' else 5)
            assert sorted(int(r['sample']) for r in records) == list(range(len(records)))
            hashes[phase].update(r['proof_hash'] for r in records)
            times = [float(r['prove_ms']) for r in records]
            summary.append(dict(mode=mode, workers=workers, phase=phase, count=len(times),
                                mean_ms=statistics.mean(times), median_ms=statistics.median(times),
                                min_ms=min(times), max_ms=max(times)))
        active = None
        timings = defaultdict(lambda: defaultdict(float))
        def add(label, ms):
            phase, sample = active
            timings[phase, label][sample] += ms
        for line in (root/f'{mode}-{workers}.log').read_text().splitlines():
            match = re.fullmatch(r'comparison,(initial|baseline|update),(\d+),(begin|end)', line)
            if match:
                active = (match[1], int(match[2])) if match[3] == 'begin' and (match[1] == 'initial' or int(match[2]) > 0) else None
            if active is None:
                continue
            match = re.fullmatch(r'profile checkpoint: (.+) complete in ([\d.]+)s', line)
            if match:
                add(match[1], float(match[2])*1000)
            match = re.fullmatch(r'CAIR checkpoint: (routing|Poseidon) sumcheck round (\d+)/(\d+) complete \(([\d.]+)s phase elapsed\)', line)
            if match and match[2] == match[3]:
                add('initial CAIR: '+match[1]+' sumcheck total', float(match[4])*1000)
            match = re.fullmatch(r'CAIR checkpoint: full-round sumcheck 4/4 round (\d+)/(\d+) complete \(([\d.]+)s phase elapsed\)', line)
            if match and match[1] == match[2]:
                add('initial CAIR: full-round reductions', float(match[3])*1000)
        for (phase, component), samples in timings.items():
            components.append(dict(mode=mode, workers=workers, phase=phase, component=component,
                                    count=len(samples), mean_ms=statistics.mean(samples.values())))
assert all(len(h) == 1 for h in hashes.values()), hashes
(root/'proof-hashes.json').write_text(json.dumps({phase: next(iter(values)) for phase, values in hashes.items()}, indent=2)+'\n')
for name, rows in [('summary.csv',summary),('components.csv',components)]:
    with (root/name).open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader(); writer.writerows(rows)
for row in summary:
    print(row)
print('All 44 timed proof fingerprints match across builds and worker counts.')
