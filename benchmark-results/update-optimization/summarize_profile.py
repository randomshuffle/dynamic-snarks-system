"""Aggregate elapsed timers by sample, preserving concurrent opening scope."""
from pathlib import Path
from collections import defaultdict
import csv,re,statistics,sys
root=Path(__file__).resolve().parent
prefix=sys.argv[1] if len(sys.argv)>1 else 'profile'
sample=None
events=[]
for line in (root/f'{prefix}-detail.log').read_text().splitlines():
    match=re.fullmatch(r'first-update sample (\d+) (begin|end)',line)
    if match:
        sample=int(match[1]) if match[2]=='begin' else None
    if sample in (None,0):continue
    if line.startswith('detail,'):
        _,component,phase,context,ms=line.split(',')
        scope,context=context.split(':',1)
        events.append(dict(sample=sample,scope=scope,component=component,phase=phase,context=context,ms=float(ms)))
keys=defaultdict(lambda:defaultdict(float))
rounds=defaultdict(list)
for e in events:
    key=(e['scope'],e['component'],e['phase'])
    keys[key][e['sample']]+=e['ms']
    rounds[(*key,e['context'])].append(e['ms'])
rows=[dict(scope=k[0],component=k[1],phase=k[2],mean_ms=statistics.mean(v.values()),count=len(v)) for k,v in keys.items()]
by_round=[dict(scope=k[0],component=k[1],phase=k[2],context=k[3],mean_ms=statistics.mean(v),count=len(v)) for k,v in rounds.items()]
for name,items in [('summary',rows),('rounds',by_round),('events',events)]:
    with (root/f'{prefix}-{name}.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=items[0].keys());w.writeheader();w.writerows(items)
for r in rows:print(r)
