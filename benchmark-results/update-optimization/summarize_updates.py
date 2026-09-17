"""Summarize all matched samples; drop only each process's designated warmup."""
from pathlib import Path
import csv,json,statistics
root=Path(__file__).resolve().parent
rows=[]
for mode in ['before','after']:
 for workers,blocks in [(8,3),(1,1)]:
  times=[]
  for block in range(blocks):
   path=root/f'{mode}{workers}-{block}.csv'
   lines=path.read_text().splitlines()
   assert 'gates=65536' in lines[0] and f'rayon_threads={workers}' in lines[0]
   records=list(csv.DictReader(lines[2:]));assert len(records)==31
   assert [int(r['sample']) for r in records]==list(range(31))
   times.extend(float(r['update_ms']) for r in records[1:])
  rows.append(dict(mode=mode,workers=workers,samples=len(times),mean_ms=statistics.mean(times),median_ms=statistics.median(times),min_ms=min(times),max_ms=max(times)))
with (root/'summary.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
for row in rows:print(row)

# Coarse phases are rounded and may overlap. Keep them separate from latency.
import re
from collections import defaultdict
phases=[]
for mode in ['before','after']:
 values=defaultdict(list)
 for block in range(3):
  sample=None
  for line in (root/f'{mode}8-{block}.log').read_text().splitlines():
   m=re.fullmatch(r'first-update sample (\d+) (begin|end)',line)
   if m:sample=int(m[1]) if m[2]=='begin' else None
   if sample in (None,0):continue
   m=re.fullmatch(r'profile checkpoint: (.+) complete in ([\d.]+)s',line)
   if m:values[m[1]].append(float(m[2])*1000)
   m=re.fullmatch(r'transition CAIR (main|product) checkpoint: WHIR opening proof complete \(([\d.]+)s opening elapsed: ([\d.]+)s evaluations, ([\d.]+)s proof\)',line)
   if m:
    for tag,index in [('total',2),('evaluations',3),('proximity',4)]:values[f'WHIR {m[1]} {tag}'].append(float(m[index])*1000)
 phases.extend(dict(mode=mode,component=k,mean_ms=statistics.mean(v),median_ms=statistics.median(v),count=len(v)) for k,v in values.items())
with (root/'phases.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=phases[0].keys());w.writeheader();w.writerows(phases)

full_rows=list(csv.DictReader((root/'full-after.csv').read_text().splitlines()[1:]))
old=json.loads((root.parent/'parallel-provers/proof-hashes.json').read_text())
full=[]
for phase in ['initial','baseline','update']:
 records=[r for r in full_rows if r['phase']==phase]
 assert len(records)==(1 if phase=='initial' else 5)
 times=[float(r['prove_ms']) for r in records]
 hashes={r['proof_hash'] for r in records};assert len(hashes)==1
 if phase!='update':assert hashes=={old[phase]}
 full.append(dict(phase=phase,count=len(times),mean_ms=statistics.mean(times),median_ms=statistics.median(times),proof_hash=next(iter(hashes))))
(root/'full-summary.json').write_text(json.dumps(full,indent=2)+'\n')
print('Full API proofs verified; initial/baseline fingerprints match the prior implementation.')
