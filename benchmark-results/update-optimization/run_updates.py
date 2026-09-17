"""Matched first-update runs using frozen binaries, with no concurrent work."""
from pathlib import Path
import hashlib,json,os,subprocess,time
out=Path(__file__).resolve().parent
binaries={'before':Path('/tmp/update-first-before'),'after':Path('/tmp/update-first-after'),'profile':Path('/tmp/update-first-profile-after'),'full':Path('/tmp/update-full-after')}
runs=[]
configs=[]
for block in range(3):
    for mode in (['before','after'] if block%2==0 else ['after','before']):
        configs.append((f'{mode}8-{block}',mode,8,False,31))
configs.extend([(f'{mode}1-0',mode,1,False,31) for mode in ['before','after']])
configs.extend([('after-profile-control','profile',8,False,31),('after-profile-detail','profile',8,True,31),('full-after','full',8,False,5)])
for label,mode,workers,detail,samples in configs:
    binary=binaries[mode]
    env=dict(os.environ,RAYON_NUM_THREADS=str(workers),DYNAMIC_SNARK_TRACE_LOG='16',DYNAMIC_SNARK_FIRST_KIND='leaf',DYNAMIC_SNARK_FIRST_SAMPLES=str(samples),DYNAMIC_SNARK_PROFILE='1')
    env.pop('DYNAMIC_SNARK_PROFILE_DETAIL',None)
    if detail:env['DYNAMIC_SNARK_PROFILE_DETAIL']='1'
    record=dict(label=label,mode=mode,workers=workers,samples=samples,detail=detail,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),started_unix=time.time())
    print('Starting',label,flush=True)
    with (out/f'{label}.csv').open('w') as stdout,(out/f'{label}.log').open('w') as stderr:
        p=subprocess.run([str(binary)],env=env,stdout=stdout,stderr=stderr)
    record.update(exit_code=p.returncode,elapsed_seconds=time.time()-record['started_unix'])
    runs.append(record);(out/'run.json').write_text(json.dumps(runs,indent=2)+'\n')
    print('Finished',label,round(record['elapsed_seconds'],2),'s',flush=True)
    p.check_returncode()
