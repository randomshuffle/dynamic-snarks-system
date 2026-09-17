"""Run matched binaries sequentially; compilation and all other tests finish first."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

root = Path(__file__).resolve().parent
binaries = {name: Path(f'/tmp/parallel-provers-{name}/prover_comparison') for name in ('before', 'after')}
metadata_path = root/'run.json'
metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else dict(
    gates=65536, samples=5, warmups_per_path=1, features=['parallel'],
    binary_sha256={name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}, runs=[])
assert metadata['binary_sha256'] == {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
for mode, workers in [('before', 8), ('after', 8), ('before', 1), ('after', 1)]:
    if any(r['mode'] == mode and r['workers'] == workers and (r.get('exit_code') == 0 or r.get('complete_verified_records') == 11) for r in metadata['runs']):
        continue
    env = dict(os.environ)
    env.pop('DYNAMIC_SNARK_PROFILE_DETAIL', None)
    env.update(RAYON_NUM_THREADS=str(workers), DYNAMIC_SNARK_TRACE_LOG='16', DYNAMIC_SNARK_FIRST_SAMPLES='5', DYNAMIC_SNARK_PROFILE='1')
    print(f'Starting {mode}, {workers} workers', flush=True)
    start = time.time()
    record = dict(mode=mode, workers=workers, started_unix=start)
    metadata['runs'].append(record)
    (root/'run.json').write_text(json.dumps(metadata, indent=2)+'\n')
    with (root/f'{mode}-{workers}.csv').open('w') as stdout, (root/f'{mode}-{workers}.log').open('w') as stderr:
        process = subprocess.run([str(binaries[mode])], env=env, stdout=stdout, stderr=stderr)
    record.update(exit_code=process.returncode, elapsed_seconds=time.time()-start)
    (root/'run.json').write_text(json.dumps(metadata, indent=2)+'\n')
    print(f'Finished {mode}, {workers} workers in {record["elapsed_seconds"]:.1f}s, exit {process.returncode}', flush=True)
    process.check_returncode()
