"""Run via stdin on the original guest after all confirmations; retain final state."""
import hashlib
import json
import os
import sys
import tarfile
from pathlib import Path

ROOT=Path('/home/kicba/research_phase2_20261023')
if os.geteuid()!=0 or not ROOT.is_dir():raise RuntimeError('protected guest required')
sys.path.insert(0,str(ROOT))
from phase1.record_environment import inventory

lock=json.loads((ROOT/'phase2/CONFIRMATION_LOCK.json').read_text())
if lock['environment_tag']!='kernel68':raise RuntimeError('original VM required')
for index in (1,2,3):
    completed=json.loads((ROOT/f'phase2/evidence/kernel68/confirmation_boot_{index:02d}/summary.json').read_text())
    if completed['completed'] is not True:raise RuntimeError('confirmation not complete')
current=inventory()
drift=[name for name,digest in lock['source_sha256'].items()
       if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest]
modules=[line for line in current['modules']['stdout'].splitlines()
         if line.startswith(('phase2_','d9_','caraxes_'))]
probes=Path('/sys/kernel/tracing/kprobe_events').read_text()
macs=[path.read_text().strip().lower() for path in Path('/sys/class/net').glob('*/address')]
before=json.loads((ROOT/'phase2/evidence/kernel68/pilot_attempt1/environment_before.json').read_text())
checks={'original_vm_mac':'00:15:5d:70:aa:02' in macs and '00:15:5d:70:aa:03' not in macs,
        'original_kernel':current['kernel']=='6.8.0-138-generic',
        'packages_unchanged':current['package_inventory_sha256']==lock['package_inventory_sha256']==before['package_inventory_sha256'],
        'timers_restored':current['update_units']==before['update_units'],
        'frozen_sources_unchanged':not drift,'test_modules_removed':not modules,'tracefs_probes_removed':not probes.strip(),
        'isolated_routes':all(not line.startswith('default ') for key in ('routes4','routes6') for line in current[key]['stdout'].splitlines())}
record={'inventory':current,'source_drift':drift,'test_modules':modules,'tracefs_probes':probes,'macs':macs,'checks':checks}
final=ROOT/'phase2/evidence/kernel68/final_environment.json'
with final.open('x') as stream:json.dump(record,stream,indent=2)
archive=ROOT/'phase2/development_kernel68.tar.gz'
paths=[final,*ROOT.glob('phase2/evidence/native_checks/6.8.0-138-generic/final_attempt1/*.json')]
if len(paths)!=19:raise RuntimeError('native evidence count differs')
with tarfile.open(archive,'x:gz') as bundle:
    for path in sorted(paths):bundle.add(path,arcname=path.relative_to(ROOT).as_posix(),recursive=False)
metadata={'filename':archive.name,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}
with archive.with_suffix(archive.suffix+'.sha256.json').open('x') as stream:json.dump(metadata,stream,indent=2)
print(json.dumps({'checks':checks,'native_records':len(paths)-1,'archive':metadata}))
if not all(checks.values()):raise RuntimeError('retained final verification failure')
