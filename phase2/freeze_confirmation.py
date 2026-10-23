"""Freeze common runtime sources plus binaries for exactly the active kernel."""
import argparse
import hashlib
import json
import os
import sys
import tarfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phase1.record_environment import inventory
from phase2.run_campaign import save


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--environment',choices=('kernel68','kernel65'),required=True);args=parser.parse_args()
    if ROOT!=Path('/home/kicba/research_phase2_20261023') or os.geteuid()!=0: raise RuntimeError('protected guest root required')
    before=inventory();expected={'kernel68':'6.8.0-138-generic','kernel65':'6.5.0-45-generic'}
    if before['kernel']!=expected[args.environment]: raise RuntimeError('wrong active kernel')
    sources=[*ROOT.glob('phase2/*.py'),*ROOT.glob('phase2/tests/*.py'),*ROOT.glob('phase2/*.c'),ROOT/'phase2/name_hash.h',ROOT/'phase2/PROTOCOL_zh-TW.md',
             *ROOT.glob('phase2/module/*'),*ROOT.glob('phase2/third_party/xcellerator/ported/*'),
             *ROOT.glob('phase1/*.py'),ROOT/'phase1/bpf_measurement.c',ROOT/'phase1/enum_probe.c',ROOT/'phase1/bin/d9_enum_probe',
             ROOT/'phase2/bin/enum_dynamic',*ROOT.glob('phase2/bin/'+before['kernel']+'/*.ko'),
             *ROOT.glob('collector/*.py'),ROOT/'collector/d9_reconciliation_hash.h',*ROOT.glob('src/kicba/*.py')]
    sources=sorted(set(p for p in sources if p.is_file() and (p.suffix in ('.py','.c','.h','.ko','.md') or p.name in ('d9_enum_probe','enum_dynamic','Makefile'))
                       and not p.name.endswith('.mod.c')))
    lock={'environment_tag':args.environment,'kernel':before['kernel'],
          'package_inventory_sha256':before['package_inventory_sha256'],'development_boot_ids':[before['boot_id']],
          'source_sha256':{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}}
    save(ROOT/'phase2/CONFIRMATION_LOCK.json',lock)
    archive=ROOT/f'phase2/frozen_sources_{args.environment}.tar.gz'
    with tarfile.open(archive,'x:gz') as bundle:
        for p in sources:bundle.add(p,arcname=p.relative_to(ROOT).as_posix(),recursive=False)
        bundle.add(ROOT/'phase2/CONFIRMATION_LOCK.json',arcname='phase2/CONFIRMATION_LOCK.json')
    save(archive.with_suffix(archive.suffix+'.sha256.json'),{'filename':archive.name,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()})
    print(json.dumps({'environment':args.environment,'frozen_inputs':len(sources),'archive':archive.name}),flush=True)
