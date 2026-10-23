"""Retain every final native fault/control row outside disposable fixtures."""
import hashlib
import json
import os
import platform
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def retain(test,row,label='result'):
    attempt=os.environ.get('PHASE2_TEST_ATTEMPT','final_attempt1')
    if not attempt.replace('_','').isalnum():raise ValueError('invalid test attempt')
    directory=ROOT/'phase2/evidence/native_checks'/platform.release()/attempt
    directory.mkdir(parents=True,exist_ok=True)
    path=directory/(test._testMethodName+'_'+str(label)+'.json')
    record={'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'test_source_sha256':hashlib.sha256(Path(test.__class__.__module__.replace('.','/')+'.py').read_bytes()).hexdigest(),
            'row':row}
    with path.open('x') as stream:json.dump(record,stream,indent=2)
