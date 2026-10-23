"""One frozen second-phase confirmation campaign on a genuinely new boot."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phase1.record_environment import inventory
from phase2.summary import summarize
from phase2.run_campaign import save


def verify_sources(lock):
    for name,digest in lock['source_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError('frozen input drift '+name)


def criteria(result,rows):
    q,c=result['quality'],result['cost']
    expected={'static_measured':960,'static_controls':44,'dynamic':80}
    checks={key:q[key]==value for key,value in expected.items()}
    for key in ('invalid','output_mismatch','wrong_valid_verdict','incorrect_decode_success','decode_failed',
                'dynamic_invalid','dynamic_difference','dynamic_not_exercised','case_failures'):
        checks[key]=q[key]==0
    checks['cost_counts']=c['attempts']==216 and c['primary']==180 and c['warmups']==36 and c['invalid_primary']==0
    checks['paired_costs']=len(c['paired'])==6 and all(r['paired_blocks']==10 and r['incomplete_or_invalid_blocks']==0 for r in c['paired'].values())
    checks['no_transform_errors']=all(not r.get('audit',{}).get('errors') for r in rows)
    for fs in ('ext4','tmpfs'):
        for implementation in ('legacy','packed'):
            for state in ('insert','grow','shrink','inode','type','remove','filldir_hiding','getdents_substitution','independent'):
                selected=[r for r in rows if r['kind']=='static' and r['fs']==fs and r['implementation']==implementation
                          and r['state']==state and r['buffer']==65536 and r['order']=='module_first']
                checks[f'positive/{fs}/{implementation}/{state}']=(len(selected)==10 and all(r['mutation_exercised'] and r['verdict']=='different' for r in selected))
    return checks


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--environment',choices=('kernel68','kernel65'),required=True)
    parser.add_argument('--boot-index',type=int,choices=(1,2,3),required=True);args=parser.parse_args()
    if ROOT!=Path('/home/kicba/research_phase2_20261023') or os.geteuid()!=0:
        raise RuntimeError('protected guest root required')
    lock=json.loads((ROOT/'phase2/CONFIRMATION_LOCK.json').read_text());verify_sources(lock)
    before=inventory()
    if args.environment!=lock['environment_tag'] or before['kernel']!=lock['kernel'] or before['package_inventory_sha256']!=lock['package_inventory_sha256']:
        raise RuntimeError('environment differs from lock')
    if before['boot_id'] in lock['development_boot_ids']: raise RuntimeError('confirmation reuses a development boot')
    parent=ROOT/'phase2/evidence'/args.environment
    for path in parent.glob('confirmation_boot_*/environment_before.json'):
        if json.loads(path.read_text())['boot_id']==before['boot_id']: raise RuntimeError('duplicate confirmation boot ID')
    output=parent/f'confirmation_boot_{args.boot_index:02d}';output.mkdir(parents=True,exist_ok=False)
    save(output/'environment_before.json',before)
    result={'environment_tag':args.environment,'boot_index':args.boot_index,'boot_id':before['boot_id'],'completed':False}
    try:
        with (output/'campaign.log').open('x') as log:
            subprocess.run([sys.executable,str(ROOT/'phase2/run_campaign.py'),'--role','confirmation',
                            '--seed',str(2202301+args.boot_index),'--output',str(output/'campaign')],
                           check=True,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        rows=[json.loads(s) for s in (output/'campaign/attempts.jsonl').read_text().splitlines()]
        result.update(summarize(rows));result['criteria']=criteria(result,rows)
        completion=json.loads((output/'campaign/completion.json').read_text())
        result['campaign_completion']=completion
        result['criteria']['environment_and_timers']=all(completion[k] is True for k in ('completed','environment_unchanged','timers_restored'))
        verify_sources(lock)
        result['completed']=all(result['criteria'].values())
    except BaseException as error:
        result['error']=repr(error)
        raise
    finally:
        save(output/'summary.json',result)
        archive=ROOT/f'phase2/confirmation_{args.environment}_boot_{args.boot_index:02d}.tar.gz'
        with tarfile.open(archive,'x:gz') as bundle:
            for path in output.rglob('*'):
                if path.is_file() and path.suffix in ('.json','.jsonl','.log','.txt'):
                    bundle.add(path,arcname=path.relative_to(ROOT).as_posix(),recursive=False)
        save(archive.with_suffix(archive.suffix+'.sha256.json'),{'filename':archive.name,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()})
    print(json.dumps({'environment':args.environment,'boot_index':args.boot_index,'boot_id':before['boot_id'],
                     'completed':result['completed'],'failed_criteria':[k for k,v in result['criteria'].items() if not v]}),flush=True)
    if not result['completed']: raise RuntimeError('retained confirmation failed quality criteria')
