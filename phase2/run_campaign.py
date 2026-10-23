"""Second-phase native campaigns with exact controls and retained failures."""
import argparse
import contextlib
import hashlib
import json
import os
import platform
import random
import stat
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phase2.measurement import Measurement, legacy
from phase2.oracle import ACTIONS, identities, transform, difference
from phase1.record_environment import inventory

STATES=(*ACTIONS,'filldir_hiding','getdents_substitution','independent')
OWN_MODULES=('phase2_transform','phase2_independent','kicba_d7_hiding','kicba_d9_getdents_substitute')


def save(path,data):
    with path.open('x',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=True,indent=2)


def emit(stream,data):
    data['recorded_at_ns']=time.monotonic_ns()
    stream.write(json.dumps(data,ensure_ascii=True)+'\n');stream.flush()


def module_paths():
    directory=ROOT/'phase2/bin'/platform.release()
    return {'filldir_hiding':directory/'kicba_d7_hiding.ko',
            'getdents_substitution':directory/'kicba_d9_getdents_substitute.ko',
            'independent':directory/'phase2_independent.ko'}


def loaded(): return {r.split()[0] for r in Path('/proc/modules').read_text().splitlines()}


def unload():
    for name in OWN_MODULES:
        if name in loaded(): subprocess.run(['rmmod',name],check=True,capture_output=True)


def load_state(state):
    if state=='normal': return
    if state in ACTIONS:
        subprocess.run(['insmod',str(ROOT/'phase2/bin'/platform.release()/'phase2_transform.ko'),
                        'mode='+str(ACTIONS.index(state))],check=True,capture_output=True)
    elif state=='independent':
        subprocess.run(['insmod',str(module_paths()[state])],check=True,capture_output=True)
    else: legacy._set_state(state,module_paths())


def counters(state):
    if state not in ACTIONS or state=='normal': return {}
    folder=Path('/sys/module/phase2_transform/parameters')
    return {key:int((folder/key).read_text()) for key in ('changed','skipped','errors')}


def make_fixture(path,count=64):
    path.mkdir()
    for i in range(count):
        (path/f'ordinary_{i:08d}').touch()
        if i==count//2:
            for name in ('phase2_subject','d8_hidden_0000','d9_swap_a_0000','boogaloo_one','普通檔名'):
                (path/name).touch()
    (path/'directory').mkdir()
    (path/'symlink').symlink_to('ordinary_00000000')
    os.mkfifo(path/'fifo')
    return path


def manifest(path):
    kinds={stat.S_IFREG:8,stat.S_IFDIR:4,stat.S_IFLNK:10,stat.S_IFIFO:1}
    rows=[]
    for name in ['.','..',*os.listdir(path)]:
        info=os.lstat(path/name)
        rows.append({'name_hex':os.fsencode(name).hex(),'inode':info.st_ino,'d_type':kinds[stat.S_IFMT(info.st_mode)]})
    return rows


def expected_output(original,state,mutation=True):
    if not mutation: return [dict(r) for r in original]
    if state in ACTIONS: return transform(original,state)
    if state in ('filldir_hiding','independent'):
        prefix=b'd8_hidden_' if state=='filldir_hiding' else b'boogaloo'
        return [dict(r) for r in original if not bytes.fromhex(r['name_hex']).startswith(prefix)]
    result=[dict(r) for r in original]
    for row in result:
        name=bytes.fromhex(row['name_hex'])
        if name.startswith(b'd9_swap_a_'): row['name_hex']=(b'd9_swap_b_'+name[len(b'd9_swap_a_'):]).hex()
    return result


@contextlib.contextmanager
def filesystem_roots(output):
    ext=output/'fixture_ext4';ext.mkdir()
    memory=output/'fixture_tmpfs';memory.mkdir()
    subprocess.run(['mount','-t','tmpfs','-o','size=256M,mode=0700','tmpfs',str(memory)],check=True)
    try:
        for path,expected in ((ext,'ext4'),(memory,'tmpfs')):
            actual=subprocess.check_output(['findmnt','-n','-o','FSTYPE','-T',str(path)],text=True).strip()
            if actual!=expected: raise RuntimeError('filesystem mismatch '+str(path)+': '+actual)
        yield {'ext4':ext,'tmpfs':memory}
    finally: subprocess.run(['umount',str(memory)],check=True)


def run_static(output,stream,roots,repeats):
    ordinal=0
    tools={name:Measurement(name,attach=False) for name in ('legacy','packed','parse')}
    try:
        for fs,base in roots.items():
            fixture=make_fixture(base/'static')
            original=manifest(fixture);save(output/('oracle_'+fs+'.json'),original)
            for state in STATES:
                for buffer in (256,65536):
                    variants=[('parse','none'),('legacy','module_first'),('packed','module_first')]
                    if state=='independent': variants.extend([('legacy','probe_first'),('packed','probe_first')])
                    for implementation,order in variants:
                        tool=tools[implementation]
                        unload()
                        try:
                            if order=='probe_first': tool.attach()
                            load_state(state)
                            if order!='probe_first': tool.attach()
                            for repetition in range(1 if implementation=='parse' else repeats):
                                ordinal+=1;dump=output/f'actual_static_{ordinal:06d}.jsonl'
                                before=counters(state)
                                row=tool.scan(fixture,buffer,dump=dump)
                                after=counters(state)
                                audit={k:after[k]-before[k] for k in before}
                                actual=[json.loads(s) for s in dump.read_text().splitlines()] if dump.exists() else []
                                mutation=(state=='normal' or state not in ACTIONS or audit.get('changed',0)>0)
                                expected=expected_output(original,state,mutation)
                                up,down=difference(original,expected)
                                row.update(kind='static',fs=fs,state=state,buffer=buffer,implementation=implementation,
                                           order=order,repetition=repetition,audit=audit,mutation_exercised=mutation,
                                           output_match=identities(actual)==identities(expected),
                                           expected_difference=bool(up or down),expected_upstream=up,expected_downstream=down,
                                           actual_file=dump.name)
                                if implementation!='parse':
                                    row['verdict_match']=row['verdict']==('different' if up or down else 'equal')
                                    row['recovery_match']=(row.get('decode_success') is True
                                        and sorted(row.get('upstream_only',[]))==up and sorted(row.get('downstream_only',[]))==down)
                                emit(stream,row)
                        except Exception as error:
                            emit(stream,{'kind':'case_failure','fs':fs,'state':state,'buffer':buffer,
                                         'implementation':implementation,'order':order,'error':repr(error)})
                            raise
                        finally: tool.detach();unload()
    finally:
        for tool in tools.values(): tool.close()


def run_dynamic(output,stream,roots,repeats):
    ordinal=0
    for fs,base in roots.items():
        fixture=make_fixture(base/'dynamic',512)
        events=[];stop=threading.Event();errors=[]
        def churn():
            i=0
            try:
                while not stop.is_set():
                    a,b=fixture/f'churn_a_{i%128:03d}',fixture/f'churn_b_{i%128:03d}'
                    a.touch();events.append((time.monotonic_ns(),'create'))
                    a.replace(b);events.append((time.monotonic_ns(),'rename'))
                    b.unlink();events.append((time.monotonic_ns(),'delete'));i+=1
            except Exception as error: errors.append(repr(error))
        worker=threading.Thread(target=churn);worker.start()
        try:
            for implementation in ('legacy','packed'):
                with Measurement(implementation,probe=ROOT/'phase2/bin/enum_dynamic') as tool:
                    for buffer in (256,65536):
                        for repetition in range(repeats):
                            ordinal+=1;dump=output/f'actual_dynamic_{ordinal:05d}.jsonl'
                            row=tool.scan(fixture,buffer,dump=dump)
                            visible=row.get('userspace',{})
                            start,end=visible.get('scan_started_ns',0),visible.get('scan_finished_ns',0)
                            overlap=Counter(op for timestamp,op in events if start<=timestamp<=end)
                            row.update(kind='dynamic',fs=fs,implementation=implementation,buffer=buffer,repetition=repetition,
                                       churn_in_scan=dict(overlap),churn_exercised=all(overlap[op]>0 for op in ('create','rename','delete')),
                                       worker_errors=list(errors),actual_file=dump.name)
                            emit(stream,row)
        finally:
            stop.set();worker.join(timeout=10)
            save(output/('churn_events_'+fs+'.json'),{'events':events,'errors':errors,'worker_stopped':not worker.is_alive()})


def run_cost(output,stream,repeats,seed):
    tools={name:Measurement(name,attach=False) for name in ('parse','legacy','packed')}
    rng=random.Random(seed)
    try:
        for count in (512,8192,65536):
            fixture=legacy.make_simple_fixture(output/('fixture_cost_'+str(count)),count)
            for condition in ('baseline','cpu'):
                stress=None
                try:
                    if condition=='cpu':
                        stress=subprocess.Popen(['stress-ng','--cpu','2','--quiet'],stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL,start_new_session=True)
                        time.sleep(0.5)
                    for block in range(repeats+2):
                        order=list(tools);rng.shuffle(order)
                        for implementation in order:
                            tool=tools[implementation]
                            try:
                                attach_ns=tool.attach()
                                row=tool.scan(fixture)
                                row.update(kind='cost',cardinality=count,condition=condition,implementation=implementation,
                                           block=block-2,warmup=block<2,order=order,attach_ns=attach_ns,
                                           count_match=row.get('userspace',{}).get('count')==count+2,
                                           load_active=stress is None or stress.poll() is None,guest_load=os.getloadavg())
                                emit(stream,row)
                            finally: tool.detach()
                finally: legacy.stop_stress(stress)
    finally:
        for tool in tools.values(): tool.close()


def map_audit(output):
    result={}
    for implementation in ('legacy','packed'):
        with Measurement(implementation,attach=False) as tool:
            names=(['state_by_pid'] if implementation=='packed' else ['monitored_pids','collection_enabled',
                'hash_seeds','iblt_cell_count','depth_by_pid','pending_by_pid','kernel_fingerprints','kernel_iblt','stats_by_pid'])
            result[implementation]={}
            for name in names:
                raw=Path(f'/proc/self/fdinfo/{tool.bpf[name].map_fd}').read_text()
                fields={k:v.strip() for k,v in (s.split(':',1) for s in raw.splitlines() if ':' in s)}
                result[implementation][name]={'raw_fdinfo':raw,'fields':fields}
    save(output/'map_memory.json',result)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--role',choices=('pilot','confirmation'),required=True)
    parser.add_argument('--seed',type=int,default=2202301);args=parser.parse_args()
    if os.geteuid()!=0 or ROOT!=Path('/home/kicba/research_phase2_20261023'):
        raise RuntimeError('protected native guest root required')
    for family in ([],['-6']):
        if subprocess.check_output(['ip',*family,'route','show','default'],text=True).strip():
            raise RuntimeError('default route present')
    legacy.runtime()
    if loaded() & (set(OWN_MODULES)|legacy.KNOWN_MODULES):
        raise RuntimeError('another research module is already loaded')
    checkpoint=json.loads((ROOT/'phase2/host/evidence/checkpoint.json').read_text(encoding='utf-8-sig'))
    if not checkpoint['success']: raise RuntimeError('checkpoint missing')
    if args.role=='confirmation':
        lock=json.loads((ROOT/'phase2/CONFIRMATION_LOCK.json').read_text())
        for name,digest in lock['source_sha256'].items():
            if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest: raise RuntimeError('source drift '+name)
    output=args.output.resolve()
    if ROOT not in output.parents: raise ValueError('output outside version directory')
    output.mkdir(parents=True,exist_ok=False)
    before=inventory();save(output/'environment_before.json',before)
    sources={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (ROOT/'phase2').rglob('*') if p.is_file() and p.suffix in ('.py','.c','.h','.ko')
             and not any(x in p.parts for x in ('evidence','downloads','__pycache__'))}
    save(output/'manifest.json',{'role':args.role,'seed':args.seed,'protocol_sha256':hashlib.sha256(
        (ROOT/'phase2/PROTOCOL_zh-TW.md').read_bytes()).hexdigest(),'source_sha256':sources,
        'boot_id':before['boot_id'],'kernel':before['kernel']})
    units=['apt-daily.timer','apt-daily-upgrade.timer','apt-daily.service','apt-daily-upgrade.service']
    started=time.monotonic();completed=False
    try:
        subprocess.run(['systemctl','stop',*units[:2]],check=True,capture_output=True)
        subprocess.run(['systemctl','mask','--runtime',*units],check=True,capture_output=True)
        for service in units[2:]:
            if subprocess.run(['systemctl','is-active','--quiet',service]).returncode==0:
                raise RuntimeError('package operation already active')
        legacy.runtime()
        with (output/'attempts.jsonl').open('x') as stream:
            try:
                with filesystem_roots(output) as roots:
                    run_static(output,stream,roots,1 if args.role=='pilot' else 10)
                    run_dynamic(output,stream,roots,2 if args.role=='pilot' else 10)
                run_cost(output,stream,3 if args.role=='pilot' else 10,args.seed)
                map_audit(output);completed=True
            except BaseException as error:
                emit(stream,{'kind':'suite_failure','error':repr(error)});raise
    finally:
        unload()
        subprocess.run(['systemctl','unmask','--runtime',*units],check=True,capture_output=True)
        for unit in units[:2]:
            if 'ActiveState=active' in before['update_units'][unit]['stdout']:
                subprocess.run(['systemctl','start',unit],check=True,capture_output=True)
        after=inventory();save(output/'environment_after.json',after)
        save(output/'completion.json',{'completed':completed,'elapsed_seconds':time.monotonic()-started,
             'environment_unchanged':before['kernel']==after['kernel'] and before['package_inventory_sha256']==after['package_inventory_sha256'],
             'timers_restored':before['update_units']==after['update_units']})
    print(json.dumps({'completed':completed,'output':str(output)}),flush=True)


if __name__=='__main__': main()
