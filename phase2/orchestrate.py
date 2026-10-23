"""Host coordinator: three fresh boots on one already-selected lab VM."""
import argparse
import hashlib
import json
import subprocess
import tarfile
import time
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
HOST=ROOT/'phase2/host/evidence'
GUEST='/home/kicba/research_phase2_20261023'
SSH=['C:/Windows/System32/OpenSSH/ssh.exe','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
     '-o','UserKnownHostsFile=D:/KICBA-Lab/ssh/known_hosts','-o','ConnectTimeout=5','-o','LogLevel=ERROR',
     '-i','D:/KICBA-Lab/ssh/kicba_ed25519','kicba@192.168.77.2']
SCP=['C:/Windows/System32/OpenSSH/scp.exe','-q',*SSH[1:-1]]


def remote(command,**kwargs): return subprocess.run([*SSH,command],**kwargs)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--environment',choices=('kernel68','kernel65'),required=True)
    args=parser.parse_args();tag=args.environment
    expected={'kernel68':'6.8.0-138-generic','kernel65':'6.5.0-45-generic'}[tag]
    if remote('uname -r',capture_output=True,text=True,check=True).stdout.strip()!=expected:
        raise RuntimeError('wrong VM/kernel selected')
    events_path=HOST/(tag+'_orchestration.jsonl')
    with events_path.open('x') as log:
        def event(kind,**values):
            row={'recorded_at':datetime.now(timezone.utc).isoformat(),'kind':kind,'environment':tag,**values}
            text=json.dumps(row);log.write(text+'\n');log.flush();print(text,flush=True)
        for index in (1,2,3):
            before=remote('cat /proc/sys/kernel/random/boot_id',capture_output=True,text=True,check=True).stdout.strip()
            stop=HOST/f'{tag}_boot_{index:02d}.stop'
            samples=HOST/f'{tag}_boot_{index:02d}_samples.jsonl'
            if stop.exists() or samples.exists():raise FileExistsError('host sample attempt already exists')
            sampler=subprocess.Popen(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',
                str(ROOT/'phase1/host/sample_host.ps1'),'-OutputPath',str(samples),'-StopFile',str(stop)],
                creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                event('reboot_requested',boot_index=index,previous_boot_id=before)
                remote('sudo -n reboot',capture_output=True,text=True,timeout=15)
                deadline=time.monotonic()+240;fresh=None
                while time.monotonic()<deadline:
                    time.sleep(3)
                    probe=remote('cat /proc/sys/kernel/random/boot_id',capture_output=True,text=True)
                    if probe.returncode==0 and probe.stdout.strip() and probe.stdout.strip()!=before:
                        fresh=probe.stdout.strip();break
                if fresh is None: raise RuntimeError('fresh boot unavailable')
                event('confirmation_started',boot_index=index,boot_id=fresh)
                result=remote(f'sudo -n env PYTHONDONTWRITEBYTECODE=1 python3 {GUEST}/phase2/run_confirmation.py --environment {tag} --boot-index {index}',
                              capture_output=True,text=True)
                (HOST/f'{tag}_boot_{index:02d}_ssh.txt').write_text(result.stdout+result.stderr,encoding='utf-8')
                name=f'confirmation_{tag}_boot_{index:02d}.tar.gz'
                directory=ROOT/'phase2/evidence/downloads'
                archive=directory/name;metadata=directory/(name+'.sha256.json')
                if archive.exists() or metadata.exists():raise FileExistsError('archive download exists')
                for filename in (name,name+'.sha256.json'):
                    subprocess.run([*SCP,f'kicba@192.168.77.2:{GUEST}/phase2/{filename}',str(directory/filename)],check=True)
                expected_digest=json.loads(metadata.read_text())['sha256']
                if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected_digest:raise RuntimeError('download checksum mismatch')
                with tarfile.open(archive) as bundle:bundle.extractall(ROOT,filter='data')
                summary=json.loads((ROOT/f'phase2/evidence/{tag}/confirmation_boot_{index:02d}/summary.json').read_text())
                event('confirmation_finished',boot_index=index,boot_id=fresh,returncode=result.returncode,
                      completed=summary.get('completed'),quality=summary.get('quality'),
                      paired_cost=summary.get('cost',{}).get('paired',{}).get('65536/baseline'))
                if result.returncode or summary.get('completed') is not True:
                    raise RuntimeError('retained confirmation failed; do not replace it')
            finally:
                stop.touch(exist_ok=False)
                try:sampler.wait(timeout=10)
                except subprocess.TimeoutExpired:event('sampler_stopping',boot_index=index)
        event('three_boots_complete')
