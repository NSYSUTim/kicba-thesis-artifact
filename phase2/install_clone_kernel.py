"""Install only the pinned offline kernel on the distinguishable lab clone."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phase1.record_environment import inventory


if __name__=='__main__':
    if ROOT!=Path('/home/kicba/research_phase2_20261023') or os.geteuid()!=0:
        raise RuntimeError('protected guest root required')
    addresses=[p.read_text().strip().lower() for p in Path('/sys/class/net').glob('*/address')]
    if '00:15:5d:70:aa:02' in addresses: raise RuntimeError('refusing to install on original VM MAC')
    if '6.8.0-138-generic'!=os.uname().release: raise RuntimeError('unexpected initial clone kernel')
    output=ROOT/'phase2/evidence/clone_kernel_install';output.mkdir(parents=True,exist_ok=False)
    before=inventory()
    (output/'environment_before.json').write_text(json.dumps(before,indent=2))
    data=json.loads((ROOT/'phase2/downloads/kernel_packages.json').read_text())
    paths=[]
    for row in data['packages']:
        path=ROOT/'phase2/downloads'/row['filename']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']: raise RuntimeError('package checksum mismatch')
        paths.append(str(path))
    units=['apt-daily.timer','apt-daily-upgrade.timer','apt-daily.service','apt-daily-upgrade.service']
    try:
        subprocess.run(['systemctl','stop',*units[:2]],check=True)
        subprocess.run(['systemctl','mask','--runtime',*units],check=True)
        for unit in units[2:]:
            if subprocess.run(['systemctl','is-active','--quiet',unit]).returncode==0: raise RuntimeError('package operation active')
        subprocess.run(['dpkg','-i',*paths],check=True)
        config=Path('/etc/default/grub.d/99-phase2-kernel.cfg')
        with config.open('x') as f:
            f.write('GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 6.5.0-45-generic"\n')
        subprocess.run(['update-grub'],check=True)
        if 'Ubuntu, with Linux 6.5.0-45-generic' not in Path('/boot/grub/grub.cfg').read_text():
            raise RuntimeError('expected kernel menu entry not found')
    finally:
        subprocess.run(['systemctl','unmask','--runtime',*units],check=True)
        for unit in units[:2]:
            if 'ActiveState=active' in before['update_units'][unit]['stdout']: subprocess.run(['systemctl','start',unit],check=True)
        after=inventory()
        (output/'environment_after_install.json').write_text(json.dumps(after,indent=2))
    print('CLONE_KERNEL_INSTALLED; reboot explicitly after retaining logs',flush=True)
