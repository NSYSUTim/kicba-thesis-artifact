"""Build only new-version outputs, retaining original collector and module bytes."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

if __name__=='__main__':
    if ROOT!=Path('/home/kicba/research_phase2_20261023') or os.geteuid()!=0:
        raise RuntimeError('protected guest root required')
    kernel=platform.release();output=ROOT/'phase2/bin'/kernel;output.mkdir(parents=True,exist_ok=True)
    source=(ROOT/'phase1/enum_probe.c').read_text()
    source=source.replace('returned_bytes += (uint64_t)result;',
                          'returned_bytes += (uint64_t)result;\n        usleep(1000); /* dynamic scheduling stress only */')
    before='    printf("{\\"schema_version\\":1'
    after=('    printf("{\\"scan_started_ns\\":%llu,\\"scan_finished_ns\\":%llu,",\n'
           '           (unsigned long long)started.tv_sec * 1000000000ULL + started.tv_nsec,\n'
           '           (unsigned long long)finished.tv_sec * 1000000000ULL + finished.tv_nsec);\n'
           '    printf("\\"schema_version\\":1')
    if before not in source: raise RuntimeError('dynamic scanner source anchor changed')
    source=source.replace(before,after)
    dynamic=ROOT/'phase2/enum_dynamic.c'
    if dynamic.exists() and dynamic.read_text()!=source: raise RuntimeError('dynamic scanner source drift')
    if not dynamic.exists(): dynamic.write_text(source)
    subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror',str(dynamic),'-o',str(ROOT/'phase2/bin/enum_dynamic')],check=True)
    for folder in (ROOT/'phase2/module',ROOT/'phase2/third_party/xcellerator/ported'):
        subprocess.run(['make','-C','/lib/modules/'+kernel+'/build','M='+str(folder),'CC=gcc-12','modules'],check=True)
        for file in folder.glob('*.ko'): shutil.copy2(file,output/file.name)
    build=ROOT/'phase2/build_legacy'/kernel
    for name in ('d7_controls_r2','d9_getdents_substitute'):
        destination=build/name
        shutil.copytree(ROOT/'attack_variants'/name,destination,dirs_exist_ok=True)
        subprocess.run(['make','-C','/lib/modules/'+kernel+'/build','M='+str(destination),'CC=gcc-12','modules'],check=True)
        for file in destination.glob('*.ko'): shutil.copy2(file,output/file.name)
    print('BUILT',kernel,flush=True)
