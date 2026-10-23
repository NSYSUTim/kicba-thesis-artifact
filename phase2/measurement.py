"""Same scanner, fingerprint and return-probe window, two storage layouts."""

import ctypes as ct
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, ROOT/'src', ROOT/'collector'):
    sys.path.insert(0,str(directory))
from phase1 import run_experiments as legacy
from phase1.coverage import combine_verdict
from phase2.oracle import SEED1, SEED2
from kicba.reconciliation import IBLT


class Measurement:
    def __init__(self, implementation, cells=256, maxactive=256, attach=True, probe=None):
        if implementation not in ('legacy','packed','parse'):
            raise ValueError('unknown implementation')
        if cells < 4 or cells > 256 or cells & (cells-1):
            raise ValueError('invalid capacity')
        if implementation=='legacy' and cells!=256:
            raise ValueError('frozen legacy diagnostic requires 256 cells')
        legacy.runtime()
        self.implementation,self.cells,self.maxactive=implementation,cells,maxactive
        self.probe=Path(probe) if probe else ROOT/'phase1/bin/d9_enum_probe'
        self.bpf=None
        self.attached=False
        self.registration={}
        if implementation=='legacy':
            self.bpf=legacy.new_bpf(4)
        elif implementation=='packed':
            self.bpf=legacy.BPF(src_file=str(ROOT/'phase2/bpf_packed.c'),cflags=[
                '-I'+str(ROOT/'phase2'),'-I'+str(ROOT/'collector'),'-Wno-macro-redefined'])
        if attach: self.attach()

    @staticmethod
    def key(pid): return ct.c_uint(pid)

    def attach(self):
        started=time.monotonic_ns()
        if self.attached: raise RuntimeError('already attached')
        if self.implementation=='legacy':
            legacy.attach(self.bpf,self.maxactive)
            legacy._set_array(self.bpf['iblt_cell_count'],0,ct.c_uint(self.cells))
        elif self.implementation=='packed':
            self.bpf.attach_kprobe(event='filldir64',fn_name='packed_enter')
            try:
                self.bpf.attach_kretprobe(event='filldir64',fn_name='packed_return',maxactive=self.maxactive)
            except Exception:
                self.bpf.detach_kprobe(event='filldir64')
                raise
        self.attached=True
        return time.monotonic_ns()-started

    def detach(self):
        if self.attached and self.bpf is not None: legacy.detach(self.bpf)
        self.attached=False

    def begin(self,directory,buffer,dump=None,user_mode=None):
        started=time.monotonic_ns()
        if user_mode is None: user_mode=0 if self.implementation=='parse' else 2
        command=[str(self.probe),str(directory),str(buffer),str(self.cells),
                 str(SEED1),str(SEED2),str(user_mode)]
        if dump is not None: command.append(str(dump))
        process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            if self.implementation=='legacy':
                self.bpf['monitored_pids'][self.key(process.pid)]=ct.c_ubyte(1)
            if self.implementation=='packed':
                table=self.bpf['state_by_pid'];state=table.Leaf()
                state.seed1,state.seed2=SEED1,SEED2
                state.cell_count,state.enabled=self.cells,1
                table[self.key(process.pid)]=state
            self.registration[process.pid]=time.monotonic_ns()-started
        except BaseException:
            process.kill();process.communicate()
            raise
        return process

    def _packed_telemetry(self,pid):
        state=self.bpf['state_by_pid'].get(self.key(pid))
        if state is None: return {'measurement_valid':False,'invalid_reason':'missing_state'}
        stats={field:int(getattr(state.stats,field)) for field in (*legacy.ERROR_FIELDS,
                   'outer_entries','accepted_entries','rejected_entries','name_read_checksum')}
        fp=[int(state.fp.count),int(state.fp.sum1),int(state.fp.sum2)]
        valid=(state.enabled==1 and state.seed1==SEED1 and state.seed2==SEED2
               and state.cell_count==self.cells and state.depth==0 and state.pending_valid==0
               and all(stats[field]==0 for field in legacy.ERROR_FIELDS)
               and stats['outer_entries']>0 and stats['accepted_entries']==fp[0]
               and stats['outer_entries']==stats['accepted_entries']+stats['rejected_entries'])
        rows=[[int(c.count),int(c.key_xor),int(c.inode_xor),int(c.type_xor),int(c.check_xor)]
              for c in state.cells[:self.cells]]
        return {'measurement_valid':bool(valid),'kernel_stats':stats,'kernel_fingerprint':fp,
                'kernel_rows':rows,'depth':int(state.depth),'pending_valid':int(state.pending_valid),
                'configuration':[int(state.seed1),int(state.seed2),int(state.cell_count),int(state.enabled)]}

    def finish(self,process):
        if self.implementation!='packed':
            # The legacy diagnostic supports 256 cells; other sizes are for packed-only fault checks.
            row=legacy.finish_probe(process,self.bpf,4 if self.bpf is not None else None,
                                     readback=self.bpf is not None,decode=self.bpf is not None)
            row['measurement_valid']=row['original_valid']
            row['registration_ns']=self.registration.pop(process.pid,0)
            return row
        row={'pid':process.pid,'measurement_valid':False,'readback_ns':0,'decode_ns':0,'cleanup_ns':0,
             'registration_ns':self.registration.pop(process.pid,0)}
        try:
            stdout,stderr=process.communicate(timeout=60)
            row.update(returncode=process.returncode,stderr=stderr)
            if process.returncode:
                row['stdout']=stdout
                return row
            start=time.monotonic_ns();visible=json.loads(stdout)
            row['json_parse_ns']=time.monotonic_ns()-start
            row['userspace']=visible
            start=time.monotonic_ns();row.update(self._packed_telemetry(process.pid))
            row['readback_ns']=time.monotonic_ns()-start
            if 'kernel_fingerprint' in row:
                row['fingerprint_equal']=row['kernel_fingerprint']==[visible['count'],visible['sum1'],visible['sum2']]
                start=time.monotonic_ns()
                diff=IBLT.from_rows(row['kernel_rows'],SEED1,SEED2).subtract(IBLT.from_rows(
                    legacy._rows_from_sparse(self.cells,visible['cells']),SEED1,SEED2)).decode()
                row['decode_ns']=time.monotonic_ns()-start
                row.update(decode_success=diff.success,
                           upstream_only=[[t.key_hash,t.inode,t.d_type] for t in diff.upstream_only],
                           downstream_only=[[t.key_hash,t.inode,t.d_type] for t in diff.downstream_only],
                           residual_cells=diff.residual_cells)
            return row
        except Exception as error:
            row['measurement_valid']=False;row['error']=repr(error)
            return row
        finally:
            if process.poll() is None: process.kill();process.communicate()
            start=time.monotonic_ns()
            try: del self.bpf['state_by_pid'][self.key(process.pid)]
            except KeyError: pass
            row['cleanup_ns']=time.monotonic_ns()-start

    def collect_started(self,processes,first=None):
        if first is None and self.bpf is not None: first=legacy.snapshot()
        for process in processes: legacy.release(process)
        rows=[self.finish(p) for p in processes]
        quality=legacy.coverage_between(first,legacy.snapshot()) if self.bpf is not None else None
        for row in rows:
            row['coverage']=quality
            if self.bpf is not None:
                row['verdict']=combine_verdict(row['measurement_valid'],row.get('fingerprint_equal'),quality)
            else: row['verdict']='unmeasured'
        return rows

    def scan(self,directory,buffer=65536,dump=None):
        total=time.monotonic_ns()
        first=legacy.snapshot() if self.bpf is not None else None
        start=time.monotonic_ns()
        process=self.begin(directory,buffer,dump)
        legacy.release(process)
        row=self.finish(process)
        row['wall_ns']=time.monotonic_ns()-start
        quality=legacy.coverage_between(first,legacy.snapshot()) if self.bpf is not None else None
        row['coverage']=quality
        row['wall_with_coverage_ns']=time.monotonic_ns()-total
        row['verdict']=(combine_verdict(row['measurement_valid'],row.get('fingerprint_equal'),quality)
                        if self.bpf is not None else 'unmeasured')
        return row

    def close(self):
        if self.bpf is not None: self.bpf.cleanup()
        self.attached=False

    def __enter__(self): return self
    def __exit__(self,*args): self.close()
