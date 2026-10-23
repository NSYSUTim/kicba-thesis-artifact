"""Actual kernel integration checks; no simulated BPF map results."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from phase2.tests.evidence import retain

ROOT = Path(__file__).resolve().parents[2]
try:
    from phase2.measurement import Measurement
except ImportError:
    Measurement = None


@unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0
                     and ROOT == Path('/home/kicba/research_phase2_20261023'),
                     'requires protected native VM')
class NativeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(Measurement, 'packed measurement not implemented')
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / 'phase2')
        self.fixture = Path(self.temporary.name)
        for name in ['phase2_subject', '普通檔名', 'z'*255, 'other']:
            (self.fixture/name).touch()
        (self.fixture/'directory').mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def test_exact_accepted_fingerprint_and_cells_match_independent_python(self):
        from phase2.oracle import token_rows, SEED1, SEED2
        from kicba.reconciliation import EntryToken, IBLT, MultisetFingerprint
        for cells in (8, 256):
            with self.subTest(cells=cells), Measurement('packed', cells=cells) as tool:
                dump=self.fixture/('..')/('exact_'+str(cells)+'.jsonl')
                try:
                    row=tool.scan(self.fixture, 512, dump=dump)
                    retain(self,{'measurement':row,'actual':[json.loads(s) for s in dump.read_text().splitlines()]},cells)
                    self.assertEqual(row['verdict'],'equal',row)
                    self.assertTrue(row['decode_success'],row)
                    tokens=[EntryToken(*r) for r in token_rows([json.loads(s) for s in dump.read_text().splitlines()])]
                    self.assertEqual(row['kernel_fingerprint'],list(MultisetFingerprint.from_tokens(tokens).as_tuple()))
                    self.assertEqual(row['kernel_rows'],[list(r) for r in IBLT.from_tokens(tokens,cells,SEED1,SEED2).to_rows()])
                finally:
                    dump.unlink(missing_ok=True)

    def test_small_buffers_keep_rejected_acceptance_attempts_out(self):
        (self.fixture/('z'*255)).unlink()
        with Measurement('packed') as tool:
            row=tool.scan(self.fixture,64)
            retain(self,row)
            self.assertEqual(row['verdict'],'equal',row)
            self.assertGreater(row['kernel_stats']['rejected_entries'],0)
            self.assertTrue(row['decode_success'])

    def test_invalid_cell_config_is_not_valid_equal(self):
        with Measurement('packed') as tool:
            process=tool.begin(self.fixture,512)
            state=tool.bpf['state_by_pid'][tool.key(process.pid)]
            state.cell_count=3
            tool.bpf['state_by_pid'][tool.key(process.pid)]=state
            row=tool.collect_started([process])[0]
            retain(self,row)
            self.assertEqual(row['verdict'],'invalid',row)

    def test_missing_state_and_unpaired_state_are_invalid(self):
        with Measurement('packed') as tool:
            for fault in ('missing','unpaired'):
                process=tool.begin(self.fixture,512)
                if fault=='missing':
                    del tool.bpf['state_by_pid'][tool.key(process.pid)]
                else:
                    state=tool.bpf['state_by_pid'][tool.key(process.pid)]
                    state.depth=1
                    tool.bpf['state_by_pid'][tool.key(process.pid)]=state
                row=tool.collect_started([process])[0]
                retain(self,row,fault)
                self.assertEqual(row['verdict'],'invalid',row)

    def test_seed_mismatch_is_invalid(self):
        with Measurement('packed') as tool:
            process=tool.begin(self.fixture,512)
            state=tool.bpf['state_by_pid'][tool.key(process.pid)]
            state.seed1 ^= 1
            tool.bpf['state_by_pid'][tool.key(process.pid)]=state
            row=tool.collect_started([process])[0]
            retain(self,row)
            self.assertEqual(row['verdict'],'invalid',row)

    def test_16_concurrent_scans_keep_separate_records(self):
        with Measurement('packed') as tool:
            processes=[tool.begin(self.fixture,512) for _ in range(16)]
            rows=tool.collect_started(processes)
            retain(self,rows)
            self.assertEqual(len({r['pid'] for r in rows}),16)
            self.assertTrue(all(r['verdict']=='equal' and r['decode_success'] for r in rows), rows)

    def test_real_return_probe_loss_rejects_whole_window(self):
        (self.fixture/('z'*255)).unlink()
        for i in range(2048): (self.fixture/f'bulk_{i:05d}').touch()
        with Measurement('packed', maxactive=1) as tool:
            rows=tool.collect_started([tool.begin(self.fixture,256) for _ in range(16)])
            retain(self,rows)
            self.assertTrue(any(v['missed_delta']>0 for v in rows[0]['coverage']['per_event'].values()))
            self.assertTrue(all(r['verdict']=='invalid' for r in rows), rows)


if __name__ == '__main__': unittest.main()
