import json
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path
from phase2.oracle import identities, transform, difference, ACTIONS
from phase2.measurement import Measurement, ROOT
from phase2.tests.evidence import retain


@unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:-1)()==0
                     and ROOT==Path('/home/kicba/research_phase2_20261023'), 'protected VM only')
class ActionTests(unittest.TestCase):
    def setUp(self):
        self.module=ROOT/'phase2/bin'/platform.release()/'phase2_transform.ko'
        self.assertTrue(self.module.is_file(),'controlled transform module not implemented')
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT/'phase2')
        self.fixture=Path(self.tmp.name)/'fixture';self.fixture.mkdir()
        for i in range(64):(self.fixture/f'ordinary_{i:04d}').touch()
        (self.fixture/'phase2_subject').touch()
        self.dump=Path(self.tmp.name)/'baseline.jsonl'
        with Measurement('parse') as tool: tool.scan(self.fixture,dump=self.dump)
        self.original=[json.loads(s) for s in self.dump.read_text().splitlines()]

    def tearDown(self):
        subprocess.run(['rmmod','phase2_transform'],capture_output=True)
        self.tmp.cleanup()

    def test_each_real_action_matches_exact_oracle_and_signed_recovery(self):
        for mode,action in enumerate(ACTIONS):
            if action=='normal': continue
            with self.subTest(action=action):
                subprocess.run(['insmod',str(self.module),'mode='+str(mode)],check=True)
                try:
                    expected=transform(self.original,action)
                    with Measurement('packed') as tool:
                        dump=Path(self.tmp.name)/(action+'.jsonl')
                        row=tool.scan(self.fixture,dump=dump)
                        actual=[json.loads(s) for s in dump.read_text().splitlines()]
                    retain(self,{'measurement':row,'actual':actual,'expected':expected},action)
                    self.assertEqual(identities(actual),identities(expected))
                    up,down=difference(self.original,expected)
                    self.assertEqual(row['verdict'],'different' if up or down else 'equal',row)
                    self.assertTrue(row['decode_success'],row)
                    self.assertEqual(sorted(row['upstream_only']),up)
                    self.assertEqual(sorted(row['downstream_only']),down)
                    params=Path('/sys/module/phase2_transform/parameters')
                    self.assertGreater(int((params/'changed').read_text()),0)
                    self.assertEqual(int((params/'errors').read_text()),0)
                finally: subprocess.run(['rmmod','phase2_transform'],check=True)

    def test_without_probes_transform_still_changes_actual_output(self):
        subprocess.run(['insmod',str(self.module),'mode=5'],check=True)
        with Measurement('parse') as tool:
            dump=Path(self.tmp.name)/'no_probe.jsonl'
            tool.scan(self.fixture,dump=dump)
        actual=[json.loads(s) for s in dump.read_text().splitlines()]
        retain(self,{'actual':actual,'expected':transform(self.original,'inode')})
        self.assertEqual(identities(actual),identities(transform(self.original,'inode')))

    def test_independent_filter_small_capacity_failure_keeps_alert(self):
        for i in range(17): (self.fixture/f'boogaloo_{i:03d}').touch()
        module=ROOT/'phase2/bin'/platform.release()/'phase2_independent.ko'
        subprocess.run(['insmod',str(module)],check=True)
        try:
            with Measurement('packed',cells=8) as tool:
                row=tool.scan(self.fixture)
                retain(self,row)
                self.assertTrue(row['measurement_valid'],row)
                self.assertEqual(row['verdict'],'different',row)
                self.assertFalse(row['decode_success'],row)
        finally:subprocess.run(['rmmod','phase2_independent'],check=True)


if __name__=='__main__': unittest.main()
