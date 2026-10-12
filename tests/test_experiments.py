import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from sal.experiments import events,execute,stable_seed

class ExperimentTests(unittest.TestCase):
    def test_deterministic_synthetic_stream(self):
        first=list(events(15,stable_seed(42,'demo')))
        second=list(events(15,stable_seed(42,'demo')))
        self.assertEqual(first,second)
        self.assertEqual(len(first),15)
        self.assertTrue(all(str(x['source_ip']).startswith('192.0.2.') for x in first))

    def test_full_quick_run_and_isolated_output(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            args=types.SimpleNamespace(config=str(root/'configs/default.yaml'),profile='quick',
                seed=404,output_root=tmp,experiments=['E1','E2','E3','E4','E5','E6','E7'])
            one=execute(args)
            self.assertEqual(one.name,'test1')
            self.assertTrue((one/'manifest.json').exists())
            import json
            report=json.loads((one/'manifest.json').read_text())
            self.assertTrue(all(x['success'] for x in report['experiments'].values()))
            self.assertEqual(len(list((one/'figures').glob('F*.png'))),5)
            self.assertEqual(len(list((one/'tables').glob('T*.csv'))),6)
            args.experiments=['E3']
            two=execute(args)
            self.assertEqual(two.name,'test2')
            self.assertTrue((one/'manifest.json').exists())

if __name__=='__main__':unittest.main()
