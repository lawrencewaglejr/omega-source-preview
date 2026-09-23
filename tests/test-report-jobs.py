import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'dashboard'))
from telemetry_store import TelemetryStore
from report_jobs import ReportJobs


class ReportTests(unittest.TestCase):
    def test_full_export_matches_analysis_and_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); root.chmod(0o700)
            eve=root/'eve.json'
            now=dt.datetime.now(dt.timezone.utc).isoformat()
            eve.write_text('\n'.join(json.dumps({'timestamp':now,'event_type':'dns','flow_id':n,'src_ip':'192.168.50.10','dns':{'rrname':f'example{n}.test'}}) for n in range(5))+'\n')
            store=TelemetryStore(root/'telemetry.db',eve_path=eve)
            store.poll()
            evidence=[]
            def ai(question, data):
                evidence.append(data)
                # Collection may continue while inference runs; the report is frozen.
                with eve.open('a') as target:
                    target.write(json.dumps({'timestamp':now,'event_type':'flow','flow_id':999})+'\n')
                store.poll()
                return 200, {'answer':'Five observed events; this is not a compromise.'}
            jobs=ReportJobs(store,root/'reports',ai,lambda:{'devices':[]})
            code,job=jobs.submit('owner','local-test')
            self.assertEqual(code,202)
            self.assertEqual(jobs.get(job['id'],'someone-else')[0],404)
            for _ in range(200):
                _,state=jobs.get(job['id'],'owner')
                if state['state']!='pending': break
                time.sleep(.01)
            self.assertEqual(state['state'],'complete',state)
            self.assertTrue(state['ai_available'])
            _,path=jobs.get(job['id'],'owner',download=True)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            with zipfile.ZipFile(path) as archive:
                events=[json.loads(line) for line in archive.read('events.jsonl').splitlines()]
                analysis=json.loads(archive.read('coverage-and-correlations.json'))
                self.assertEqual(len(events),5)
                originals=[json.loads(line) for line in archive.read('source-events.jsonl').splitlines()]
                self.assertEqual(len(originals),5)
                self.assertIn('flow_id',originals[0]['record'])
                self.assertEqual(analysis['events_analyzed'],5)
                self.assertIn('Five observed events',archive.read('OMEGA-report.html').decode())
            self.assertEqual(evidence[0]['events_analyzed'],5)
            self.assertEqual(store.snapshot()['events'],6)
            store.close()


if __name__=='__main__': unittest.main()
