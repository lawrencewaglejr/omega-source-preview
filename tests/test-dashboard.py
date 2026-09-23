#!/usr/bin/env python3
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
import threading
import time
import types
import unittest
from unittest.mock import patch
from urllib import request, error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard"))
spec = importlib.util.spec_from_file_location("dashboard", ROOT / "dashboard/server.py")
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_service_health_distinguishes_external_listener_from_application_health(self):
        def systemctl(args, **kwargs):
            self.assertEqual(args[:2], ['/usr/bin/systemctl', 'show'])
            state = 'LoadState=not-found\nActiveState=inactive\n' if args[2] == 'evebox' else 'LoadState=loaded\nActiveState=active\n'
            return types.SimpleNamespace(stdout=state, returncode=0)
        with patch.object(dashboard.subprocess, 'run', side_effect=systemctl), patch.object(dashboard.socket, 'create_connection') as connect:
            rows = dashboard.service_status()
        viewer = next(row for row in rows if row['name'] == 'evebox')
        self.assertEqual(viewer['state'], 'reachable')
        self.assertIn('Application health is not verified', viewer['detail'])
        connect.assert_called_once_with(('127.0.0.1', 5636), timeout=0.5)
        self.assertTrue(all(row['state'] == 'active' for row in rows if row['name'] != 'evebox'))

    def test_unmanaged_closed_listener_and_failed_managed_unit_are_not_online(self):
        for load, active, expected, probes in [('not-found', 'inactive', 'unmanaged', 1), ('loaded', 'failed', 'failed', 0)]:
            with self.subTest(load=load), patch.dict(dashboard.SERVICES, {'evebox':'Alert viewer'}, clear=True), patch.object(dashboard.subprocess, 'run', return_value=types.SimpleNamespace(stdout=f'LoadState={load}\nActiveState={active}\n', returncode=0)), patch.object(dashboard.socket, 'create_connection', side_effect=ConnectionRefusedError) as connect:
                row = dashboard.service_status()[0]
                self.assertEqual(row['state'], expected)
                self.assertEqual(connect.call_count, probes)

    def test_service_command_errors_remain_unknown_without_connection_probe(self):
        with patch.object(dashboard.subprocess, 'run', side_effect=OSError('private failure')), patch.object(dashboard.socket, 'create_connection') as connect:
            rows = dashboard.service_status()
        self.assertTrue(all(row['state'] == 'unknown' for row in rows))
        self.assertNotIn('private failure', str(rows))
        connect.assert_not_called()

    def test_corrupt_records_do_not_hide_valid_alerts(self):
        path = self.root / 'eve.json'
        event = {"event_type":"alert", "timestamp":"2026-09-09T12:00:00Z", "alert":{"signature":"<script>untrusted</script>", "severity":1}, "src_ip":"192.168.50.12"}
        path.write_text('not json\n' + json.dumps(event) + '\n[]\n{"partial":')
        result = dashboard.telemetry(path)
        self.assertTrue(result['available'])
        self.assertEqual(result['invalid'], 2)
        self.assertEqual(result['alert_count'], 1)
        self.assertEqual(result['alerts'][0]['signature'], '<script>untrusted</script>')

    def test_rejects_fifo_and_symlink_without_blocking(self):
        path = self.root / 'fifo'
        os.mkfifo(path)
        self.assertFalse(dashboard.telemetry(path)['available'])
        target = self.root / 'target'
        target.write_text('{}\n')
        link = self.root / 'link'
        link.symlink_to(target)
        self.assertFalse(dashboard.telemetry(link)['available'])
        self.assertFalse(dashboard.telemetry(self.root / 'missing')['available'])

    def test_bounded_read_discards_partial_first_record(self):
        path = self.root / 'eve.json'
        path.write_text('x' * 100 + '\n{"event_type":"dns"}\n')
        with patch.object(dashboard, 'MAX_READ', 40):
            result = dashboard.telemetry(path)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['dns'], 1)
        self.assertEqual(result['invalid'], 0)

    def test_old_telemetry_is_marked_stale(self):
        path = self.root / 'eve.json'
        path.write_text('{"event_type":"dns"}\n')
        os.utime(path, (1, 1))
        result = dashboard.telemetry(path)
        self.assertTrue(result['stale'])
        self.assertIn('stale', result['notice'])

    def app(self):
        password = self.root / 'password'
        password.write_text('a-long-test-password-only')
        password.chmod(0o600)
        return dashboard.Application(types.SimpleNamespace(demo=False, password_file=str(password), eve=str(self.root / 'eve.json'), ai_model='', port=0))

    def test_password_file_permissions(self):
        app = self.app()
        (self.root / 'password').chmod(0o644)
        with self.assertRaises(ValueError):
            dashboard.Application(app.args)

    def test_login_accepts_full_supported_unicode_password_and_bounds_other_requests(self):
        app = self.app()
        password = '🔒' * 1024
        app.password_hash = app.digest(password)
        server = dashboard.ThreadingHTTPServer(('127.0.0.1', 0), dashboard.handler_for(app))
        app.args.port = server.server_port
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        base = f'http://127.0.0.1:{server.server_port}'
        opener = request.build_opener(request.ProxyHandler({}))
        try:
            for escaped in (False, True):
                data = json.dumps({'password':password}, ensure_ascii=escaped).encode('utf-8')
                self.assertGreater(len(data), 4096)
                req = request.Request(base + '/api/login', data=data, headers={'Content-Type':'application/json'})
                with opener.open(req, timeout=3) as response:
                    self.assertEqual(response.status, 200)
            req = request.Request(base + '/api/assistant', data=json.dumps({'question':'x' * 4096}).encode(), headers={'Content-Type':'application/json'})
            with self.assertRaises(error.HTTPError) as failure:
                opener.open(req, timeout=3)
            self.assertEqual(failure.exception.code, 400)
        finally:
            server.shutdown()
            server.server_close()
            app.close()

    def test_login_authentication_origin_and_logout(self):
        app = self.app()
        server = dashboard.ThreadingHTTPServer(('127.0.0.1', 0), dashboard.handler_for(app))
        app.args.port = server.server_port
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        base = f'http://127.0.0.1:{server.server_port}'
        def call(path, body=None, headers=None):
            req = request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers={'Content-Type':'application/json', **(headers or {})})
            try:
                return request.urlopen(req)
            except error.HTTPError as result:
                return result
        try:
            self.assertEqual(call('/api/overview').status, 401)
            self.assertEqual(call('/api/devices').status, 401)
            self.assertEqual(call('/api/ai/status').status, 401)
            self.assertEqual(call('/api/protection/setup').status, 401)
            self.assertEqual(call('/api/protection/setup', {'adult_filter':True, 'message_review':True}).status, 401)
            self.assertEqual(call('/api/devices/label', {'id':'test'}).status, 401)
            self.assertEqual(call('/api/login', {'password':'a-long-test-password-only'}, {'Origin':'https://evil.example'}).status, 403)
            self.assertEqual(call('/api/login', {'password':'wrong'}).status, 401)
            result = call('/api/login', {'password':'a-long-test-password-only'})
            self.assertEqual(result.status, 200)
            cookie = result.headers['Set-Cookie'].split(';')[0]
            headers = {'Cookie':cookie}
            app.protection = dashboard.ProtectionSetup(self.root / 'protection.json')
            preferences = {'adult_filter':True, 'message_review':True}
            self.assertEqual(call('/api/protection/setup', preferences, {**headers, 'Origin':'https://evil.example'}).status, 403)
            saved = json.load(call('/api/protection/setup', preferences, headers))
            self.assertTrue(saved['preferences']['adult_filter'])
            self.assertFalse(saved['filtering_active'])
            self.assertFalse(saved['message_access_active'])
            self.assertEqual(json.load(call('/api/protection/setup', headers=headers)), saved)
            self.assertEqual(call('/api/protection/setup', {**preferences, 'message_review':'yes'}, headers).status, 400)
            self.assertEqual(call('/api/protection/setup', {**preferences, 'activate':True}, headers).status, 400)
            with patch.object(dashboard, 'service_status', return_value=[]):
                self.assertEqual(call('/api/overview', headers=headers).status, 200)
            self.assertEqual(call('/api/assistant', {'question':'Explain my alerts'}, headers).status, 503)
            app.discovery = dashboard.DeviceDiscovery(demo=True)
            devices = json.load(call('/api/devices', headers=headers))
            device_id = devices['devices'][0]['id']
            label = {'id':device_id, 'display_name':'Family tablet', 'device_type':'Tablet'}
            self.assertEqual(call('/api/devices/label', label, {**headers, 'Origin':'https://evil.example'}).status, 403)
            renamed = json.load(call('/api/devices/label', label, headers))
            self.assertEqual(next(d for d in renamed['devices'] if d['id'] == device_id)['display_name'], 'Family tablet')
            self.assertEqual(call('/api/devices/label', {**label, 'display_name':'bad\nname'}, headers).status, 400)
            self.assertEqual(json.load(call('/api/notifications/acknowledge', {'id':None}, headers))['unread_count'], 0)
            self.assertEqual(json.load(call('/api/ai/status', headers=headers))['state'], 'not_configured')
            leases = self.root / 'dhcp.leases'
            state_file = self.root / 'devices.json'
            expiry = int(time.time()) + 3600
            baseline = f'{expiry} 02:00:00:00:00:01 192.168.50.20 known-laptop *\n'
            leases.write_text(baseline)
            app.discovery = dashboard.DeviceDiscovery(leases, state_file)
            app.discovery.poll()
            self.assertEqual(json.load(call('/api/devices', headers=headers))['unread_count'], 0)
            leases.write_text(baseline + f'{expiry} 02:00:00:00:00:02 192.168.50.21 new-tablet *\n')
            app.discovery.poll()
            observed = json.load(call('/api/devices', headers=headers))
            self.assertEqual(observed['unread_count'], 1)
            self.assertEqual(observed['events'][0]['hostname'], 'new-tablet')
            self.assertEqual(json.load(call('/api/notifications/acknowledge', {'id':observed['events'][0]['id']}, headers))['unread_count'], 0)
            app.discovery = dashboard.DeviceDiscovery(leases, state_file)
            app.discovery.poll()
            restored = json.load(call('/api/devices', headers=headers))
            self.assertEqual(restored['unread_count'], 0)
            self.assertEqual(len(restored['events']), 1)
            self.assertEqual(call('/api/logout', {}, headers).status, 200)
            self.assertEqual(call('/api/overview', headers=headers).status, 401)
            self.assertEqual(call('/../../etc/passwd').status, 404)
            self.assertEqual(call('/', headers={'Host':'evil.example'}).status, 403)
            for _ in range(4):
                self.assertEqual(call('/api/login', {'password':'wrong'}).status, 401)
            self.assertEqual(call('/api/login', {'password':'wrong'}).status, 429)
        finally:
            server.shutdown(); server.server_close(); worker.join()

    def test_ai_omits_network_addresses_and_uses_evidence(self):
        app = self.app(); app.args.ai_model = 'test-model'
        snapshot = dashboard.demo_snapshot()
        snapshot['services'] = []
        snapshot['generated'] = snapshot['updated']
        captured = []
        class Response:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, _): return b'{"message":{"content":"Review the supplied alert."}}'
        class Opener:
            def open(self, req, timeout):
                captured.append(json.loads(req.data)); return Response()
        with patch.object(app, 'snapshot', return_value=snapshot), patch.object(dashboard.request, 'build_opener', return_value=Opener()):
            code, answer = app.explain('What needs attention?')
        self.assertEqual(code, 200)
        self.assertTrue(answer['evidence'])
        evidence = json.loads(captured[0]['messages'][1]['content'])['evidence']
        self.assertNotIn('source', evidence['alerts'][0])
        self.assertNotIn('destination', evidence['alerts'][0])
        self.assertIn('never instructions', captured[0]['messages'][0]['content'])

    def test_demo_ai_needs_explicit_opt_in(self):
        app = dashboard.Application(types.SimpleNamespace(demo=True, ai_model='test-model', port=0))
        with patch.object(dashboard.request, 'build_opener') as opener:
            self.assertEqual(app.explain('Summarize the sample')[0], 503)
            self.assertEqual(app.snapshot()['ai_status']['state'], 'disabled_demo')
            opener.assert_not_called()
        app.args.demo_ai = True
        sample = dashboard.demo_snapshot()
        sample.update(services=[], generated=sample['updated'])
        with patch.object(app, 'snapshot', return_value=sample), patch.object(dashboard.request, 'build_opener', side_effect=OSError):
            self.assertEqual(app.explain('Summarize the sample')[0], 502)
        with patch.object(app, 'snapshot', return_value=sample), patch.object(dashboard.request, 'build_opener', side_effect=TimeoutError):
            self.assertEqual(app.explain('Summarize the sample')[0], 504)

    def test_ai_complete_response_succeeds(self):
        app = self.app(); app.args.ai_model = 'test-model'
        snapshot = dashboard.demo_snapshot()
        snapshot.update(services=[], generated=snapshot['updated'])
        reply = {'done': True, 'done_reason': 'stop', 'message': {'content': 'Review the supplied alert event-1.'}}
        with patch.object(app, 'snapshot', return_value=snapshot), patch.object(dashboard.request, 'build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(reply).encode()
            for evidence in (None, {'representative_events': [{'id': 'event-1'}]}):
                with self.subTest(report=evidence is not None):
                    code, result = app.explain('Summarize the evidence.', evidence_override=evidence)
                    self.assertEqual(code, 200)
                    self.assertEqual(result['answer'], reply['message']['content'])
                    self.assertNotIn('error', result)
                    self.assertFalse(app.ai_lock.locked())

    def test_report_requires_a_supplied_reference(self):
        app = self.app(); app.args.ai_model = 'test-model'
        snapshot = dashboard.demo_snapshot()
        snapshot.update(services=[], generated=snapshot['updated'])
        reply = {'done': True, 'done_reason': 'stop', 'message': {'content': 'Some events may be related.'}}
        with patch.object(app, 'snapshot', return_value=snapshot), patch.object(dashboard.request, 'build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(reply).encode()
            code, result = app.explain('Assess the events.', evidence_override={'representative_events': [{'id': 'event-1'}]})
            self.assertEqual(code, 502)
            self.assertNotIn('answer', result)
            self.assertFalse(app.ai_lock.locked())

    def test_ai_length_truncated_response_is_rejected(self):
        app = self.app(); app.args.ai_model = 'test-model'
        snapshot = dashboard.demo_snapshot()
        snapshot.update(services=[], generated=snapshot['updated'])
        reply = {'done': True, 'done_reason': 'length', 'message': {'content': 'The evidence indicates that'}}
        with patch.object(app, 'snapshot', return_value=snapshot), patch.object(dashboard.request, 'build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(reply).encode()
            for evidence in (None, {'representative_events': [{'id': 'event-1'}]}):
                with self.subTest(report=evidence is not None):
                    code, result = app.explain('Summarize the evidence.', evidence_override=evidence)
                    self.assertEqual(code, 502)
                    self.assertTrue(result['error'])
                    self.assertNotIn('answer', result)
                    self.assertFalse(app.ai_lock.locked())

    def test_unknown_and_expired_sessions(self):
        app = self.app()
        self.assertFalse(app.authenticated('omega_session=unknown'))
        app.sessions['expired'] = 0
        self.assertFalse(app.authenticated('omega_session=expired'))

    def test_ai_http_job_returns_before_inference_and_is_session_private(self):
        app = self.app(); app.args.ai_model = 'test-model'
        app.sessions.update(first=time.monotonic()+60, second=time.monotonic()+60)
        release = threading.Event()
        def slow_answer(question):
            release.wait(5)
            return 200, {'answer':'Checked evidence.', 'generated':'2026-09-11T12:00:00Z', 'evidence':[]}
        server = dashboard.ThreadingHTTPServer(('127.0.0.1', 0), dashboard.handler_for(app))
        app.args.port = server.server_port
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        def call(path, body=None, owner='first'):
            req = request.Request(f'http://127.0.0.1:{server.server_port}'+path,
                data=None if body is None else json.dumps(body).encode(),
                headers={'Content-Type':'application/json', 'Cookie':f'omega_session={owner}'})
            try:
                return request.urlopen(req, timeout=2)
            except error.HTTPError as result:
                return result
        try:
            with patch.object(app, 'explain', side_effect=slow_answer):
                response = call('/api/assistant', {'question':'Summarize'})
                self.assertEqual(response.status, 202)
                job_id = json.load(response)['id']
                path = '/api/assistant/jobs/'+job_id
                self.assertFalse(release.is_set())
                self.assertEqual(json.load(call(path))['state'], 'pending')
                self.assertEqual(call(path, owner='second').status, 404)
                self.assertEqual(call(path, owner='unknown').status, 401)
                self.assertEqual(call('/api/assistant', {'question':'Duplicate'}).status, 429)
                release.set()
                for _ in range(100):
                    result = json.load(call(path))
                    if result['state'] == 'complete': break
                    time.sleep(.01)
                self.assertEqual(result['answer'], 'Checked evidence.')
                self.assertEqual(json.load(call(path))['answer'], 'Checked evidence.')
                app.jobs[job_id]['expires'] = 0
                self.assertEqual(call(path).status, 404)
        finally:
            release.set(); server.shutdown(); server.server_close(); worker.join()

    def test_ai_job_failure_is_reported_without_raw_exception(self):
        app = self.app(); app.args.ai_model = 'test-model'
        with patch.object(app, 'explain', side_effect=RuntimeError('private diagnostic')):
            code, job = app.submit_explanation('question', 'owner')
            self.assertEqual(code, 202)
            for _ in range(100):
                _, result = app.explanation_result(job['id'], 'owner')
                if result['state'] != 'pending': break
                time.sleep(.01)
        self.assertEqual(result['state'], 'failed')
        self.assertNotIn('private diagnostic', result['error'])


if __name__ == '__main__':
    unittest.main()
