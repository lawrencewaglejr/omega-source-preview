#!/usr/bin/python3
"""Owner setup authentication, state transitions, and live acceptance logic."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onboarding"))
import appliance as A
spec = importlib.util.spec_from_file_location("onboarding_server", ROOT / "onboarding/server.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.appliance = A.DemoAppliance()
        self.app = S.Application(self.appliance, "fixture-pair-code")
        self.server = S.ThreadingHTTPServer(("127.0.0.1", 0), S.handler_for(self.app))
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.cookie = None
        self.csrf = None
        self.opener = request.build_opener(request.ProxyHandler({}))

    def call(self, path, body=None, headers=None, raw=None):
        all_headers = {}
        if body is not None or raw is not None:
            all_headers.update({"Origin": self.url, "Content-Type": "application/json"})
        if self.cookie:
            all_headers["Cookie"] = self.cookie
        if self.csrf:
            all_headers["X-OMEGA-CSRF"] = self.csrf
        for key, value in (headers or {}).items():
            if value is None:
                all_headers.pop(key, None)
            else:
                all_headers[key] = value
        data = raw if raw is not None else json.dumps(body).encode() if body is not None else None
        req = request.Request(self.url + path, data=data, headers=all_headers)
        try:
            response = self.opener.open(req, timeout=3)
        except error.HTTPError as exc:
            response = exc
        with response:
            content = response.read()
            return response.status, json.loads(content), response.headers

    def pair(self):
        code, result, headers = self.call("/api/pair", {"code": "fixture-pair-code"})
        self.assertEqual(code, 200)
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.csrf = result["csrf"]
        return headers

    def wait(self, job):
        until = time.monotonic() + 3
        while time.monotonic() < until:
            code, result, _ = self.call("/api/jobs/" + job)
            self.assertEqual(code, 200)
            if result["state"] != "pending":
                return result
            time.sleep(.01)
        self.fail("Setup job failed to finish")

    def operation(self, path, body):
        code, job, _ = self.call(path, body)
        self.assertEqual(code, 202, job)
        return self.wait(job["job_id"])

    def test_pair_once_private_cookie_reload_and_no_anonymous_details(self):
        code, result, _ = self.call("/api/status")
        self.assertEqual(result, {"authenticated": False, "demo": True})
        headers = self.pair()
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.call("/api/status")[1]["csrf"], self.csrf)
        self.assertEqual(self.call("/api/pair", {"code": "fixture-pair-code"})[0], 401)

    def test_pair_expiry_rate_limit_and_invalid_unicode(self):
        self.assertEqual(self.call("/api/pair", {"code": "\ud800"})[0], 401)
        for _ in range(4):
            self.assertEqual(self.call("/api/pair", {"code": "wrong"})[0], 401)
        self.assertEqual(self.call("/api/pair", {"code": "fixture-pair-code"})[0], 429)
        self.app.failures.clear()
        self.app.pair_until = time.monotonic() - 1
        self.assertEqual(self.call("/api/pair", {"code": "fixture-pair-code"})[0], 401)

    def test_untrusted_origin_host_and_missing_csrf_cannot_mutate(self):
        for headers in ({"Host": "example.invalid"}, {"Origin": "http://example.invalid"}, {"Origin": None}):
            self.assertEqual(self.call("/api/pair", {"code": "fixture-pair-code"}, headers)[0], 403)
        self.assertEqual(self.call("/api/activate", {})[0], 401)
        self.pair()
        for value in (None, "wrong", "é"):
            self.assertEqual(self.call("/api/activate", {}, {"X-OMEGA-CSRF": value})[0], 403)
        self.assertEqual(self.appliance.current_phase, "unconfigured")

    def test_duplicate_and_malformed_json_unknown_fields_and_body_limits(self):
        self.assertEqual(self.call("/api/pair", raw=b'{"code":"a","code":"b"}')[0], 400)
        self.assertEqual(self.call("/api/pair", raw=b'\xff')[0], 400)
        self.assertEqual(self.call("/api/pair", {"code": "x" * S.MAX_BODY})[0], 400)
        self.pair()
        self.assertEqual(self.call("/api/check", {"config": {}, "command": "anything"})[0], 400)
        self.assertEqual(self.call("/api/activate", {}, {"Content-Type": "text/plain"})[0], 415)

    def test_jobs_nonblocking_serialized_private_and_session_expiry(self):
        self.pair()
        started, finish = threading.Event(), threading.Event()
        def slow(config):
            started.set()
            finish.wait(3)
            return {"ok": True}
        with mock.patch.object(self.appliance, "check", side_effect=slow):
            code, job, _ = self.call("/api/check", {"config": A.DEFAULTS})
            self.assertEqual(code, 202)
            self.assertTrue(started.wait(1))
            self.assertEqual(self.call("/api/activate", {})[0], 409)
            self.assertEqual(self.call("/api/manager/identity", {})[0], 409)
            self.assertEqual(self.call("/api/jobs/" + job["job_id"])[1]["state"], "pending")
            token = self.cookie.split("=", 1)[1]
            self.app.sessions["different"] = {"csrf": "other", "expires": time.monotonic() + 20}
            self.assertEqual(self.call("/api/jobs/" + job["job_id"], headers={"Cookie": "omega_setup=different"})[0], 404)
            finish.set()
            self.assertEqual(self.wait(job["job_id"])["state"], "complete")
            self.app.sessions[token]["expires"] = time.monotonic() - 1
            self.assertEqual(self.call("/api/jobs/" + job["job_id"])[0], 401)

    def test_preview_complete_flow_no_password_in_jobs_or_status(self):
        self.pair()
        password = "private fixture password"
        self.assertEqual(self.operation("/api/activate", {})["state"], "failed")
        self.assertEqual(self.operation("/api/check", {"config": A.DEFAULTS})["result"]["ok"], True)
        result = self.operation("/api/configure", {"config": A.DEFAULTS, "password": password, "password_confirm": password})
        self.assertEqual(result["result"]["phase"], "configured")
        self.assertNotIn(password, json.dumps(self.app.jobs))
        self.assertNotIn(password, json.dumps(self.call("/api/status")[1]))
        self.assertEqual(self.operation("/api/activate", {})["result"]["phase"], "active")
        self.assertTrue(self.operation("/api/verify", {})["result"]["demo"])

    def test_configure_requires_same_checked_settings_and_matching_password(self):
        self.pair()
        body = {"config": A.DEFAULTS, "password": "private fixture password", "password_confirm": "private fixture password"}
        self.assertEqual(self.operation("/api/configure", body)["state"], "failed")
        self.operation("/api/check", {"config": A.DEFAULTS})
        changed = dict(body, config=dict(A.DEFAULTS, OMEGA_AI_THREADS=3))
        self.assertEqual(self.operation("/api/configure", changed)["state"], "failed")
        self.assertEqual(self.operation("/api/configure", dict(body, password_confirm="different password"))["state"], "failed")
        self.assertEqual(self.appliance.current_phase, "unconfigured")

    def test_unknown_exception_does_not_reveal_details_or_block_future_work(self):
        self.pair()
        with mock.patch.object(self.appliance, "check", side_effect=RuntimeError("private fixture secret")):
            result = self.operation("/api/check", {"config": A.DEFAULTS})
        self.assertEqual(result["state"], "failed")
        self.assertNotIn("private fixture secret", json.dumps(result))
        self.assertTrue(self.operation("/api/check", {"config": A.DEFAULTS})["result"]["ok"])

    def test_manager_validation_errors_are_actionable_but_unknown_errors_are_private(self):
        self.pair()
        mirror = A.load_helper("configure-wazuh-mirror")
        self.appliance.mirror_module = mirror
        config = {"host": "manager.example.test", "user": "root", "port": 22, "host_key": "invalid"}
        # Real packaged validation runs before any filesystem or manager access.
        with mock.patch.object(self.appliance, "configure_manager", side_effect=mirror.validate_config):
            result = self.operation("/api/manager/configure", config)
            self.assertEqual(result["state"], "failed")
            self.assertEqual(result["error"], "Use a dedicated non-root manager reader account.")
            config["user"] = "omega-reader"
            result = self.operation("/api/manager/configure", config)
            self.assertEqual(result["state"], "failed")
            self.assertEqual(result["error"], "An ssh-ed25519 public key is required.")
        with mock.patch.object(self.appliance, "configure_manager", side_effect=OSError("private manager fixture secret")):
            result = self.operation("/api/manager/configure", config)
        self.assertEqual(result["state"], "failed")
        self.assertNotIn("private manager fixture secret", json.dumps(self.app.jobs))
        self.assertIn("Setup could not finish", result["error"])
        self.assertTrue(self.operation("/api/check", {"config": A.DEFAULTS})["result"]["ok"])

    def test_identity_errors_keep_known_recovery_guidance_and_hide_unknown_details(self):
        self.pair()
        mirror = A.load_helper("configure-wazuh-mirror")
        self.appliance.mirror_module = mirror
        known = (
            mirror.SetupError("Existing device identity is incomplete; it will not be replaced."),
            A.SetupError("Existing installations retain their manager identity. Use the operator recovery process."),
        )
        for failure in (*known, OSError("private identity fixture secret"), ValueError("private identity fixture secret")):
            with self.subTest(error_type=type(failure).__name__):
                with mock.patch.object(self.appliance, "identity", side_effect=failure):
                    code, result, _ = self.call("/api/manager/identity", {})
                self.assertEqual(code, 409)
                if failure in known:
                    self.assertEqual(result["error"], str(failure))
                else:
                    self.assertNotIn("private identity fixture secret", json.dumps(result))
                    self.assertIn("Could not prepare a fresh manager identity", result["error"])
                self.assertFalse(self.app.operation.locked())
        self.assertEqual(self.call("/api/manager/identity", {})[0], 200)


class ApplianceTests(unittest.TestCase):
    @staticmethod
    def snapshot(count=2):
        return {"coverage": {"collection_mode": "from_now", "collection_started": "2026-09-14T00:00:00+00:00"},
                "sources": [{"id": name, "available": True, "caught_up": True, "total_records": count,
                             "duplicate_records": 0, "sync_current": True} for name in (
                                 "suricata", "pihole", "wazuh_alerts", "wazuh_archives")]}

    def test_defaults_match_shipped_configuration(self):
        self.assertEqual(A.DEFAULTS, json.loads((ROOT / "image/rootfs-overlay/etc/omega/dashboard-setup.json.example").read_text()))

    def test_production_requires_root_and_demo_uses_no_privileged_operations(self):
        with mock.patch.object(A.os, "geteuid", return_value=1000), self.assertRaises(A.SetupError):
            A.Appliance()
        with mock.patch.object(A.subprocess, "run", side_effect=AssertionError("No subprocess in preview")):
            preview = A.DemoAppliance()
            preview.identity()
            preview.check(A.DEFAULTS)
            preview.configure({"config": A.DEFAULTS, "password": "private preview password", "password_confirm": "private preview password"})
            preview.activate()
            preview.verify()

    def test_live_sources_require_new_unique_records_and_stable_boundary(self):
        before, after = self.snapshot(2), self.snapshot(3)
        self.assertTrue(all(row["status"] == "pass" for row in A.source_verification(before, after).values()))
        self.assertTrue(all(row["status"] == "gap" for row in A.source_verification(before, before).values()))
        for row in after["sources"]:
            row["duplicate_records"] = 1
        self.assertTrue(all(row["status"] == "gap" for row in A.source_verification(before, after).values()))
        after = self.snapshot(3)
        after["coverage"]["collection_started"] = "a different run"
        self.assertTrue(all(row["status"] == "gap" for row in A.source_verification(before, after).values()))

    def test_stale_missing_unavailable_sources_and_historical_mode_stay_gaps(self):
        before = self.snapshot(2)
        for field in ("available", "caught_up", "sync_current"):
            after = self.snapshot(3)
            after["sources"][2][field] = False
            self.assertEqual(A.source_verification(before, after)["wazuh"]["status"], "gap")
        self.assertTrue(all(row["status"] == "gap" for row in A.source_verification(before, {}).values()))
        after = self.snapshot(3)
        after["coverage"]["collection_mode"] = "available_history"
        self.assertTrue(all(row["status"] == "gap" for row in A.source_verification(before, after).values()))

    def test_one_new_wazuh_observation_in_both_streams_is_not_a_false_gap(self):
        before, after = self.snapshot(2), self.snapshot(3)
        after["sources"][3]["duplicate_records"] = 1
        result = A.source_verification(before, after)
        self.assertEqual(result["wazuh"]["status"], "pass")
        self.assertEqual(result["wazuh"]["new_records"], 1)
        after["sources"][2]["duplicate_records"] = 1
        self.assertEqual(A.source_verification(before, after)["wazuh"]["status"], "gap")

    def test_activate_only_starts_fixed_units_after_configuration(self):
        appliance = object.__new__(A.Appliance)
        appliance.phase = mock.Mock(return_value="unconfigured")
        with mock.patch.object(A.subprocess, "run") as run:
            with self.assertRaises(A.SetupError):
                appliance.activate()
            run.assert_not_called()
            appliance.phase.side_effect = ["configured", "active"]
            self.assertTrue(appliance.activate()["ok"])
            self.assertEqual(run.call_args.args[0], ["/usr/bin/systemctl", "enable", "--now", "omega-ai.service", "omega-dashboard.service"])

    def test_local_client_rejects_arbitrary_endpoints(self):
        with mock.patch.object(A.DashboardClient, "call"):
            client = A.DashboardClient("private")
        with self.assertRaises(A.SetupError):
            client.call("https://example.com")
        with self.assertRaises(A.SetupError):
            client.call("/api/assistant/jobs/../../etc/passwd")

    def test_unicode_local_login_uses_utf8_with_bounded_password_body(self):
        with mock.patch.object(A.DashboardClient, "call"):
            client = A.DashboardClient("private")
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok":true}'
        client.opener.open = mock.Mock(return_value=response)
        client.call("/api/login", {"password": "🔒" * 1024})
        data = client.opener.open.call_args.args[0].data
        self.assertLess(len(data), 8192)
        self.assertEqual(json.loads(data)["password"], "🔒" * 1024)

    def test_verification_requires_real_completed_inference_and_logs_out(self):
        appliance = object.__new__(A.Appliance)
        appliance.phase = lambda: "active"
        appliance.setup = lambda: type("Accounts", (), {"accounts": {"omega-dashboard": (1000, 1000, [])}})()
        appliance.setup_module = type("SetupModule", (), {"PASSWORD": "/fixture/password", "read_small": staticmethod(lambda *a, **k: b"private fixture password")})()
        client = mock.Mock()
        client.call.side_effect = [self.snapshot(2), {"id": "a" * 32}, {"state": "complete", "answer": "Fixture grounded answer"}, self.snapshot(3)]
        with mock.patch.object(A, "DashboardClient", return_value=client), mock.patch.object(A.time, "sleep"):
            result = appliance.verify()
        self.assertTrue(result["ok"])
        client.close.assert_called_once()
        client.reset_mock()
        client.call.side_effect = [self.snapshot(2), {"id": "b" * 32}, {"state": "failed", "error": "model unavailable"}, self.snapshot(3)]
        with mock.patch.object(A, "DashboardClient", return_value=client), mock.patch.object(A.time, "sleep"):
            result = appliance.verify()
        self.assertFalse(result["ok"])
        self.assertEqual(result["ai"]["status"], "gap")
        client.close.assert_called_once()

    def test_failed_verification_clears_previous_success_before_login(self):
        appliance = object.__new__(A.Appliance)
        appliance.verification = {"ok": True}
        appliance.phase = lambda: "unconfigured"
        with self.assertRaises(A.SetupError):
            appliance.verify()
        self.assertIsNone(appliance.verification)


if __name__ == "__main__":
    unittest.main()
