#!/usr/bin/env python3
"""Verify local model health checking without real network calls or inference."""
import concurrent.futures
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ai_status", ROOT / "dashboard/ai_status.py")
ai_status = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ai_status)


class Response:
    status = 200

    def __init__(self, raw):
        self.raw = raw
        self.limit = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, limit):
        self.limit = limit
        return self.raw[:limit]


class AIStatusTests(unittest.TestCase):
    def test_demo_and_unconfigured_never_contact_model(self):
        monitor = ai_status.AIStatusMonitor()
        with patch.object(ai_status.request, "build_opener") as builder:
            self.assertEqual(monitor.snapshot("qwen3:1.7b", True)["state"], "disabled_demo")
            self.assertFalse(monitor.snapshot("qwen3:1.7b", True)["configured"])
            self.assertEqual(monitor.snapshot()["state"], "not_configured")
            builder.assert_not_called()

    def test_fixed_endpoint_no_proxy_no_redirect_and_bounded_read(self):
        response = Response(b'{"models":[{"name":"qwen3:1.7b"}]}')
        with patch.object(ai_status.request, "build_opener") as builder:
            builder.return_value.open.return_value = response
            result = ai_status.AIStatusMonitor().snapshot("qwen3:1.7b")
            req = builder.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url, "http://127.0.0.1:11434/api/tags")
            self.assertEqual(req.get_method(), "GET")
            self.assertIsNone(req.data)
            self.assertEqual(builder.return_value.open.call_args.kwargs["timeout"], 1.0)
            handlers = builder.call_args.args
            self.assertEqual(handlers[0].proxies, {})
            self.assertIsInstance(handlers[1], ai_status.NoRedirect)
            self.assertIsNone(handlers[1].redirect_request(req, None, 302, "", {}, "https://example.com"))
        self.assertEqual(response.limit, ai_status.MAX_BODY + 1)
        self.assertEqual(result["state"], "ready")
        self.assertTrue(result["ready"])
        self.assertTrue(result["checked_at"])

    def test_model_matching_is_exact_and_accepts_default_tag(self):
        cases = [("qwen3", [{"name": "qwen3:latest"}], "ready"),
                 ("qwen3:1.7b", [{"model": "qwen3:1.7b"}], "ready"),
                 ("qwen3:1.7b", [{"name": "qwen3:8b"}], "model_missing"),
                 ("qwen3:1.7b", [], "model_missing")]
        for model, models, expected in cases:
            with self.subTest(model=model, models=models), patch.object(ai_status.request, "build_opener") as builder:
                builder.return_value.open.return_value = Response(json.dumps({"models": models}).encode())
                result = ai_status.AIStatusMonitor().snapshot(model)
                self.assertEqual(result["state"], expected)
                self.assertTrue(result["configured"])

    def test_unavailable_on_network_http_and_invalid_responses(self):
        errors = [OSError("offline"), TimeoutError(), error.HTTPError(ai_status.ENDPOINT, 302, "redirect", {}, None)]
        for failure in errors:
            with self.subTest(error=type(failure)), patch.object(ai_status.request, "build_opener") as builder:
                builder.return_value.open.side_effect = failure
                self.assertEqual(ai_status.AIStatusMonitor().snapshot("m")["state"], "unavailable")
        for raw in [b"not json", b"[]", b"{}", b'{"models":{}}', b'{"models":[null]}', b'{"models":[{"name":1}]}', b" " * (ai_status.MAX_BODY + 1)]:
            with self.subTest(raw=raw[:60]), patch.object(ai_status.request, "build_opener") as builder:
                builder.return_value.open.return_value = Response(raw)
                self.assertEqual(ai_status.AIStatusMonitor().snapshot("m")["state"], "unavailable")

    def test_cached_success_failure_expiry_and_configuration_change(self):
        monitor = ai_status.AIStatusMonitor()
        with patch.object(ai_status.time, "monotonic", return_value=100) as clock, patch.object(ai_status.request, "build_opener") as builder:
            builder.return_value.open.return_value = Response(b'{"models":[{"name":"m"}]}')
            first = monitor.snapshot("m")
            first["state"] = "mutated"
            self.assertEqual(monitor.snapshot("m")["state"], "ready")
            self.assertEqual(builder.call_count, 1)
            clock.return_value = 116
            builder.return_value.open.side_effect = OSError("offline")
            self.assertEqual(monitor.snapshot("m")["state"], "unavailable")
            self.assertEqual(monitor.snapshot("m")["state"], "unavailable")
            self.assertEqual(builder.call_count, 2)
            monitor.snapshot("different")
            self.assertEqual(builder.call_count, 3)

    def test_concurrent_polls_share_one_probe(self):
        monitor = ai_status.AIStatusMonitor()
        with patch.object(ai_status.request, "build_opener") as builder:
            builder.return_value.open.return_value = Response(b'{"models":[{"name":"m"}]}')
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: monitor.snapshot("m"), range(20)))
            self.assertTrue(all(result["ready"] for result in results))
            self.assertEqual(builder.call_count, 1)


if __name__ == "__main__":
    unittest.main()
