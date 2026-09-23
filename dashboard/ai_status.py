"""Bounded local Ollama model availability checks; never generates an answer."""
from __future__ import annotations

import datetime as dt
import json
import threading
import time
from urllib import request
from http.client import HTTPException

ENDPOINT = "http://127.0.0.1:11434/api/tags"
TIMEOUT_SECONDS = 1.0
CACHE_SECONDS = 15.0
MAX_BODY = 256 * 1024


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AIStatusMonitor:
    """Cache one configured model's status and serialize concurrent probes.

    ``ready`` means the local service reports that the model is installed.
    It does not mean inference quality or appliance resource use is validated.
    The endpoint is fixed to loopback and uses no environment proxy or redirects.
    API reference: https://docs.ollama.com/api/tags
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._key = None
        self._cached = None
        self._expires = 0.0

    @staticmethod
    def _result(state, model, message, checked_at=None):
        return {
            "state": state,
            "ready": state == "ready",
            "configured": bool(model) and state != "disabled_demo",
            "model": model or None,
            "message": message,
            "checked_at": checked_at,
        }

    def snapshot(self, model="", demo=False):
        model = model.strip() if isinstance(model, str) else ""
        if demo:
            return self._result("disabled_demo", model, "AI is disabled in preview mode. No model is contacted.")
        if not model:
            return self._result("not_configured", "", "No local AI model is configured.")
        with self._lock:
            if self._key == model and self._cached is not None and time.monotonic() < self._expires:
                return dict(self._cached)
            checked_at = dt.datetime.now(dt.timezone.utc).isoformat()
            try:
                opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
                req = request.Request(ENDPOINT, headers={"Accept": "application/json"}, method="GET")
                with opener.open(req, timeout=TIMEOUT_SECONDS) as response:
                    if response.status != 200:
                        raise ValueError("Unexpected status")
                    raw = response.read(MAX_BODY + 1)
                if len(raw) > MAX_BODY:
                    raise ValueError("Response too large")
                body = json.loads(raw)
                models = body.get("models") if isinstance(body, dict) else None
                if not isinstance(models, list):
                    raise ValueError("Invalid model list")
                names = set()
                for entry in models:
                    if not isinstance(entry, dict):
                        raise ValueError("Invalid model entry")
                    name = entry.get("name") or entry.get("model")
                    if not isinstance(name, str) or not name:
                        raise ValueError("Invalid model name")
                    names.add(name)
                # Ollama uses :latest when an untagged model name is supplied.
                expected = model if ":" in model.rsplit("/", 1)[-1] else model + ":latest"
                if model in names or expected in names:
                    result = self._result("ready", model, "Local AI service is reachable and the configured model is installed. Answers are generated only when you ask.", checked_at)
                else:
                    result = self._result("model_missing", model, "Local AI service is reachable, but the configured model is not installed.", checked_at)
            except (OSError, ValueError, TypeError, RecursionError, HTTPException):
                result = self._result("unavailable", model, "The local AI service could not be verified. Check that Ollama is running on this appliance.", checked_at)
            self._key = model
            self._cached = result
            self._expires = time.monotonic() + CACHE_SECONDS
            return dict(result)
