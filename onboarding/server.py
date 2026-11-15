#!/usr/bin/env python3
"""Short-lived, paired, loopback-only owner setup; never enabled in a master image."""
from __future__ import annotations

import argparse
import collections
import copy
import hmac
import http.cookies
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from appliance import Appliance, DemoAppliance, SetupError

STATIC = Path(__file__).parent / "static"
MAX_BODY = 24 * 1024
SESSION_SECONDS = 3600
PAIR_SECONDS = 1800


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key")
        result[key] = value
    return result


class Application:
    def __init__(self, appliance, code=None):
        self.appliance = appliance
        self.code = code or secrets.token_urlsafe(24)
        self.pair_until = time.monotonic() + PAIR_SECONDS
        self.lock = threading.RLock()
        self.operation = threading.Lock()
        self.sessions = {}
        self.failures = collections.deque()
        self.jobs = {}

    def pair(self, code):
        with self.lock:
            now = time.monotonic()
            while self.failures and self.failures[0] < now - 60:
                self.failures.popleft()
            if len(self.failures) >= 5:
                return 429, {"error": "Wait one minute before trying another pairing code."}, None
            try:
                matches = isinstance(code, str) and bool(self.code) and hmac.compare_digest(code.encode(), self.code.encode())
            except UnicodeError:
                matches = False
            if not matches or now > self.pair_until:
                self.failures.append(now)
                return 401, {"error": "Pairing code is incorrect, already used, or expired. Restart the setup command for a new code."}, None
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[token] = {"csrf": csrf, "expires": now + SESSION_SECONDS}
            self.code = None  # Pair once; reload recovers from the private session cookie.
            return 200, {"authenticated": True, "csrf": csrf}, token

    def session(self, cookie):
        try:
            parsed = http.cookies.SimpleCookie(cookie)
            token = parsed["omega_setup"].value
        except (KeyError, http.cookies.CookieError):
            return None, None
        with self.lock:
            row = self.sessions.get(token)
            if row and row["expires"] > time.monotonic():
                return token, row
        return None, None

    def error_message(self, error, fallback):
        # Only these local helpers define errors whose text is safe to show.
        known_errors = [SetupError]
        for name in ("setup_module", "mirror_module"):
            error_type = getattr(getattr(self.appliance, name, None), "SetupError", None)
            if isinstance(error_type, type) and issubclass(error_type, Exception):
                known_errors.append(error_type)
        return str(error) if isinstance(error, tuple(known_errors)) else fallback

    def submit(self, owner, action, body):
        if not self.operation.acquire(blocking=False):
            return 409, {"error": "Another setup operation is running. Wait for it to finish."}
        with self.lock:
            now = time.monotonic()
            self.jobs = {key: job for key, job in self.jobs.items() if job["expires"] > now}
            if len(self.jobs) >= 32:
                self.jobs.pop(next(iter(self.jobs)))
            job_id = secrets.token_hex(16)
            self.jobs[job_id] = {"owner": owner, "state": "pending", "action": action, "expires": now + SESSION_SECONDS}

        def work():
            try:
                if action == "check":
                    result = self.appliance.check(body["config"])
                elif action == "configure":
                    result = self.appliance.configure(body)
                elif action == "manager/configure":
                    result = self.appliance.configure_manager(body)
                else:
                    result = getattr(self.appliance, action)()
                update = {"state": "complete", "result": result}
            except Exception as exc:
                message = self.error_message(exc,
                    "Setup could not finish. Check source access, manager connectivity, service accounts, and available storage; then retry.")
                update = {"state": "failed", "error": message}
            finally:
                body.clear()  # Passwords never enter job records, disk, or logs.
                self.operation.release()
            with self.lock:
                self.jobs[job_id].update(update)
        # Finish an in-flight configuration transaction when the listener closes.
        threading.Thread(target=work, daemon=False, name="omega-setup-operation").start()
        return 202, {"job_id": job_id}

    def job(self, owner, job_id):
        with self.lock:
            row = self.jobs.get(job_id)
            if not row or row["owner"] != owner or row["expires"] <= time.monotonic():
                return 404, {"error": "Setup result expired or belongs to another session."}
            return 200, copy.deepcopy({key: value for key, value in row.items() if key not in ("owner", "expires")})


def handler_for(app):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass

        def reply(self, code, body, mime="application/json", cookie=None, download=None):
            raw = json.dumps(body).encode() if mime == "application/json" else body
            try:
                self.send_response(code)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                if download:
                    self.send_header("Content-Disposition", 'attachment; filename="' + download + '"')
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def valid_host(self):
            port = self.server.server_port
            return len(self.headers.get_all("Host", [])) == 1 and self.headers["Host"] in {f"127.0.0.1:{port}", f"localhost:{port}"}

        def do_GET(self):
            if not self.valid_host():
                return self.reply(403, {"error": "Unrecognized setup host."})
            owner, session = app.session(self.headers.get("Cookie", ""))
            if self.path == "/api/status":
                result = {"authenticated": bool(session), "demo": app.appliance.demo}
                if session:
                    try:
                        result.update(app.appliance.status())
                        result["csrf"] = session["csrf"]
                        with app.lock:
                            result["operations"] = {key: row["action"] for key, row in app.jobs.items() if row["owner"] == owner and row["state"] == "pending"}
                    except Exception:
                        return self.reply(503, {"error": "Appliance prerequisites are unavailable. Check the local setup installation."})
                return self.reply(200, result)
            if self.path.startswith("/api/"):
                if not session:
                    return self.reply(401, {"error": "Pair with the appliance before continuing."})
                if re.fullmatch(r"/api/jobs/[0-9a-f]{32}", self.path):
                    return self.reply(*app.job(owner, self.path.rsplit("/", 1)[-1]))
                if self.path == "/api/manager/guide":
                    path = Path(__file__).parent / "wazuh-manager-setup.md"
                    if not path.exists():
                        path = Path(__file__).resolve().parents[1] / "docs/wazuh-manager-setup.md"
                    try:
                        return self.reply(200, path.read_bytes(), "text/markdown; charset=utf-8", download="OMEGA-manager-setup.md")
                    except OSError:
                        return self.reply(503, {"error": "Manager guide is missing from this installation."})
                return self.reply(404, {"error": "Not found."})
            assets = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}
            if self.path not in assets:
                return self.reply(404, {"error": "Not found."})
            name, mime = assets[self.path]
            try:
                self.reply(200, (STATIC / name).read_bytes(), mime)
            except OSError:
                self.reply(503, {"error": "Setup interface is missing from this installation."})

        def do_POST(self):
            if (not self.valid_host() or len(self.headers.get_all("Origin", [])) != 1
                    or self.headers["Origin"] != "http://" + self.headers["Host"]):
                return self.reply(403, {"error": "A same-origin setup request is required."})
            if self.headers.get("Content-Type") != "application/json":
                return self.reply(415, {"error": "JSON required."})
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                return self.reply(400, {"error": "Invalid request length."})
            try:
                size = int(self.headers["Content-Length"])
                if not 0 < size <= MAX_BODY:
                    raise ValueError()
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError()
                body = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_json)
                if not isinstance(body, dict):
                    raise ValueError()
            except (ValueError, OSError, RecursionError):
                return self.reply(400, {"error": "Invalid setup request."})
            if self.path == "/api/pair":
                if set(body) != {"code"}:
                    return self.reply(400, {"error": "Enter the pairing code."})
                code, result, token = app.pair(body["code"])
                cookie = f"omega_setup={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}" if token else None
                return self.reply(code, result, cookie=cookie)
            owner, session = app.session(self.headers.get("Cookie", ""))
            if not session:
                return self.reply(401, {"error": "Pair with the appliance before continuing."})
            csrf = self.headers.get("X-OMEGA-CSRF", "")
            if not hmac.compare_digest(csrf.encode("utf-8"), session["csrf"].encode("utf-8")):
                return self.reply(403, {"error": "Refresh the setup page before retrying."})
            paths = {"/api/check": {"config"}, "/api/configure": {"config", "password", "password_confirm"},
                     "/api/manager/configure": {"host", "user", "port", "host_key"},
                     "/api/activate": set(), "/api/verify": set(), "/api/manager/identity": set()}
            if self.path not in paths:
                return self.reply(404, {"error": "Not found."})
            if set(body) != paths[self.path]:
                return self.reply(400, {"error": "Review the setup fields and try again."})
            if "config" in body and not isinstance(body["config"], dict):
                return self.reply(400, {"error": "Review the appliance settings."})
            if self.path == "/api/manager/identity":
                if not app.operation.acquire(blocking=False):
                    return self.reply(409, {"error": "Wait for the current setup operation."})
                try:
                    response = (200, app.appliance.identity())
                except Exception as exc:
                    response = (409, {"error": app.error_message(exc,
                        "Could not prepare a fresh manager identity. Check the local installation and existing setup state.")})
                finally:
                    app.operation.release()
                return self.reply(*response)
            return self.reply(*app.submit(owner, self.path.removeprefix("/api/"), body))
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="Simulate setup without reading or changing an appliance")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Use a loopback port between 1024 and 65535.")
    appliance = DemoAppliance() if args.demo else Appliance()
    app = Application(appliance, code="OMEGA-PREVIEW" if args.demo else None)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(app))
    server.daemon_threads = True
    expiry = threading.Timer(90 * 60, server.shutdown)
    expiry.daemon = True
    expiry.start()
    # Display once to the invoking owner. Never put the code in a URL or HTTP log.
    print(f"OMEGA {'preview' if args.demo else 'owner setup'}: http://127.0.0.1:{args.port}", flush=True)
    print(f"Pairing code (one use, 30 minutes): {app.code}", flush=True)
    print("Keep this terminal open. Setup closes after 90 minutes; press Ctrl+C when finished. Use an authenticated SSH tunnel for access from another computer.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        expiry.cancel()
        server.server_close()


if __name__ == "__main__":
    main()
