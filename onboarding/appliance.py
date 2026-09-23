"""Fixed local operations exposed by the short-lived owner setup interface."""
from __future__ import annotations

import copy
import hashlib
import http.cookiejar
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib import request


ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = {
    "OMEGA_AI_MODEL": "qwen3:1.7b", "OMEGA_AI_THREADS": 2,
    "OMEGA_SURICATA_EVE": "/var/log/suricata/eve.json",
    "OMEGA_PIHOLE_DATABASE": "/var/lib/omega/pihole/etc-pihole/pihole-FTL.db",
    "OMEGA_WAZUH_ALERTS": "/var/lib/omega-wazuh-import/alerts/alerts.json",
    "OMEGA_WAZUH_ARCHIVES": "/var/lib/omega-wazuh-import/archives/archives.json",
    "OMEGA_WAZUH_SYNC_STATUS": "/var/lib/omega-wazuh-import/sync-status.json",
    "OMEGA_RETENTION_DAYS": 3650, "OMEGA_MAX_EVENTS": 50000000,
}
UNITS = ("omega-ai.service", "omega-dashboard.service")


class SetupError(ValueError):
    """An intentionally owner-readable error, with no private input values."""


def load_helper(name):
    path = Path("/usr/libexec/omega") / name
    if not path.exists():
        path = ROOT / "image/rootfs-overlay/usr/libexec/omega" / name
        if name == "configure-wazuh-mirror":
            # Source-checkout development only; the packaged mirror is beside us.
            sys.path.insert(0, str(ROOT / "dashboard"))
    loader = importlib.machinery.SourceFileLoader("omega_" + name.replace("-", "_"), str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def config_digest(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class DashboardClient:
    """Owner-authenticated, loopback-only acceptance checks; no proxy or redirect."""
    def __init__(self, password):
        self.opener = request.build_opener(request.ProxyHandler({}), NoRedirect(),
                                          request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.call("/api/login", {"password": password})

    def call(self, path, body=None):
        if not (path in ("/api/login", "/api/logout", "/api/overview", "/api/assistant")
                or re.fullmatch(r"/api/assistant/jobs/[0-9a-f]{32}", path)):
            raise SetupError("Unsupported local verification operation.")
        headers = {"Accept": "application/json", "Origin": "http://127.0.0.1:8089"}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request("http://127.0.0.1:8089" + path, data=data, headers=headers)
        with self.opener.open(req, timeout=10) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise SetupError("The local verification response was too large.")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise SetupError("The local verification response was invalid.")
        return result

    def close(self):
        try:
            self.call("/api/logout", {})
        except (OSError, ValueError):
            pass


def source_verification(before, after):
    """Require new records during this check; retained history is insufficient."""
    old = {row["id"]: row for row in before.get("sources", [])}
    new = {row["id"]: row for row in after.get("sources", [])}
    mode_ok = after.get("coverage", {}).get("collection_mode") == "from_now"
    same_boundary = bool(before.get("coverage", {}).get("collection_started")) and (
        before["coverage"]["collection_started"] == after.get("coverage", {}).get("collection_started"))
    result = {}
    for name, streams in (("suricata", ("suricata",)), ("pihole", ("pihole",)),
                          ("wazuh", ("wazuh_alerts", "wazuh_archives"))):
        def unique_count(row):
            return row.get("total_records", 0) - row.get("duplicate_records", 0)
        deltas = [unique_count(new.get(key, {})) - unique_count(old.get(key, {})) for key in streams]
        raw_deltas = [new.get(key, {}).get("total_records", 0) - old.get(key, {}).get("total_records", 0) for key in streams]
        current = all(new.get(key, {}).get("available") is True and new[key].get("caught_up") is True
                      and new[key].get("sync_current", True) is True for key in streams)
        # One Wazuh observation may legitimately exist in both streams. Confirm
        # arrivals in both, with new unique evidence across their shared IDs.
        arrived = (all(delta > 0 for delta in raw_deltas) and sum(deltas) > 0) if name == "wazuh" else all(delta > 0 for delta in deltas)
        observed = mode_ok and same_boundary and current and arrived
        result[name] = {"status": "pass" if observed else "gap", "detail": (
            ("Both manager streams delivered records, including new Wazuh evidence across their shared event IDs."
             if name == "wazuh" else "New source records arrived during this check; the collector is current.")
            if observed else "Fresh records are not yet verified. Generate a known benign event, check source access, and run verification again."),
            "new_records": max(0, sum(deltas))}
    return result


class Appliance:
    demo = False

    def __init__(self):
        if os.geteuid() != 0:
            raise SetupError("Run start-setup with sudo on the appliance, or use --demo for a preview.")
        self.setup_module = load_helper("configure-dashboard")
        self.mirror_module = load_helper("configure-wazuh-mirror")
        self.checked = None
        self.verification = None

    def setup(self):
        return self.setup_module.Setup()

    def manager(self):
        return self.mirror_module.Provisioner()

    def phase(self):
        marker = Path(self.setup_module.READY)
        if not marker.exists():
            return "unconfigured"
        if marker.is_symlink() or not marker.is_file():
            raise SetupError("The appliance activation marker needs operator review.")
        return "active" if all(self.unit_active(unit) for unit in UNITS) else "configured"

    @staticmethod
    def unit_active(unit):
        result = subprocess.run(["/usr/bin/systemctl", "is-active", unit], capture_output=True,
                                text=True, timeout=5, check=False)
        return result.returncode == 0 and result.stdout.strip() == "active"

    def status(self):
        return {"phase": self.phase(), "defaults": copy.deepcopy(DEFAULTS),
                "manager": self.manager().status(), "verification": self.verification}

    def identity(self):
        if self.phase() != "unconfigured":
            raise SetupError("Existing installations retain their manager identity. Use the operator recovery process.")
        return self.manager().identity()

    def configure_manager(self, config):
        if self.phase() != "unconfigured":
            raise SetupError("Manager configuration is limited to an unused dashboard.")
        self.checked = None
        return self.manager().configure(config)

    def check(self, config):
        self.checked = None
        try:
            valid = self.setup().check(config)
        except self.setup_module.SetupError as exc:
            return {"ok": False, "checks": [{"name": "Appliance prerequisites", "status": "gap", "detail": str(exc)}]}
        self.checked = config_digest(valid)
        return {"ok": True, "checks": [{"name": "Appliance prerequisites", "status": "pass",
                "detail": "Private state, service accounts, source access, model integrity, and storage checks passed. Live collection and AI still need verification."}]}

    def configure(self, body):
        config = self.setup_module.validate_config(body["config"])
        if self.checked != config_digest(config):
            raise SetupError("Run the prerequisite check successfully with these settings before saving.")
        if body["password"] != body["password_confirm"]:
            raise SetupError("The passwords do not match.")
        self.setup().apply(config, body["password"])
        self.checked = None
        return {"ok": True, "phase": "configured", "detail": "Private configuration saved. Services await your activation."}

    def activate(self):
        if self.phase() == "unconfigured":
            raise SetupError("Save a valid first-use configuration before activation.")
        subprocess.run(["/usr/bin/systemctl", "enable", "--now", *UNITS],
                       capture_output=True, timeout=45, check=True)
        active = self.phase() == "active"
        return {"ok": active, "phase": "active" if active else "configured",
                "detail": "Services started. Verify new events and local AI next." if active
                else "Services have not both reached active state. Check the appliance service journal."}

    def verify(self):
        self.verification = None
        if self.phase() != "active":
            raise SetupError("Activate the dashboard and AI services before verification.")
        account = self.setup().accounts["omega-dashboard"][0]
        password = self.setup_module.read_small(Path(self.setup_module.PASSWORD), 4096, private_owner=account).decode("utf-8")
        client = DashboardClient(password)
        del password
        started = time.monotonic()
        try:
            before = client.call("/api/overview")
            if before.get("demo"):
                raise SetupError("A sample dashboard cannot verify a real appliance.")
            ai = {"status": "gap", "detail": "Local AI did not return a completed answer."}
            try:
                job = client.call("/api/assistant", {"question": "For this setup check, summarize the supplied sensor evidence, cite available alert references, and clearly state coverage limits. Do not claim full network coverage."})
                job_id = job.get("id", "")
                if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{32}", job_id):
                    raise SetupError("The local AI job could not be started.")
                deadline = started + 930
                while time.monotonic() < deadline:
                    result = client.call("/api/assistant/jobs/" + job_id)
                    if result.get("state") == "complete" and isinstance(result.get("answer"), str) and result["answer"].strip():
                        ai = {"status": "pass", "detail": "The installed local model returned a complete answer. This is one inference check, not a broad quality assessment."}
                        break
                    if result.get("state") == "failed":
                        break
                    time.sleep(3)
            except (OSError, ValueError):
                pass
            # Let a collector refresh even when inference fails immediately.
            remaining = 12 - (time.monotonic() - started)
            if remaining > 0:
                time.sleep(remaining)
            after = client.call("/api/overview")
            sources = source_verification(before, after)
            self.verification = {"ok": ai["status"] == "pass" and all(row["status"] == "pass" for row in sources.values()),
                                 "sources": sources, "ai": ai, "elapsed_seconds": round(time.monotonic() - started),
                                 "collection_started": after.get("coverage", {}).get("collection_started")}
            return self.verification
        finally:
            client.close()


class DemoAppliance:
    """UI simulation with no source reads, subprocesses, account or model access."""
    demo = True

    def __init__(self):
        self.current_phase = "unconfigured"
        self.checked = None
        self.manager_configured = False
        self.verification = None
        self.setup_module = load_helper("configure-dashboard")

    def status(self):
        return {"phase": self.current_phase, "defaults": copy.deepcopy(DEFAULTS), "manager": {
            "configured": self.manager_configured, "identity_ready": True, "ready": self.manager_configured,
            "message": "Preview connection only. No manager is contacted."}, "verification": self.verification}

    def identity(self):
        return {"public_key": "PREVIEW KEY — no SSH identity is generated", "fingerprint": "Preview only"}

    def configure_manager(self, config):
        if self.current_phase != "unconfigured" or set(config) != {"host", "user", "port", "host_key"}:
            raise SetupError("Review the manager settings before continuing.")
        if not all(isinstance(config[key], str) and config[key].strip() for key in ("host", "user", "host_key")) or type(config["port"]) is not int or not 1 <= config["port"] <= 65535:
            raise SetupError("Complete the manager address, login, port, and verified host key.")
        self.manager_configured = True
        self.checked = None
        return self.status()["manager"]

    def check(self, config):
        if self.current_phase != "unconfigured":
            raise SetupError("Preview is already configured. Restart the preview for another setup.")
        valid = self.setup_module.validate_config(config)
        self.checked = config_digest(valid)
        return {"ok": True, "checks": [{"name": "Preview prerequisites", "status": "pass", "detail": "Simulated result. No appliance or model was checked."}]}

    def configure(self, body):
        valid = self.setup_module.validate_config(body["config"])
        if self.current_phase != "unconfigured" or self.checked != config_digest(valid):
            raise SetupError("Check these settings before saving the preview.")
        self.setup_module.check_password(body["password"])
        if body["password"] != body["password_confirm"]:
            raise SetupError("The passwords do not match.")
        self.current_phase = "configured"
        self.checked = None
        return {"ok": True, "phase": "configured", "detail": "Preview only. No password was saved."}

    def activate(self):
        if self.current_phase == "unconfigured":
            raise SetupError("Finish the preview configuration before activation.")
        self.current_phase = "active"
        return {"ok": True, "phase": "active", "detail": "Preview only. No services were started."}

    def verify(self):
        self.verification = None
        if self.current_phase != "active":
            raise SetupError("Activate the preview before verification.")
        row = {"status": "pass", "detail": "Simulated result. No live source or model was checked."}
        self.verification = {"ok": True, "demo": True, "sources": {name: dict(row) for name in ("suricata", "pihole", "wazuh")}, "ai": dict(row)}
        return self.verification
