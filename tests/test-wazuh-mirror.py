#!/usr/bin/python3
"""Disposable filesystem tests. No manager, appliance, or system service changes."""
from __future__ import annotations

import base64
import datetime as dt
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard"))
import wazuh_mirror as M
from telemetry_store import TelemetryStore

loader = importlib.machinery.SourceFileLoader("mirror_provisioning", str(ROOT / "image/rootfs-overlay/usr/libexec/omega/configure-wazuh-mirror"))
spec = importlib.util.spec_from_loader(loader.name, loader)
P = importlib.util.module_from_spec(spec)
loader.exec_module(P)
KEY = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()
CONFIG = {"host": "manager.example.test", "user": "omega-reader", "port": 22, "host_key": KEY}


class ValidationTests(unittest.TestCase):
    def test_valid_addresses(self):
        for host in ("manager.example.test", "192.0.2.3", "2001:db8::12", "WAZUH"):
            self.assertTrue(M.validate_config(dict(CONFIG, host=host))["host"])

    def test_host_command_injection(self):
        for host in ("-oProxyCommand=touch /tmp/pwn", "manager;id", "$(id)", "`id`", "manager\nUser root",
                     "user@manager", "manager:22", "127.0.0.999", "a..b", "a/b", "fe80::1%eth0"):
            with self.subTest(host=host), self.assertRaises(M.MirrorError):
                M.validate_config(dict(CONFIG, host=host))

    def test_user_command_injection(self):
        for user in ("root", "-root", "user@x", "a;id", "a b", "$(id)", "a\n"):
            with self.subTest(user=user), self.assertRaises(M.MirrorError):
                M.validate_config(dict(CONFIG, user=user))

    def test_ports(self):
        for port in (0, 65536, True, "22", -1, 22.5):
            with self.subTest(port=port), self.assertRaises(M.MirrorError):
                M.validate_config(dict(CONFIG, port=port))

    def test_strict_host_keys(self):
        for key in (KEY + "\n", "@cert-authority " + KEY, "restrict " + KEY, "ssh-rsa AAAA",
                    "ssh-ed25519 AAAA", "ssh-ed25519 !!!", KEY + " comment extra"):
            with self.subTest(key=key), self.assertRaises(M.MirrorError):
                M.public_key(key)
        self.assertEqual(M.public_key(KEY + " manager")[0], KEY)

    def test_duplicate_and_extra_settings(self):
        with self.assertRaises(M.MirrorError):
            M.parse_json('{"host":"a","host":"b"}')
        with self.assertRaises(M.MirrorError):
            M.validate_config(dict(CONFIG, command="anything"))

    def test_ssh_binding_no_agent(self):
        arguments = M.ssh_command(CONFIG, Path(M.STATE))
        for option in ("StrictHostKeyChecking=yes", "IdentityAgent=none", "IdentitiesOnly=yes",
                       "GlobalKnownHostsFile=/dev/null", "HostKeyAlias=omega-wazuh-manager",
                       "HostKeyAlgorithms=ssh-ed25519", "UpdateHostKeys=no", "BatchMode=yes"):
            self.assertIn(option, arguments)
        self.assertEqual(arguments[1:3], ["-F", "/dev/null"])
        self.assertIn(KEY, M.known_hosts(CONFIG))

    def test_fixed_readonly_remote_paths(self):
        command = M.rsync_command(CONFIG, Path(M.STATE), Path("/tmp/stage"), "alerts", basis=Path("/tmp/published"))
        self.assertEqual(command[-2], "omega-wazuh-manager:alerts/")
        for prohibited in ("--inplace", "--append", "--delete", "--copy-links", "--protect-args", "--remove-source-files"):
            self.assertNotIn(prohibited, command)
        self.assertIn("--copy-dest=/tmp/published", command)
        self.assertEqual(shlex.split(command[command.index("-e") + 1])[0], "/usr/bin/ssh")
        with self.assertRaises(M.MirrorError):
            M.rsync_command(CONFIG, Path(M.STATE), Path("/tmp/stage"), "../../etc")


class MirrorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="omega-mirror-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.destination = self.root / "published"
        self.cache = self.root / "cache"
        self.cache.mkdir(mode=0o700)
        for name in M.SOURCES:
            (self.destination / name).mkdir(parents=True, mode=0o750)
        self.content = {"alerts": b'{"id":"1"}\n', "archives": b'{"id":"2"}\n'}
        self.calls = []

    def runner(self, command, timeout):
        self.calls.append((command, timeout))
        source = command[-2].split(":")[1].strip("/")
        target = Path(command[-1])
        (target / (source + ".json")).write_bytes(self.content[source])
        return subprocess.CompletedProcess(command, 0)

    def sync(self, runner=None):
        return M.sync_once(CONFIG, self.root / "private", self.destination, cache=self.cache,
                           runner=runner or self.runner,
                           disk_usage=lambda _: shutil._ntuple_diskusage(10**12, 0, 10**12))

    def test_two_sources_complete_and_heartbeat_atomic(self):
        value = self.sync()
        self.assertTrue(all(row["ok"] for row in value["sources"].values()))
        self.assertEqual(json.loads((self.destination / "sync-status.json").read_text()), value)
        self.assertEqual(stat.S_IMODE((self.destination / "sync-status.json").stat().st_mode), 0o640)
        self.assertEqual(len(list(self.cache.iterdir())), 0)

    def test_append_preserves_inode_and_unchanged_transfer(self):
        self.sync()
        active = self.destination / "alerts/alerts.json"
        inode = active.stat().st_ino
        self.sync()
        self.assertEqual(active.stat().st_ino, inode)
        self.content["alerts"] += b'{"id":"3"}\n'
        self.sync()
        self.assertEqual(active.stat().st_ino, inode)
        self.assertEqual(active.read_bytes(), self.content["alerts"])
        self.assertFalse(list(active.parent.glob("*.omega-*")))

    def test_rotation_keeps_unread_old_bytes(self):
        self.sync()
        active = self.destination / "alerts/alerts.json"
        original = active.read_bytes()
        old_inode = active.stat().st_ino
        self.content["alerts"] = b'{"id":"new"}\n'
        self.sync()
        preserved = list(active.parent.glob("alerts.json.omega-*.json"))
        self.assertEqual(len(preserved), 1)
        self.assertEqual(preserved[0].read_bytes(), original)
        self.assertEqual(preserved[0].stat().st_ino, old_inode)
        self.assertEqual(active.read_bytes(), self.content["alerts"])

    def test_failure_never_publishes_staged_partial_data(self):
        self.sync()
        original = (self.destination / "alerts/alerts.json").read_bytes()
        def failed(command, timeout):
            self.runner(command, timeout)
            (Path(command[-1]) / "alerts.json").write_bytes(b"partial corrupt transfer")
            return subprocess.CompletedProcess(command, 23)
        result = self.sync(failed)
        self.assertFalse(result["sources"]["alerts"]["ok"])
        self.assertEqual((self.destination / "alerts/alerts.json").read_bytes(), original)

    def test_remote_active_absent_does_not_reuse_stale_local(self):
        self.sync()
        result = self.sync(lambda command, timeout: subprocess.CompletedProcess(command, 0))
        self.assertFalse(result["sources"]["alerts"]["ok"])
        self.assertEqual(result["sources"]["alerts"]["error"], "source_unreadable")

    def test_timeout_writes_failure_and_attempts_other_source(self):
        calls = []
        def timeout(command, timeout):
            calls.append(command)
            raise subprocess.TimeoutExpired(command, timeout)
        result = self.sync(timeout)
        self.assertEqual(len(calls), 2)
        self.assertEqual({row["error"] for row in result["sources"].values()}, {"timeout"})
        self.assertTrue(result["checked_at"])
        self.assertTrue(self.sync()["sources"]["alerts"]["ok"])

    def test_low_space_fails_before_transfer(self):
        value = M.sync_once(CONFIG, self.root, self.destination, cache=self.cache, runner=self.runner,
                            disk_usage=lambda _: shutil._ntuple_diskusage(1, 1, 0))
        self.assertEqual(self.calls, [])
        self.assertTrue(all(row["error"] == "low_space" for row in value["sources"].values()))

    def test_retained_nested_rotation_survives_next_transfer(self):
        def rotated(command, timeout):
            self.runner(command, timeout)
            nested = Path(command[-1]) / "2026/Sep"
            nested.mkdir(parents=True)
            (nested / "ossec-alerts-14.json.gz").write_bytes(b"rotation fixture")
            return subprocess.CompletedProcess(command, 0)
        self.sync(rotated)
        rotation = self.destination / "alerts/2026/Sep/ossec-alerts-14.json.gz"
        self.sync()
        self.assertEqual(rotation.read_bytes(), b"rotation fixture")

    def test_symlink_stage_rejected(self):
        def symlink(command, timeout):
            source = command[-2].split(":")[1].strip("/")
            (Path(command[-1]) / (source + ".json")).symlink_to("/etc/passwd")
            return subprocess.CompletedProcess(command, 0)
        self.assertFalse(self.sync(symlink)["sources"]["alerts"]["ok"])

    def test_actual_rsync_local_transfer_and_copy_basis(self):
        source = self.root / "local-fixture"
        source.mkdir()
        (source / "alerts.json").write_bytes(self.content["alerts"])
        first = self.root / "first"
        first.mkdir()
        command = M.rsync_command(CONFIG, self.root, first, "alerts")
        command[-2] = str(source) + "/"
        result = M.bounded_run(command, timeout=10)
        self.assertEqual(result.returncode, 0)
        M.publish_tree(first, self.destination / "alerts", "alerts")
        second = self.root / "second"
        second.mkdir()
        command = M.rsync_command(CONFIG, self.root, second, "alerts", basis=self.destination / "alerts")
        command[-2] = str(source) + "/"
        self.assertEqual(M.bounded_run(command, timeout=10).returncode, 0)
        self.assertEqual((second / "alerts.json").read_bytes(), self.content["alerts"])
        self.assertNotEqual((second / "alerts.json").stat().st_ino,
                            (self.destination / "alerts/alerts.json").stat().st_ino)

    def test_bounded_process_timeout(self):
        start = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            M.bounded_run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05)
        self.assertLess(time.monotonic() - start, 2)

    def test_only_one_connector_can_hold_runtime_lock(self):
        path = self.root / "connector.lock"
        first = M.acquire_lock(path)
        try:
            with self.assertRaises(BlockingIOError):
                M.acquire_lock(path)
        finally:
            os.close(first)
        os.close(M.acquire_lock(path))

    def test_real_collector_does_not_replay_appended_or_unchanged_records(self):
        def event(number):
            # No Wazuh id: this exercises inode/offset identity, not id dedup.
            return (json.dumps({"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                                "agent": {"id": "007"}, "rule": {"level": 7, "description": str(number)}}) + "\n").encode()
        self.content["alerts"] = event(1)
        self.sync()
        store = TelemetryStore(self.root / "telemetry.sqlite3", wazuh_alerts_path=self.destination / "alerts/alerts.json")
        self.addCleanup(store.close)
        self.assertEqual(store.poll()["events"], 1)
        self.sync()
        unchanged = store.poll()
        self.assertEqual(unchanged["events"], 1)
        self.assertEqual(unchanged["sources"][1]["total_records"], 1)
        self.content["alerts"] += event(2)
        self.sync()
        appended = store.poll()
        self.assertEqual(appended["events"], 2)
        self.assertEqual(appended["sources"][1]["total_records"], 2)
        self.content["alerts"] += event(3)
        self.sync()  # Collector is offline for this tail.
        self.content["alerts"] = event(4)
        self.sync()  # Old unconsumed tail must survive replacement.
        rotated = store.poll()
        self.assertEqual(rotated["events"], 4)
        self.assertEqual(rotated["sources"][1]["total_records"], 4)


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="omega-mirror-setup-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for directory in ("run", "var/lib", "usr/bin", "usr/lib/systemd/system", "etc/omega"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        for name in ("usr/bin/ssh", "usr/bin/rsync", "usr/lib/systemd/system/" + P.UNIT):
            path = self.root / name
            path.write_text("fixture")
            path.chmod(0o755)
        self.calls = []
        self.account = {"uid": os.geteuid(), "gid": os.getegid(), "telemetry_gid": os.getegid()}
        self.provisioner = P.Provisioner(self.root, runner=self.runner, account_lookup=lambda: self.account)

    def runner(self, command, **kwargs):
        self.calls.append(command)
        if command[0] == "/usr/bin/ssh-keygen":
            return subprocess.run(command, **kwargs)
        return subprocess.CompletedProcess(command, 3 if "is-active" in command else 0)

    def test_real_device_key_generated_once_and_private(self):
        first = self.provisioner.identity()
        second = self.provisioner.identity()
        self.assertEqual(first, second)
        self.assertTrue(first["fingerprint"].startswith("SHA256:"))
        self.assertEqual(sum(call[0] == "/usr/bin/ssh-keygen" for call in self.calls), 1)
        state = self.root / M.STATE.lstrip("/")
        for name in ("id_ed25519", "id_ed25519.pub"):
            self.assertEqual(stat.S_IMODE((state / name).stat().st_mode), 0o600)

    def test_configuration_enables_only_fixed_service_once(self):
        result = self.provisioner.configure(CONFIG)
        self.assertTrue(result["configured"])
        self.assertFalse(result["ready"])
        state = self.root / M.STATE.lstrip("/")
        self.assertEqual(json.loads((state / "config.json").read_text()), CONFIG)
        self.assertEqual((state / "known_hosts").read_text(), M.known_hosts(CONFIG))
        self.assertIn(["/usr/bin/systemctl", "enable", "--now", P.UNIT], self.calls)
        self.provisioner.configure(CONFIG)
        self.assertEqual(sum("enable" in call for call in self.calls), 2)
        self.assertEqual(sum(call[0] == "/usr/bin/ssh-keygen" for call in self.calls), 1)

    def test_existing_deployment_never_gets_identity(self):
        (self.root / "etc/omega/dashboard.ready").write_text("existing")
        with self.assertRaises(M.MirrorError):
            self.provisioner.identity()
        self.assertEqual(self.calls, [])

    def test_existing_import_history_refused(self):
        (self.root / M.IMPORT.lstrip("/")).mkdir()
        with self.assertRaises(M.MirrorError):
            self.provisioner.configure(CONFIG)

    def test_incomplete_identity_not_regenerated(self):
        (self.root / M.STATE.lstrip("/")).mkdir(mode=0o700)
        with self.assertRaises(OSError):
            self.provisioner.identity()
        self.assertEqual(self.calls, [])

    def test_symlink_identity_root_rejected(self):
        (self.root / M.STATE.lstrip("/")).symlink_to(self.root / "var/lib", target_is_directory=True)
        with self.assertRaises(OSError):
            self.provisioner.identity()

    def test_status_fresh_stale_and_failed(self):
        self.provisioner.configure(CONFIG)
        heartbeat = self.root / M.IMPORT.lstrip("/") / "sync-status.json"
        value = {"checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                 "sources": {name: {"ok": True} for name in M.SOURCES}}
        heartbeat.write_text(json.dumps(value))
        self.assertTrue(self.provisioner.status()["ready"])
        value["checked_at"] = "2000-01-01T00:00:00+00:00"
        heartbeat.write_text(json.dumps(value))
        self.assertFalse(self.provisioner.status()["ready"])
        value["checked_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        value["sources"]["archives"]["ok"] = False
        heartbeat.write_text(json.dumps(value))
        self.assertFalse(self.provisioner.status()["ready"])

    def test_start_failure_preserves_identity_and_settings(self):
        original = self.runner
        self.provisioner.runner = lambda command, **kwargs: (subprocess.CompletedProcess(command, 1)
            if "enable" in command else original(command, **kwargs))
        value = self.provisioner.configure(CONFIG)
        self.assertTrue(value["configured"])
        self.assertIn("activation failed", value["message"])
        self.assertTrue(self.provisioner.identity()["public_key"])

    def test_setup_correction_preserves_key_and_mirrored_evidence(self):
        self.provisioner.configure(CONFIG)
        state = self.root / M.STATE.lstrip("/")
        original_key = (state / "id_ed25519").read_bytes()
        evidence = self.root / M.IMPORT.lstrip("/") / "alerts/alerts.json"
        evidence.write_bytes(b'{"retained":"evidence"}\n')
        corrected = dict(CONFIG, host="192.0.2.11", port=2222)
        self.provisioner.configure(corrected)
        self.assertEqual(json.loads((state / "config.json").read_text()), corrected)
        self.assertEqual((state / "known_hosts").read_text(), M.known_hosts(corrected))
        self.assertEqual((state / "id_ed25519").read_bytes(), original_key)
        self.assertEqual(evidence.read_bytes(), b'{"retained":"evidence"}\n')
        self.assertIn(["/usr/bin/systemctl", "stop", P.UNIT], self.calls)

    def test_deployed_dashboard_connection_cannot_be_corrected(self):
        self.provisioner.configure(CONFIG)
        (self.root / "etc/omega/dashboard.ready").write_text("deployed")
        before = list(self.calls)
        with self.assertRaises(M.MirrorError):
            self.provisioner.configure(dict(CONFIG, host="other.test"))
        self.assertEqual(self.calls, before)

    def test_unrecognized_private_state_cannot_be_corrected(self):
        self.provisioner.configure(CONFIG)
        (self.root / M.STATE.lstrip("/") / "unrelated").write_text("retain")
        with self.assertRaises(M.MirrorError):
            self.provisioner.configure(dict(CONFIG, host="other.test"))

    def test_verified_host_key_correction_clears_prior_readiness(self):
        self.provisioner.configure(CONFIG)
        state = self.root / M.STATE.lstrip("/")
        key_before = (state / "id_ed25519").read_bytes()
        heartbeat = self.root / M.IMPORT.lstrip("/") / "sync-status.json"
        heartbeat.write_text(json.dumps({"checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                             "sources": {name: {"ok": True} for name in M.SOURCES}}))
        replacement = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(reversed(range(32)))).decode()
        corrected = dict(CONFIG, host_key=replacement)
        result = self.provisioner.configure(corrected)
        self.assertFalse(result["ready"])
        self.assertEqual((state / "known_hosts").read_text(), M.known_hosts(corrected))
        self.assertEqual((state / "id_ed25519").read_bytes(), key_before)

    def test_correction_write_failure_rolls_back_pair_and_keeps_service_stopped(self):
        self.provisioner.configure(CONFIG)
        original = P.atomic_write
        failed = False
        def failing(path, *args, **kwargs):
            nonlocal failed
            if Path(path).name == "config.json" and not failed:
                failed = True
                raise OSError("test write failure")
            return original(path, *args, **kwargs)
        with mock.patch.object(P, "atomic_write", side_effect=failing), self.assertRaises(M.MirrorError):
            self.provisioner.configure(dict(CONFIG, host="other.test"))
        state = self.root / M.STATE.lstrip("/")
        self.assertEqual(json.loads((state / "config.json").read_text()), CONFIG)
        self.assertEqual((state / "known_hosts").read_text(), M.known_hosts(CONFIG))
        self.assertEqual(self.calls[-1], ["/usr/bin/systemctl", "stop", P.UNIT])


if __name__ == "__main__":
    unittest.main()
