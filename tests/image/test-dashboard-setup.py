#!/usr/bin/python3
"""First-use setup checks against a disposable filesystem, never the appliance."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "image/rootfs-overlay/usr/libexec/omega/configure-dashboard"
loader = importlib.machinery.SourceFileLoader("omega_dashboard_setup", str(HELPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
setup_module = importlib.util.module_from_spec(spec)
loader.exec_module(setup_module)
M = setup_module


class SetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="omega-setup-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = {
            "OMEGA_AI_MODEL": "qwen3:1.7b", "OMEGA_AI_THREADS": 2,
            "OMEGA_SURICATA_EVE": "/var/log/suricata/eve.json",
            "OMEGA_PIHOLE_DATABASE": "/var/lib/omega/pihole/etc-pihole/pihole-FTL.db",
            "OMEGA_WAZUH_ALERTS": "/var/lib/omega-wazuh-import/alerts/alerts.json",
            "OMEGA_WAZUH_ARCHIVES": "/var/lib/omega-wazuh-import/archives/archives.json",
            "OMEGA_WAZUH_SYNC_STATUS": "/var/lib/omega-wazuh-import/sync-status.json",
            "OMEGA_RETENTION_DAYS": 3650, "OMEGA_MAX_EVENTS": 50000000,
        }
        self.identity = (os.geteuid(), os.getegid(), [os.getegid()])
        self.accounts = {name: self.identity for name in ("omega-dashboard", "omega-ai")}
        self.probes = []
        self.setup = self.make_setup()
        self.path("/etc/omega").mkdir(parents=True)
        for name in M.APP_FILES:
            self.write("/opt/omega-dashboard/" + name, b"application fixture\n")
        for unit in ("omega-dashboard.service", "omega-ai.service"):
            self.write("/usr/lib/systemd/system/" + unit, b"[Unit]\nDescription=Fixture\n")
        runtime = b"offline runtime fixture"
        self.write(M.RUNTIME, runtime, 0o755)
        library = b"offline runtime library fixture"
        self.write(M.RUNTIME_ROOT + "/lib/ollama/libggml.so.0", library, 0o644)
        self.path(M.RUNTIME_ROOT + "/lib/ollama/libggml.so").symlink_to("libggml.so.0")
        blobs = []
        for data in (b"configuration fixture", b"model weights fixture"):
            blob = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            self.write(M.MODEL_ROOT + "/blobs/sha256-" + blob["sha256"], data)
            blobs.append(blob)
        content = {"schemaVersion": 2, "config": {"digest": "sha256:" + blobs[0]["sha256"], "size": blobs[0]["size"]},
                   "layers": [{"digest": "sha256:" + blobs[1]["sha256"], "size": blobs[1]["size"]}]}
        manifest_data = json.dumps(content).encode()
        manifest_path = "manifests/registry.ollama.ai/library/qwen3/1.7b"
        self.write(M.MODEL_ROOT + "/" + manifest_path, manifest_data)
        self.lock = {"schema": "omega-ai-payload-v1", "runtime": {"version": "0.33.3", "members": [
            {"path": "bin/ollama", "type": "file", "mode": "0755", "size": len(runtime),
             "sha256": hashlib.sha256(runtime).hexdigest()},
            {"path": "lib/ollama/libggml.so.0", "type": "file", "mode": "0644", "size": len(library),
             "sha256": hashlib.sha256(library).hexdigest()},
            {"path": "lib/ollama/libggml.so", "type": "symlink", "target": "libggml.so.0"}]},
            "model": {"tag": "qwen3:1.7b", "manifest": {"path": manifest_path, "size": len(manifest_data),
                       "sha256": hashlib.sha256(manifest_data).hexdigest()}, "blobs": blobs}}
        self.write_lock()
        for key in ("OMEGA_SURICATA_EVE", "OMEGA_WAZUH_ALERTS", "OMEGA_WAZUH_ARCHIVES"):
            self.write(self.config[key], b'{"event":"benign fixture"}\n', 0o640)
        database = self.path(self.config["OMEGA_PIHOLE_DATABASE"])
        database.parent.mkdir(parents=True)
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE query_storage(id INTEGER)")
        database.chmod(0o640)
        self.write_heartbeat()
        for path in self.root.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)

    def make_setup(self, **kwargs):
        return M.Setup(self.root, accounts=self.accounts,
                       probe=kwargs.pop("probe", lambda identity, paths: self.probes.append((identity, paths))), **kwargs)

    def path(self, absolute):
        return self.root / absolute.lstrip("/")

    def write(self, absolute, data, mode=0o644):
        path = self.path(absolute)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def write_lock(self):
        self.write("/usr/share/omega/ai/manifest.json", json.dumps(self.lock).encode())

    def write_heartbeat(self, age=0, ok=True):
        timestamp = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=age)
        self.write(self.config["OMEGA_WAZUH_SYNC_STATUS"], json.dumps({"checked_at": timestamp.isoformat(),
                   "sources": {"alerts": {"ok": ok}, "archives": {"ok": ok}}}).encode(), 0o640)

    def snapshot(self):
        return {str(path.relative_to(self.root)): (os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None,
                stat.S_IMODE(path.lstat().st_mode), path.lstat().st_ino) for path in self.root.rglob("*")}

    def assert_no_setup(self):
        self.assertFalse(self.path(M.ENV).exists())
        self.assertFalse(self.path(M.PASSWORD).exists())
        self.assertFalse(self.path(M.READY).exists())

    def test_check_reads_all_prerequisites_without_mutation(self):
        before = self.snapshot()
        self.assertEqual(self.setup.check(self.config), self.config)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(self.probes), 2)
        sources = {path for path, read_only in self.probes[0][1] if read_only}
        self.assertEqual(sources, {self.path(self.config[key]) for key in (
            "OMEGA_SURICATA_EVE", "OMEGA_PIHOLE_DATABASE", "OMEGA_WAZUH_ALERTS",
            "OMEGA_WAZUH_ARCHIVES", "OMEGA_WAZUH_SYNC_STATUS")})
        self.assertIn((self.path(M.RUNTIME), False, True), self.probes[1][1])
        self.assertIn((self.path(M.RUNTIME_ROOT + "/lib/ollama/libggml.so.0"), False, False), self.probes[1][1])
        self.assert_no_setup()

    def test_apply_creates_only_private_first_use_state_and_does_not_start_services(self):
        before = self.snapshot()
        with mock.patch.object(M.subprocess, "run", side_effect=AssertionError("must not start services")):
            self.setup.apply(self.config, "a private fixture password")
        after = self.snapshot()
        self.assertEqual(set(after) - set(before), {"var/lib/omega-dashboard", "var/lib/omega-dashboard/live",
                         "var/lib/omega-dashboard/password", "etc/omega/dashboard.env", "etc/omega/dashboard.ready"})
        for path, value in before.items():
            self.assertEqual(after[path], value)
        for absolute in (M.ENV, M.PASSWORD, M.READY):
            self.assertEqual(stat.S_IMODE(self.path(absolute).stat().st_mode), 0o600)
            self.assertEqual(self.path(absolute).stat().st_uid, os.geteuid())
        self.assertEqual(self.path(M.PASSWORD).read_text(), "a private fixture password")
        for absolute in (M.STATE, M.STATE + "/live"):
            self.assertEqual(stat.S_IMODE(self.path(absolute).stat().st_mode), 0o700)
        self.assertFalse(self.path(M.STATE + "/live/telemetry.sqlite3").exists())
        actual_env = dict(line.split("=", 1) for line in self.path(M.ENV).read_text().splitlines())
        self.assertEqual(actual_env, {key: str(value) for key, value in self.config.items()})

    def test_repeated_apply_and_check_refuse_without_modifying_files(self):
        self.setup.apply(self.config, "a private fixture password")
        before = self.snapshot()
        for operation in (lambda: self.setup.check(self.config), lambda: self.setup.apply(self.config, "another private password")):
            with self.assertRaises(M.SetupError):
                operation()
            self.assertEqual(self.snapshot(), before)

    def test_existing_evidence_and_unknown_private_state_are_preserved(self):
        for absolute in (M.STATE, M.STATE + "/live"):
            self.path(absolute).mkdir(mode=0o700)
        evidence = self.write(M.STATE + "/live/telemetry.sqlite3", b"existing evidence", 0o600)
        before = self.snapshot()
        with self.assertRaises(M.SetupError):
            self.setup.apply(self.config, "a private fixture password")
        self.assertEqual(evidence.read_bytes(), b"existing evidence")
        self.assertEqual(self.snapshot(), before)

    def test_empty_private_directories_survive_failed_apply(self):
        for absolute in (M.STATE, M.STATE + "/live"):
            self.path(absolute).mkdir(mode=0o700)
        before = self.snapshot()
        def fail(point):
            if point == "before_marker":
                raise OSError("injected write failure")
        with self.assertRaises(OSError):
            self.make_setup(checkpoint=fail).apply(self.config, "a private fixture password")
        self.assertEqual(self.snapshot(), before)

    def test_failed_marker_rolls_back_only_new_files_and_directories(self):
        before = self.snapshot()
        def fail(point):
            if point == "after_marker":
                raise OSError("injected failure")
        with self.assertRaises(OSError):
            self.make_setup(checkpoint=fail).apply(self.config, "a private fixture password")
        self.assertEqual(self.snapshot(), before)

    def test_rollback_preserves_a_replaced_output(self):
        def replace(point):
            if point == "before_marker":
                replacement = self.write("/etc/omega/other-file", b"external replacement", 0o600)
                os.replace(replacement, self.path(M.ENV))
        with self.assertRaises(M.SetupError):
            self.make_setup(checkpoint=replace).apply(self.config, "a private fixture password")
        self.assertEqual(self.path(M.ENV).read_bytes(), b"external replacement")
        self.assertFalse(self.path(M.PASSWORD).exists())
        self.assertFalse(self.path(M.READY).exists())

    def test_rollback_preserves_an_output_edited_in_place(self):
        def edit(point):
            if point == "before_marker":
                self.path(M.ENV).write_bytes(b"external in-place edit")
        with self.assertRaises(M.SetupError):
            self.make_setup(checkpoint=edit).apply(self.config, "a private fixture password")
        self.assertEqual(self.path(M.ENV).read_bytes(), b"external in-place edit")
        self.assertFalse(self.path(M.PASSWORD).exists())
        self.assertFalse(self.path(M.READY).exists())

    def test_failed_private_file_write_rolls_back_partial_outputs(self):
        before = self.snapshot()
        original = M.os.fchmod
        calls = 0
        def fail(fd, mode):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError("injected password permission failure")
            return original(fd, mode)
        with mock.patch.object(M.os, "fchmod", side_effect=fail), self.assertRaises(OSError):
            self.setup.apply(self.config, "a private fixture password")
        self.assertEqual(self.snapshot(), before)

    def test_concurrent_evidence_blocks_marker_and_is_preserved(self):
        def insert(point):
            if point == "before_marker":
                self.write(M.STATE + "/live/arrived.json", b"external evidence", 0o600)
        with self.assertRaises(M.SetupError):
            self.make_setup(checkpoint=insert).apply(self.config, "a private fixture password")
        self.assertEqual(self.path(M.STATE + "/live/arrived.json").read_bytes(), b"external evidence")
        self.assert_no_setup()

    def test_missing_unknown_duplicate_and_wrong_type_config_are_rejected(self):
        invalid = [dict(self.config, EXTRA="no"), {key: value for key, value in self.config.items() if key != "OMEGA_AI_MODEL"},
                   dict(self.config, OMEGA_AI_THREADS=True), dict(self.config, OMEGA_MAX_EVENTS="500"),
                   dict(self.config, OMEGA_RETENTION_DAYS=0), dict(self.config, OMEGA_AI_THREADS=9),
                   dict(self.config, OMEGA_MAX_EVENTS=50000001), dict(self.config, OMEGA_RETENTION_DAYS=3651)]
        for config in invalid:
            with self.subTest(config=config), self.assertRaises(M.SetupError):
                self.setup.check(config)
        with self.assertRaises(M.SetupError):
            M.parse_json(b'{"key":1,"key":2}')
        with self.assertRaises(M.SetupError):
            M.parse_json('{"key":1}'.encode("utf-16"))
        self.assert_no_setup()

    def test_systemd_substitutions_ambiguous_paths_and_same_sources_are_rejected(self):
        for value in ("/tmp/a b", "/tmp/a\nOTHER=1", "/tmp/$HOME", "/tmp/%n", "/tmp/../other", "/tmp//other",
                      "/tmp/./other", "/dev/null", "relative", "/var/lib/omega-dashboard/private",
                      "/tmp/hidden.json", "/var/tmp/hidden.json", "/home/owner/source.json",
                      "/root/source.json", "/run/user/1000/source.json"):
            with self.subTest(value=value), self.assertRaises(M.SetupError):
                self.setup.check(dict(self.config, OMEGA_SURICATA_EVE=value))
        with self.assertRaises(M.SetupError):
            self.setup.check(dict(self.config, OMEGA_WAZUH_ALERTS=self.config["OMEGA_WAZUH_ARCHIVES"]))
        with self.assertRaises(M.SetupError):
            self.setup.check(dict(self.config, OMEGA_AI_MODEL="qwen3:1.7b\nINJECT=1"))

    def test_source_symlink_and_ancestor_symlink_are_rejected(self):
        source = self.path(self.config["OMEGA_SURICATA_EVE"])
        saved = source.read_bytes()
        source.unlink()
        source.symlink_to(self.path(self.config["OMEGA_WAZUH_ALERTS"]))
        with self.assertRaises(OSError):
            self.setup.check(self.config)
        source.unlink()
        source.write_bytes(saved)
        source.parent.rename(source.parent.with_name("real-source"))
        source.parent.symlink_to(source.parent.with_name("real-source"), target_is_directory=True)
        with self.assertRaises(OSError):
            self.setup.check(self.config)
        self.assert_no_setup()

    def test_unreadable_or_writable_source_prerequisite_is_not_bypassed(self):
        def rejected(identity, paths):
            raise M.SetupError("service-account access denied")
        with self.assertRaises(M.SetupError):
            self.make_setup(probe=rejected).apply(self.config, "a private fixture password")
        self.assert_no_setup()

    @unittest.skipIf(os.geteuid() == 0, "requires an unprivileged kernel permission probe")
    def test_kernel_probe_honors_traversal_only_directories_and_requires_execution(self):
        source = self.path(self.config["OMEGA_SURICATA_EVE"])
        source.chmod(0o444)
        source.parent.chmod(0o111)
        # Exercise the actual child/open/access checks as this unprivileged user;
        # only the root-only supplemental-group transition needs substitution.
        with mock.patch.object(M.os, "setgroups", return_value=None):
            try:
                M.probe_as(self.identity, [(source, True)])
                source.chmod(0o000)
                with self.assertRaises(M.SetupError):
                    M.probe_as(self.identity, [(source, True)])
                source.chmod(0o644)
                with self.assertRaises(M.SetupError):
                    M.probe_as(self.identity, [(source, True)])
                source.chmod(0o444)
                source.parent.chmod(0o755)
                with self.assertRaises(M.SetupError):
                    M.probe_as(self.identity, [(source, True)])
                runtime = self.path(M.RUNTIME)
                M.probe_as(self.identity, [(runtime, False, True)])
                runtime.chmod(0o644)
                with self.assertRaises(M.SetupError):
                    M.probe_as(self.identity, [(runtime, False, True)])
            finally:
                source.parent.chmod(0o755)
                source.chmod(0o640)

    def test_missing_or_tampered_model_and_runtime_are_rejected(self):
        for path in (self.path(M.RUNTIME), self.path(M.RUNTIME_ROOT + "/lib/ollama/libggml.so.0"),
                     self.path(M.MODEL_ROOT + "/blobs/sha256-" + self.lock["model"]["blobs"][0]["sha256"])):
            original = path.read_bytes()
            path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            with self.assertRaises(M.SetupError):
                self.setup.check(self.config)
            path.write_bytes(original)
        manifest = self.path(M.MODEL_ROOT + "/" + self.lock["model"]["manifest"]["path"])
        manifest.unlink()
        with self.assertRaises(OSError):
            self.setup.check(self.config)
        self.assert_no_setup()

    def test_missing_runtime_library_wrong_modes_and_changed_links_are_rejected(self):
        runtime = self.path(M.RUNTIME)
        runtime.chmod(0o744)
        with self.assertRaises(M.SetupError):
            self.setup.check(self.config)
        runtime.chmod(0o755)
        link = self.path(M.RUNTIME_ROOT + "/lib/ollama/libggml.so")
        link.unlink()
        link.symlink_to("/etc/passwd")
        with self.assertRaises(M.SetupError):
            self.setup.check(self.config)
        link.unlink()
        link.symlink_to("libggml.so.0")
        self.path(M.RUNTIME_ROOT + "/lib/ollama/libggml.so.0").unlink()
        with self.assertRaises(OSError):
            self.setup.check(self.config)
        self.assert_no_setup()

    def test_runtime_member_traversal_cycles_duplicates_and_missing_targets_are_rejected(self):
        original = list(self.lock["runtime"]["members"])
        for changed in (
            {"path": "lib/ollama/../../../etc/passwd", "type": "file", "mode": "0644"},
            {"path": "lib/ollama/link", "type": "symlink", "target": "../escape"},
            {"path": "lib/ollama/link", "type": "symlink", "target": "link"},
            {"path": "lib/ollama/link", "type": "symlink", "target": "missing"},
            original[0],
        ):
            self.lock["runtime"]["members"] = original + [changed]
            self.write_lock()
            with self.subTest(member=changed), self.assertRaises(M.SetupError):
                self.setup.check(self.config)
        self.assert_no_setup()

    def test_different_model_and_wrong_manifest_references_are_rejected(self):
        with self.assertRaises(M.SetupError):
            self.setup.check(dict(self.config, OMEGA_AI_MODEL="qwen3:0.6b"))
        spec = self.lock["model"]["manifest"]
        path = self.path(M.MODEL_ROOT + "/" + spec["path"])
        content = json.loads(path.read_bytes())
        content["layers"][0]["digest"] = "sha256:" + "0" * 64
        data = json.dumps(content).encode()
        path.write_bytes(data)
        spec.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.write_lock()
        with self.assertRaises(M.SetupError):
            self.setup.check(self.config)

    def test_duplicate_model_reference_is_rejected(self):
        spec = self.lock["model"]["manifest"]
        path = self.path(M.MODEL_ROOT + "/" + spec["path"])
        content = json.loads(path.read_bytes())
        content["layers"].append(content["layers"][0])
        data = json.dumps(content).encode()
        path.write_bytes(data)
        spec.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.write_lock()
        with self.assertRaises(M.SetupError):
            self.setup.check(self.config)

    def test_stale_failed_and_future_mirror_heartbeats_are_rejected(self):
        for age, ok in ((121, True), (0, False), (-90, True)):
            self.write_heartbeat(age=age, ok=ok)
            with self.subTest(age=age, ok=ok), self.assertRaises(M.SetupError):
                self.setup.check(self.config)
        self.assert_no_setup()

    def test_explicit_local_manager_does_not_require_a_mirror_heartbeat(self):
        self.path(self.config["OMEGA_WAZUH_SYNC_STATUS"]).unlink()
        self.config["OMEGA_WAZUH_SYNC_STATUS"] = ""
        self.setup.check(self.config)

    def test_invalid_log_and_uninitialized_pihole_are_rejected(self):
        log = self.path(self.config["OMEGA_SURICATA_EVE"])
        original = log.read_bytes()
        log.write_bytes(b"not JSON\n")
        with self.assertRaises(M.SetupError):
            self.setup.check(self.config)
        log.write_bytes(original)
        self.path(self.config["OMEGA_PIHOLE_DATABASE"]).write_bytes(b"")
        with self.assertRaises(M.SetupError):
            self.setup.check(self.config)

    def test_wal_database_requires_existing_companions_without_creating_them(self):
        database = self.path(self.config["OMEGA_PIHOLE_DATABASE"])
        data = bytearray(database.read_bytes())
        data[18:20] = b"\x02\x02"
        database.write_bytes(data)
        before = self.snapshot()
        with self.assertRaises(OSError):
            self.setup.check(self.config)
        self.assertEqual(self.snapshot(), before)

    def test_password_validation_and_private_input_permissions(self):
        for value in ("short", " long but padded password", "valid length\nbut newline", "x" * 1025, "x" * 16 + "\ud800"):
            with self.subTest(value=value), self.assertRaises(M.SetupError):
                self.setup.apply(self.config, value)
        source = self.write("/private-password", b"private fixture password", 0o600)
        self.assertEqual(M.read_small(source, private_owner=os.geteuid()), b"private fixture password")
        source.chmod(0o640)
        with self.assertRaises(M.SetupError):
            M.read_small(source, private_owner=os.geteuid())
        source.chmod(0o600)
        os.link(source, self.path("/linked-password"))
        with self.assertRaises(M.SetupError):
            M.read_small(source, private_owner=os.geteuid())
        self.assert_no_setup()

    def test_real_root_cannot_use_injected_test_dependencies(self):
        with mock.patch.object(M.os, "geteuid", return_value=0), self.assertRaises(M.SetupError):
            M.Setup(Path("/"), accounts=self.accounts, probe=lambda *_: None)
        with mock.patch.object(M.os, "geteuid", return_value=1000), self.assertRaises(M.SetupError):
            M.Setup(Path("/"))

    def test_shipped_json_example_is_valid_and_matches_service_environment_example(self):
        examples = ROOT / "image/rootfs-overlay/etc/omega"
        config = M.validate_config(M.parse_json((examples / "dashboard-setup.json.example").read_bytes()))
        environment = dict(line.split("=", 1) for line in (examples / "dashboard.env.example").read_text().splitlines()
                           if line and not line.startswith("#"))
        self.assertEqual({key: str(value) for key, value in config.items()}, environment)

    def test_cli_has_no_root_or_password_value_bypass_and_check_rejects_password_input(self):
        for args in (("--root", str(self.root), "--check", "--config", "/example.json"),
                     ("--password", "a private fixture password", "--apply", "--config", "/example.json")):
            result = subprocess.run([sys.executable, "-B", str(HELPER), *args], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("a private fixture password", result.stdout + result.stderr)
        with mock.patch.object(M, "Setup", side_effect=AssertionError("should reject before filesystem access")):
            self.assertEqual(M.main(["--check", "--config", "/example.json", "--password-file", "/private"]), 1)


if __name__ == "__main__":
    unittest.main()
