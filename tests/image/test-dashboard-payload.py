#!/usr/bin/python3
"""Exercise dashboard release staging through its public command line."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
STAGER = ROOT / "image/scripts/stage-dashboard.py"
PAYLOAD = (
    "ai_status.py", "correlation.py", "devices.py", "protection.py",
    "report_jobs.py", "server.py", "static/app.js", "static/index.html",
    "static/style.css", "telemetry_store.py", "text_report.py",
)
EPOCH = 1670000000


class DashboardPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="omega-dashboard-payload-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.dashboard = self.source / "dashboard"
        self.dashboard.mkdir(parents=True)
        for relative in PAYLOAD:
            target = self.dashboard / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "dashboard" / relative, target)
            target.chmod(0o644)
        self.manifest = self.root / "dashboard.manifest"
        self.rows = [self.manifest_row(relative) for relative in PAYLOAD]
        self.write_manifest(self.rows)
        self.destination = self.root / "staged"

    def manifest_row(self, relative: str) -> str:
        content = (self.dashboard / relative).read_bytes()
        return f"{len(content)}\t{hashlib.sha256(content).hexdigest()}\t{relative}"

    def write_manifest(self, rows: list[str]) -> None:
        self.manifest.write_text("\n".join([
            "omega-dashboard-manifest-v1", "file_count\t11",
            "columns\tsize\tsha256\tpath", *rows, "",
        ]), encoding="ascii")
        self.manifest.chmod(0o644)

    def run_stage(self, *, destination: Path | None = None,
                  source: Path | None = None, verify_only: bool = False) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-B", str(STAGER), "--source-root",
                   str(source or self.source), "--manifest", str(self.manifest)]
        if not verify_only:
            command.extend(["--destination", str(destination or self.destination)])
        environment = dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH))
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
        return subprocess.run(command, cwd=self.root, env=environment,
                              text=True, capture_output=True, timeout=10, check=False)

    def assert_rejected_without_output(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("DASHBOARD_PAYLOAD_VALID=YES", result.stdout)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".omega-dashboard-*")), [])

    def test_stages_exact_application_and_can_import_its_modules(self) -> None:
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DASHBOARD_FILES_STAGED=11", result.stdout)
        self.assertIn("DASHBOARD_PAYLOAD_VALID=YES", result.stdout)
        actual = {str(path.relative_to(self.destination)) for path in self.destination.rglob("*") if path.is_file()}
        self.assertEqual(actual, set(PAYLOAD))
        for relative in PAYLOAD:
            self.assertEqual((self.destination / relative).read_bytes(), (self.dashboard / relative).read_bytes())
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
        # server imports the six supporting app modules before parsing --help.
        startup = subprocess.run([sys.executable, "-B", str(self.destination / "server.py"), "--help"],
                                 cwd=self.root, env=environment, capture_output=True,
                                 text=True, timeout=10, check=False)
        self.assertEqual(startup.returncode, 0, startup.stderr)
        self.assertIn("--telemetry-state", startup.stdout)
        self.assertIn("--from-now", startup.stdout)
        self.assertFalse(list(self.destination.rglob("__pycache__")))

    def test_verification_only_does_not_stage_an_application(self) -> None:
        result = self.run_stage(verify_only=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "DASHBOARD_PAYLOAD_VALID=YES\n")
        self.assertFalse(self.destination.exists())

    def test_service_cache_command_checks_the_dashboard_before_reporting_ready(self) -> None:
        scripts = self.source / "image/scripts"
        scripts.mkdir(parents=True)
        locks = self.source / "image/locks"
        locks.mkdir()
        shutil.copy2(self.manifest, locks / "dashboard.manifest")
        for name in ("build.sh", "stage-dashboard.py"):
            shutil.copyfile(ROOT / "image/scripts" / name, scripts / name)
        verifier = scripts / "verify.sh"
        verifier.write_text("#!/bin/bash\nexit 0\n", encoding="ascii")
        verifier.chmod(0o755)
        # The external archives are independent inputs. Keep their verifiers
        # inert here so the public build command exercises dashboard wiring
        # without requiring the multi-gigabyte offline cache.
        for name in ("verify-package-cache.py", "verify-oci-cache.py",
                     "verify-builder-tools.py", "stage-ai.py", "stage-onboarding.py"):
            (scripts / name).write_text("raise SystemExit(0)\n", encoding="ascii")
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}

        def check() -> subprocess.CompletedProcess[str]:
            return subprocess.run([
                "/bin/bash", "-p", str(scripts / "build.sh"),
                "--check-service-cache", str(self.root / "unused-cache"),
            ], cwd=self.root, env=environment, text=True, capture_output=True,
                timeout=10, check=False)

        result = check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "DASHBOARD_PAYLOAD_VALID=YES\nSERVICE_INPUT_CACHE=VERIFIED\n")
        target = self.dashboard / "server.py"
        content = target.read_bytes()
        target.write_bytes(bytes([content[0] ^ 1]) + content[1:])
        rejected = check()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("DASHBOARD_CONTENT_MISMATCH_server.py", rejected.stderr)
        self.assertNotIn("SERVICE_INPUT_CACHE=VERIFIED", rejected.stdout)
        self.assertNotIn("DASHBOARD_PAYLOAD_VALID=YES", rejected.stdout)

    def test_content_tampering_is_rejected_even_when_size_matches(self) -> None:
        target = self.dashboard / "server.py"
        content = target.read_bytes()
        target.write_bytes(bytes([content[0] ^ 1]) + content[1:])
        self.assert_rejected_without_output(self.run_stage())

    def test_missing_source_file_is_rejected(self) -> None:
        (self.dashboard / "server.py").unlink()
        self.assert_rejected_without_output(self.run_stage())

    def test_missing_duplicate_extra_and_reordered_manifest_paths_are_rejected(self) -> None:
        secret = self.dashboard / "password"
        secret.write_text("private appliance password\n")
        secret.chmod(0o600)
        variants = {
            "missing": self.rows[:-1],
            "duplicate": [*self.rows, self.rows[-1]],
            "extra": [*self.rows, self.manifest_row("password")],
            "reordered": list(reversed(self.rows)),
            "traversal": [*self.rows[:-1], self.rows[-1].rsplit("\t", 1)[0] + "\t../telemetry_store.py"],
        }
        for name, rows in variants.items():
            with self.subTest(name=name):
                self.write_manifest(rows)
                self.assert_rejected_without_output(self.run_stage())

    def test_source_file_symlink_is_rejected(self) -> None:
        target = self.dashboard / "server.py"
        original = self.root / "original-server.py"
        target.rename(original)
        target.symlink_to(original)
        self.assert_rejected_without_output(self.run_stage())

    def test_nested_source_parent_symlink_is_rejected(self) -> None:
        static = self.dashboard / "static"
        original = self.root / "original-static"
        static.rename(original)
        static.symlink_to(original, target_is_directory=True)
        self.assert_rejected_without_output(self.run_stage())

    def test_dashboard_directory_symlink_is_rejected(self) -> None:
        original = self.root / "original-dashboard"
        self.dashboard.rename(original)
        self.dashboard.symlink_to(original, target_is_directory=True)
        self.assert_rejected_without_output(self.run_stage())

    def test_source_root_symlink_is_rejected(self) -> None:
        source_link = self.root / "source-link"
        source_link.symlink_to(self.source, target_is_directory=True)
        self.assert_rejected_without_output(self.run_stage(source=source_link))

    def test_fifo_source_is_rejected_without_waiting_for_a_writer(self) -> None:
        target = self.dashboard / "server.py"
        target.unlink()
        os.mkfifo(target, mode=0o600)
        self.assert_rejected_without_output(self.run_stage())

    def test_hardlinked_source_is_rejected(self) -> None:
        os.link(self.dashboard / "server.py", self.root / "other-server.py")
        self.assert_rejected_without_output(self.run_stage())

    def test_group_or_world_writable_source_is_rejected(self) -> None:
        target = self.dashboard / "server.py"
        for mode in (0o664, 0o646):
            with self.subTest(mode=oct(mode)):
                target.chmod(mode)
                self.assert_rejected_without_output(self.run_stage())

    def test_existing_destination_is_preserved(self) -> None:
        self.destination.mkdir()
        sentinel = self.destination / "do-not-overwrite"
        sentinel.write_bytes(b"existing application")
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(list(self.destination.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"existing application")
        self.assertEqual(list(self.root.glob(".omega-dashboard-*")), [])
        existing_file = self.root / "existing-file"
        existing_file.write_bytes(b"keep this file")
        self.assertNotEqual(self.run_stage(destination=existing_file).returncode, 0)
        self.assertEqual(existing_file.read_bytes(), b"keep this file")
        broken_link = self.root / "broken-destination"
        broken_link.symlink_to(self.root / "missing-target")
        self.assertNotEqual(self.run_stage(destination=broken_link).returncode, 0)
        self.assertTrue(broken_link.is_symlink())
        self.assertFalse(broken_link.exists())

    def test_unlisted_private_files_are_excluded(self) -> None:
        for relative in ("password", "telemetry.sqlite3", "devices.json", "reports/private.zip", "static/private.txt"):
            path = self.dashboard / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"private state must never enter the image")
            path.chmod(0o600)
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = {str(path.relative_to(self.destination)) for path in self.destination.rglob("*") if path.is_file()}
        self.assertEqual(actual, set(PAYLOAD))

    def test_repeated_staging_has_identical_bytes_modes_and_timestamps(self) -> None:
        def inventory(root: Path) -> dict:
            rows = {}
            # Directory enumeration itself updates access times on some hosts.
            for path in [root, root / "static", *(root / relative for relative in PAYLOAD)]:
                info = path.stat()
                self.assertEqual(info.st_mtime_ns, EPOCH * 1_000_000_000)
                self.assertEqual(info.st_atime_ns, EPOCH * 1_000_000_000)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o755 if path.is_dir() else 0o644)
                rows[str(path.relative_to(root))] = (
                    stat.S_IMODE(info.st_mode), info.st_mtime_ns,
                    None if path.is_dir() else path.read_bytes(),
                )
            return rows

        first = self.run_stage()
        self.assertEqual(first.returncode, 0, first.stderr)
        initial = inventory(self.destination)
        for index, relative in enumerate(PAYLOAD):
            target = self.dashboard / relative
            target.chmod(0o600 if index % 2 else 0o644)
            os.utime(target, (EPOCH + index + 1, EPOCH + index + 1))
        repeated = self.root / "repeated"
        second = self.run_stage(destination=repeated)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(initial, inventory(repeated))


if __name__ == "__main__":
    unittest.main()
