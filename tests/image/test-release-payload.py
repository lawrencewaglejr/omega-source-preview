#!/usr/bin/python3
"""Exercise offline service startup and release inventory boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import tempfile
import unittest
import time


ROOT = pathlib.Path(__file__).resolve().parents[2]
IMAGE = ROOT / "image"
OVERLAY = IMAGE / "rootfs-overlay"


class ReleasePayloadTests(unittest.TestCase):
    def test_ext4_metadata_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            digests = []
            environment = dict(os.environ, E2FSPROGS_FAKE_TIME="1787801458", SOURCE_DATE_EPOCH="1787801458")
            for index in range(2):
                tree = root / f"tree-{index}"
                (tree / "nested").mkdir(parents=True)
                (tree / "nested/file").write_bytes(b"same content")
                (tree / "link").symlink_to("nested/file")
                os.link(tree / "nested/file", tree / "hardlink")
                image = root / str(index) / "root.ext4"
                image.parent.mkdir()
                subprocess.run([
                    "/usr/sbin/mke2fs", "-q", "-t", "ext4", "-F", "-U",
                    "bd67750e-9777-5c69-b79e-ee0d454fbe92", "-E",
                    "hash_seed=bd67750e-9777-5c69-b79e-ee0d454fbe92,lazy_itable_init=0,lazy_journal_init=0",
                    "-d", str(tree), str(image), "16384",
                ], env=environment, capture_output=True, check=True)
                subprocess.run([str(IMAGE / "host-tools/e2fsck"), "-pvfD", str(image)],
                               env=environment, capture_output=True, check=True)
                digests.append(hashlib.sha256(image.read_bytes()).hexdigest())
                time.sleep(1)
            self.assertEqual(digests[0], digests[1])

    def test_services_use_locked_images_without_registry_fallback(self) -> None:
        rows = (IMAGE / "locks/oci-images.manifest").read_text().splitlines()[5:]
        for row in rows:
            fields = row.split("\t")
            name, config_id = fields[0], "sha256:" + fields[6]
            unit_name = "pihole-FTL" if name == "pihole" else name
            unit = (OVERLAY / f"usr/lib/systemd/system/{unit_name}.service").read_text()
            command = next(line.removeprefix("ExecStart=") for line in unit.splitlines() if line.startswith("ExecStart="))
            args = shlex.split(command)
            self.assertIn("--pull=never", args)
            self.assertIn(config_id, args)
            self.assertEqual(args[args.index("--env-file") + 1], f"/etc/omega/{name}.env")
            if name == "evebox":
                self.assertEqual(args[args.index(config_id) + 1:], ["/bin/evebox", "server", "--sqlite", "/var/log/suricata/eve.json"])
                environment = (OVERLAY / "etc/omega/evebox.env.example").read_text()
                self.assertIn("EVEBOX_HTTP_HOST=127.0.0.1\n", environment)
                self.assertIn("EVEBOX_HTTP_PORT=5636\n", environment)

    def test_import_recovers_missing_images_and_checks_archive_from_any_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive_dir = root / "archive"
            archive_dir.mkdir()
            state_dir = root / "state"
            archive = archive_dir / "omega-services.tar"
            archive.write_bytes(b"test archive")
            checksum = archive_dir / "omega-services.tar.sha256"
            checksum.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  omega-services.tar\n")
            docker = root / "docker"
            docker.write_text("""#!/usr/bin/python3
import os, pathlib, sys
root = pathlib.Path(os.environ['OMEGA_IMPORT_TEST_ROOT'])
args = sys.argv[1:]
with (root / 'calls').open('a') as log:
    log.write(' '.join(args) + '\\n')
if args[:2] == ['image', 'inspect']:
    if not (root / 'images-present').exists():
        sys.exit(1)
    print(args[-1])
elif args[:2] == ['image', 'load']:
    if os.environ.get('OMEGA_IMPORT_TEST_INCOMPLETE_LOAD') != 'yes':
        (root / 'images-present').touch()
else:
    sys.exit(2)
""")
            docker.chmod(0o755)
            program = (OVERLAY / "usr/libexec/omega/import-images").read_text()
            program = program.replace("/usr/share/omega/oci", str(archive_dir))
            program = program.replace("/var/lib/omega", str(state_dir))
            program = program.replace("/usr/bin/docker", str(docker))
            program = program.replace(" -o root -g root", "")
            importer = root / "import-images"
            importer.write_text(program)
            environment = dict(os.environ, OMEGA_IMPORT_TEST_ROOT=str(root))

            def run() -> subprocess.CompletedProcess[str]:
                return subprocess.run(["/bin/bash", "-p", str(importer)], cwd="/", env=environment, capture_output=True, text=True, check=False)

            self.assertEqual(run().returncode, 0)
            self.assertEqual((state_dir / "oci-images.imported").read_bytes(), checksum.read_bytes())
            self.assertEqual(run().returncode, 0)
            self.assertEqual((root / "calls").read_text().count("image load"), 1)
            (root / "images-present").unlink()
            self.assertEqual(run().returncode, 0)
            self.assertEqual((root / "calls").read_text().count("image load"), 2)
            (root / "images-present").unlink()
            environment["OMEGA_IMPORT_TEST_INCOMPLETE_LOAD"] = "yes"
            self.assertNotEqual(run().returncode, 0)
            calls_before = (root / "calls").read_bytes()
            archive.write_bytes(b"corrupted archive")
            self.assertNotEqual(run().returncode, 0)
            self.assertEqual((root / "calls").read_bytes(), calls_before)

    def test_release_describes_installed_packages_and_rejects_unlocked_ones(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            deploy = root / "build/deploy-omega-v1"
            deploy.mkdir(parents=True)
            (deploy / "omega-rpi5-trixie-arm64.img").write_bytes(bytes(4096))
            rows = (IMAGE / "locks/packages.manifest").read_text().splitlines()[4:]
            selected = rows[0].split("\t")
            installed = deploy / "manifest"
            installed.write_text(f"{selected[0]}\t{selected[1]}\n")
            (deploy / "config.yaml").write_text(f"workspace: {root}/build\n")
            (deploy / "image.json").write_text(json.dumps({"workspace": str(root / "build")}))

            def assemble(name: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run([
                    "/usr/bin/python3", str(IMAGE / "scripts/assemble-release.py"),
                    "--build-root", str(root / "build"), "--omega-source", str(IMAGE),
                    "--output-directory", str(root / name), "--source-commit", "1" * 40,
                ], capture_output=True, text=True, check=False)

            result = assemble("release")
            self.assertEqual(result.returncode, 0, result.stderr)
            sbom = json.loads((root / "release/omega-v1.spdx.json").read_text())
            dashboard = next(package for package in sbom["packages"] if package["SPDXID"] == "SPDXRef-omega-dashboard")
            manifest = (root / "release/dashboard.manifest").read_bytes()
            self.assertEqual(manifest, (IMAGE / "locks/dashboard.manifest").read_bytes())
            self.assertEqual(dashboard["checksums"][0]["checksumValue"], hashlib.sha256(manifest).hexdigest())
            provenance = json.loads((root / "release/omega-v1.provenance.json").read_text())
            self.assertEqual(provenance["dashboard_manifest_sha256"], hashlib.sha256(manifest).hexdigest())
            onboarding = next(package for package in sbom["packages"] if package["SPDXID"] == "SPDXRef-omega-onboarding")
            onboarding_bytes = (root / "release/onboarding.manifest").read_bytes()
            self.assertEqual(onboarding_bytes, (IMAGE / "locks/onboarding.manifest").read_bytes())
            self.assertEqual(onboarding["checksums"][0]["checksumValue"], hashlib.sha256(onboarding_bytes).hexdigest())
            self.assertEqual(provenance["onboarding_manifest_sha256"], hashlib.sha256(onboarding_bytes).hexdigest())
            ai_bytes = (root / "release/ai.manifest.json").read_bytes()
            self.assertEqual(ai_bytes, (IMAGE / "locks/ai.manifest.json").read_bytes())
            self.assertEqual(provenance["ai_manifest_sha256"], hashlib.sha256(ai_bytes).hexdigest())
            ai = json.loads(ai_bytes)
            runtime = next(p for p in sbom["packages"] if p["SPDXID"] == "SPDXRef-ollama-cpu-runtime")
            model = next(p for p in sbom["packages"] if p["SPDXID"] == "SPDXRef-qwen3-model")
            self.assertEqual(runtime["checksums"][0]["checksumValue"], ai["runtime"]["archive"]["sha256"])
            self.assertEqual(model["checksums"][0]["checksumValue"], ai["model"]["manifest"]["sha256"])
            debs = [package for package in sbom["packages"] if package["SPDXID"].startswith("SPDXRef-deb-")]
            self.assertEqual([package["name"] for package in debs], [selected[0]])
            self.assertEqual(debs[0]["versionInfo"], selected[1])
            self.assertEqual(debs[0]["checksums"][0]["checksumValue"], selected[4])
            valid_purposes = {"OTHER", "INSTALL", "ARCHIVE", "FIRMWARE", "APPLICATION", "FRAMEWORK", "LIBRARY", "CONTAINER", "SOURCE", "DEVICE", "OPERATING_SYSTEM", "FILE"}
            for package in sbom["packages"]:
                self.assertIn(package["primaryPackagePurpose"], valid_purposes)
            check = subprocess.run(["/usr/bin/sha256sum", "--check", "SHA256SUMS"], cwd=root / "release", capture_output=True, check=False)
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertEqual(assemble("repeat").returncode, 0)
            self.assertEqual((root / "release/SHA256SUMS").read_bytes(), (root / "repeat/SHA256SUMS").read_bytes())
            self.assertEqual((root / "release/config.yaml").read_text(), "workspace: /build/omega-workspace/build\n")
            self.assertEqual(json.loads((root / "release/image.json").read_text()), {"workspace": "/build/omega-workspace/build"})
            installed.write_text("unlocked-package\t1.0\n")
            rejected = assemble("unlocked")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("INSTALLED_PACKAGE_NOT_LOCKED_unlocked-package", rejected.stderr)
            installed.unlink()
            rejected = assemble("missing")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("INSTALLED_PACKAGE_MANIFEST_MISSING", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
