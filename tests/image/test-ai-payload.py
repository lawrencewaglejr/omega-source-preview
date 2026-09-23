#!/usr/bin/python3
"""Exercise offline AI verification and staging with tiny synthetic inputs."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
STAGER = ROOT / "image/scripts/stage-ai.py"
EPOCH = 1670000000
ARCHIVE_URL = "https://github.com/ollama/ollama/releases/download/v0.33.3/ollama-linux-arm64.tar.zst"
LICENSE_URL = "https://raw.githubusercontent.com/ollama/ollama/v0.33.3/LICENSE"
REGISTRY = "https://registry.ollama.ai/v2/library/qwen3"
MODEL_PATH = "manifests/registry.ollama.ai/library/qwen3/1.7b"
RUNTIME = "opt/omega-ai/ollama-0.33.3"
MODELS = "var/lib/omega-ai/models"


@unittest.skipUnless(Path("/usr/bin/zstd").is_file(), "zstd is required for offline AI input fixtures")
class AiPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="omega-ai-payload-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.input_root = self.root / "inputs"
        self.cache = self.input_root / "cache/objects/sha256"
        self.cache.mkdir(parents=True)
        self.destination = self.root / "staged"
        self.lock_path = self.root / "ai.manifest.json"
        self.contents = {
            "bin/ollama": b"synthetic executable; never run\n",
            "lib/ollama/CPU_LICENSE": b"Synthetic CPU library license\n",
            "lib/ollama/libcpu.so.1.0": b"synthetic CPU library\n",
        }
        self.links = {
            "lib/ollama/libcpu.so": "libcpu.so.1",
            "lib/ollama/libcpu.so.1": "libcpu.so.1.0",
        }
        members = [
            {"path": name, "type": "file", "size": len(data),
             "sha256": hashlib.sha256(data).hexdigest(),
             "mode": "0644" if name.endswith("LICENSE") else "0755"}
            for name, data in self.contents.items()
        ] + [{"path": name, "type": "symlink", "target": target}
             for name, target in self.links.items()]
        self.entries = [(name, "file", data) for name, data in self.contents.items()]
        self.entries += [(name, "symlink", target) for name, target in self.links.items()]
        # Non-selected archive members must never enter the staged image.
        self.entries += [("lib/ollama/cuda_v99/libgpu.so", "file", b"unselected GPU library")]
        blobs = [self.put_object(f"synthetic model object {i}\n".encode(), "") for i in range(5)]
        for blob in blobs:
            blob["url"] = REGISTRY + "/blobs/sha256:" + blob["sha256"]
        blobs.sort(key=lambda row: row["sha256"])
        self.model_json = {
            "schemaVersion": 2,
            "config": {"digest": "sha256:" + blobs[0]["sha256"], "size": blobs[0]["size"]},
            "layers": [{"digest": "sha256:" + row["sha256"], "size": row["size"]}
                       for row in blobs[1:]],
        }
        self.lock = {
            "schema": "omega-ai-payload-v1",
            "runtime": {
                "version": "0.33.3", "members": sorted(members, key=lambda row: row["path"]),
                "archive": self.archive_object(self.entries),
                "license": self.put_object(b"Synthetic Ollama license\n", LICENSE_URL),
            },
            "model": {"tag": "qwen3:1.7b", "blobs": blobs, "manifest": {}},
        }
        self.set_model_manifest(self.model_json)

    def put_object(self, data: bytes, url: str) -> dict:
        digest = hashlib.sha256(data).hexdigest()
        path = self.cache / digest
        path.write_bytes(data)
        path.chmod(0o600)
        return {"sha256": digest, "size": len(data), "url": url}

    def archive_object(self, entries: list[tuple]) -> dict:
        source = io.BytesIO()
        with tarfile.open(fileobj=source, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, kind, content in entries:
                member = tarfile.TarInfo(name)
                member.uid, member.gid = 1234, 5678
                member.uname, member.gname = "fixture-owner", "fixture-group"
                member.mtime, member.mode = EPOCH + 123, 0o7777
                if kind == "file":
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
                else:
                    member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                                   "fifo": tarfile.FIFOTYPE}[kind]
                    if kind != "fifo":
                        member.linkname = content
                    archive.addfile(member)
        compressed = subprocess.run(["/usr/bin/zstd", "--quiet", "--stdout"],
                                    input=source.getvalue(), capture_output=True,
                                    timeout=10, check=True).stdout
        return self.put_object(compressed, ARCHIVE_URL)

    def set_archive(self, entries: list[tuple]) -> None:
        self.lock["runtime"]["archive"] = self.archive_object(entries)
        self.write_lock()

    def set_model_manifest(self, value: dict) -> None:
        row = self.put_object(json.dumps(value, sort_keys=True).encode() + b"\n",
                              REGISTRY + "/manifests/1.7b")
        row["path"] = MODEL_PATH
        self.lock["model"]["manifest"] = row
        self.write_lock()

    def write_lock(self) -> None:
        self.lock_path.write_text(json.dumps(self.lock, sort_keys=True, indent=2) + "\n", encoding="ascii")
        self.lock_path.chmod(0o644)

    def run_stage(self, *, verify_only: bool = False, destination: Path | None = None,
                  input_root: Path | None = None) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-B", str(STAGER), "--input-cache-root",
                   str(input_root or self.input_root), "--manifest", str(self.lock_path)]
        if not verify_only:
            command += ["--stage-root", str(destination or self.destination)]
        environment = dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH))
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
        return subprocess.run(command, cwd=self.root, env=environment, capture_output=True,
                              text=True, timeout=10, check=False)

    def assert_rejected(self, result: subprocess.CompletedProcess[str], error: str | None = None) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("AI_PAYLOAD_STAGED=YES", result.stdout)
        self.assertNotIn("AI_INPUT_CACHE=VERIFIED", result.stdout)
        if error:
            self.assertIn(error, result.stderr)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.destination.is_symlink())
        self.assertEqual(list(self.root.glob(".omega-ai-*")), [])

    def test_verification_only_checks_all_eight_objects_without_staging(self) -> None:
        result = self.run_stage(verify_only=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "AI_OBJECTS_VERIFIED=8\nAI_INPUT_CACHE=VERIFIED\n")
        self.assertFalse(self.destination.exists())

    def test_stages_exact_cpu_runtime_model_license_and_receipt(self) -> None:
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("AI_PAYLOAD_STAGED=YES", result.stdout)
        expected = {f"{RUNTIME}/{name}" for name in self.contents | self.links}
        expected |= {f"{RUNTIME}/LICENSE", f"{MODELS}/{MODEL_PATH}", "usr/share/omega/ai/manifest.json"}
        expected |= {f"{MODELS}/blobs/sha256-{row['sha256']}" for row in self.lock["model"]["blobs"]}
        actual = {str(p.relative_to(self.destination)) for p in self.destination.rglob("*")
                  if p.is_file() or p.is_symlink()}
        self.assertEqual(actual, expected)
        for name, data in self.contents.items():
            self.assertEqual((self.destination / RUNTIME / name).read_bytes(), data)
        for name, target in self.links.items():
            self.assertEqual(os.readlink(self.destination / RUNTIME / name), target)
            self.assertEqual((self.destination / RUNTIME / name).read_bytes(), self.contents["lib/ollama/libcpu.so.1.0"])
        for row in self.lock["model"]["blobs"]:
            self.assertEqual((self.destination / MODELS / "blobs" / ("sha256-" + row["sha256"])).read_bytes(),
                             (self.cache / row["sha256"]).read_bytes())
        self.assertEqual((self.destination / "usr/share/omega/ai/manifest.json").read_bytes(), self.lock_path.read_bytes())
        self.assertEqual((self.destination / RUNTIME / "LICENSE").read_bytes(), b"Synthetic Ollama license\n")

    def test_corrupt_same_size_object_is_rejected_in_both_modes(self) -> None:
        path = self.cache / self.lock["model"]["blobs"][0]["sha256"]
        content = path.read_bytes()
        path.write_bytes(bytes([content[0] ^ 1]) + content[1:])
        for verify_only in (False, True):
            with self.subTest(verify_only=verify_only):
                self.assert_rejected(self.run_stage(verify_only=verify_only), "AI_OBJECT_SHA256_MISMATCH")

    def test_wrong_size_and_missing_object_are_rejected(self) -> None:
        path = self.cache / self.lock["runtime"]["license"]["sha256"]
        path.write_bytes(b"short")
        self.assert_rejected(self.run_stage(), "AI_FILE_SIZE_INVALID")
        path.unlink()
        self.assert_rejected(self.run_stage())

    def test_missing_runtime_member_is_rejected_and_partial_stage_removed(self) -> None:
        self.set_archive([entry for entry in self.entries if entry[0] != "lib/ollama/CPU_LICENSE"])
        self.assert_rejected(self.run_stage(), "AI_RUNTIME_MEMBERS_MISSING")

    def test_duplicate_selected_tar_member_is_rejected(self) -> None:
        self.set_archive(self.entries + [self.entries[0]])
        self.assert_rejected(self.run_stage(), "AI_ARCHIVE_DUPLICATE_MEMBER")

    def test_runtime_bytes_are_checked_independently_of_archive_digest(self) -> None:
        entries = copy.deepcopy(self.entries)
        name, kind, content = entries[0]
        entries[0] = (name, kind, bytes([content[0] ^ 1]) + content[1:])
        self.set_archive(entries)
        self.assert_rejected(self.run_stage(), "AI_RUNTIME_FILE_SHA256_MISMATCH")

    def test_selected_file_cannot_be_replaced_by_hardlink_symlink_or_fifo(self) -> None:
        for kind, content in (("hardlink", "lib/ollama/libcpu.so.1.0"),
                              ("symlink", "/etc/passwd"), ("fifo", "")):
            with self.subTest(kind=kind):
                entries = copy.deepcopy(self.entries)
                entries[0] = ("bin/ollama", kind, content)
                self.set_archive(entries)
                self.assert_rejected(self.run_stage(), "AI_ARCHIVE_MEMBER_MISMATCH")

    def test_selected_tar_symlink_must_match_pinned_relative_target(self) -> None:
        for target in ("/etc/passwd", "../../../../escape", "different.so"):
            with self.subTest(target=target):
                entries = [(name, kind, target if name == "lib/ollama/libcpu.so" else content)
                           for name, kind, content in self.entries]
                self.set_archive(entries)
                self.assert_rejected(self.run_stage(), "AI_ARCHIVE_LINK_MISMATCH")

    def test_unselected_unsafe_tar_paths_and_links_are_never_extracted(self) -> None:
        escape = self.root / "escape"
        entries = self.entries + [
            ("../../escape", "file", b"must not escape"),
            (str(escape), "file", b"must not use absolute path"),
            ("lib/ollama/cuda_v99/escape", "symlink", str(escape)),
            ("lib/ollama/cuda_v99/hardlink", "hardlink", "../../escape"),
        ]
        self.set_archive(entries)
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(escape.exists())
        self.assertFalse((self.destination / RUNTIME / "lib/ollama/cuda_v99").exists())

    def test_unsafe_selected_manifest_paths_are_rejected(self) -> None:
        original = copy.deepcopy(self.lock)
        for path in ("../bin/ollama", "/bin/ollama", "lib/ollama/../../escape", "lib/ollama/nested/file"):
            with self.subTest(path=path):
                self.lock = copy.deepcopy(original)
                self.lock["runtime"]["members"][1]["path"] = path
                self.write_lock()
                self.assert_rejected(self.run_stage(), "AI_MEMBER_PATH_INVALID")

    def test_unsafe_missing_and_cyclic_manifest_symlink_targets_are_rejected(self) -> None:
        original = copy.deepcopy(self.lock)
        variants = {
            "absolute": ("/etc/passwd", "AI_MEMBER_LINK_INVALID"),
            "traversal": ("../../escape", "AI_MEMBER_LINK_INVALID"),
            "missing": ("missing.so", "AI_MEMBER_LINK_TARGET_MISSING"),
            "cycle": ("libcpu.so", "AI_MEMBER_LINK_CYCLE"),
        }
        for label, (target, error) in variants.items():
            with self.subTest(label=label):
                self.lock = copy.deepcopy(original)
                link = next(row for row in self.lock["runtime"]["members"] if row["path"] == "lib/ollama/libcpu.so")
                link["target"] = target
                self.write_lock()
                self.assert_rejected(self.run_stage(), error)

    def test_model_reference_digest_size_missing_and_duplicate_mismatch_are_rejected(self) -> None:
        variants = {}
        changed_digest = copy.deepcopy(self.model_json)
        changed_digest["layers"][0]["digest"] = "sha256:" + "f" * 64
        variants["digest"] = changed_digest
        changed_size = copy.deepcopy(self.model_json)
        changed_size["layers"][0]["size"] += 1
        variants["size"] = changed_size
        missing = copy.deepcopy(self.model_json)
        missing["layers"].pop()
        variants["missing"] = missing
        duplicate = copy.deepcopy(self.model_json)
        duplicate["layers"][0] = copy.deepcopy(duplicate["layers"][1])
        variants["duplicate"] = duplicate
        for label, value in variants.items():
            with self.subTest(label=label):
                self.set_model_manifest(value)
                self.assert_rejected(self.run_stage(), "AI_MODEL_REFERENCES_MISMATCH")

    def test_extra_cache_state_is_not_copied(self) -> None:
        for name in ("password", "telemetry.sqlite3", "f" * 64):
            (self.cache / name).write_bytes(b"private state must stay outside the image")
        (self.input_root / "private-report.zip").write_bytes(b"private report")
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        all_bytes = [p.read_bytes() for p in self.destination.rglob("*") if p.is_file() and not p.is_symlink()]
        self.assertTrue(all(b"private state" not in data and b"private report" not in data for data in all_bytes))

    def test_preexisting_destination_directory_file_and_broken_link_are_preserved(self) -> None:
        self.destination.mkdir()
        sentinel = self.destination / "existing-data"
        sentinel.write_bytes(b"keep existing appliance data")
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(list(self.destination.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"keep existing appliance data")
        existing_file = self.root / "existing-file"
        existing_file.write_bytes(b"keep file")
        self.assertNotEqual(self.run_stage(destination=existing_file).returncode, 0)
        self.assertEqual(existing_file.read_bytes(), b"keep file")
        broken = self.root / "broken-destination"
        broken.symlink_to(self.root / "missing")
        self.assertNotEqual(self.run_stage(destination=broken).returncode, 0)
        self.assertTrue(broken.is_symlink())
        self.assertEqual(os.readlink(broken), str(self.root / "missing"))
        self.assertEqual(list(self.root.glob(".omega-ai-*")), [])

    def test_source_object_symlink_hardlink_and_fifo_are_rejected_without_blocking(self) -> None:
        path = self.cache / self.lock["runtime"]["license"]["sha256"]
        content = path.read_bytes()
        outside = self.root / "original-license"
        outside.write_bytes(content)
        outside.chmod(0o600)
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, path)
                else:
                    os.mkfifo(path, mode=0o600)
                self.assert_rejected(self.run_stage())

    def test_source_cache_parent_link_is_rejected(self) -> None:
        original = self.cache.parent / "original-sha256"
        self.cache.rename(original)
        self.cache.symlink_to(original, target_is_directory=True)
        self.assert_rejected(self.run_stage(), "AI_DIRECTORY_INVALID")

    def test_source_root_link_is_rejected(self) -> None:
        link = self.root / "linked-inputs"
        link.symlink_to(self.input_root, target_is_directory=True)
        self.assert_rejected(self.run_stage(input_root=link), "AI_DIRECTORY_INVALID")

    def test_writable_cached_objects_are_rejected(self) -> None:
        path = self.cache / self.lock["runtime"]["license"]["sha256"]
        for mode in (0o664, 0o606):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                self.assert_rejected(self.run_stage(), "AI_FILE_METADATA_INVALID")

    def test_manifest_symlink_and_fifo_are_rejected_without_blocking(self) -> None:
        original = self.root / "original-manifest"
        self.lock_path.rename(original)
        self.lock_path.symlink_to(original)
        self.assert_rejected(self.run_stage())
        self.lock_path.unlink()
        os.mkfifo(self.lock_path, mode=0o600)
        self.assert_rejected(self.run_stage())

    def test_duplicate_json_keys_are_rejected(self) -> None:
        raw = self.lock_path.read_text()
        self.lock_path.write_text(raw.replace('"schema": "omega-ai-payload-v1"',
                                              '"schema": "omega-ai-payload-v1", "schema": "omega-ai-payload-v1"'))
        self.assert_rejected(self.run_stage(), "AI_JSON_DUPLICATE_KEY")

    def test_repeated_staging_has_identical_contents_modes_and_times(self) -> None:
        def inventory(root: Path) -> dict:
            paths = [root, *root.rglob("*")]
            result = {}
            for path in paths:
                info = path.lstat()
                relative = str(path.relative_to(root))
                self.assertEqual(info.st_mtime_ns, EPOCH * 1_000_000_000, relative)
                if stat.S_ISDIR(info.st_mode):
                    private = relative == "var/lib/omega-ai" or relative.startswith("var/lib/omega-ai/")
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o700 if private else 0o755, relative)
                    content = None
                elif stat.S_ISLNK(info.st_mode):
                    content = os.readlink(path)
                else:
                    # Enumeration can change directory access times, but files are untouched so far.
                    self.assertEqual(info.st_atime_ns, EPOCH * 1_000_000_000, relative)
                    expected_mode = 0o600 if relative.startswith(MODELS + "/") else 0o644
                    if relative.startswith(RUNTIME + "/"):
                        name = relative[len(RUNTIME) + 1:]
                        if name in self.contents and not name.endswith("LICENSE"):
                            expected_mode = 0o755
                    self.assertEqual(stat.S_IMODE(info.st_mode), expected_mode, relative)
                    content = path.read_bytes()
                result[relative] = (stat.S_IMODE(info.st_mode), info.st_mtime_ns, content)
            return result

        first = self.run_stage()
        self.assertEqual(first.returncode, 0, first.stderr)
        initial = inventory(self.destination)
        for index, path in enumerate(self.cache.iterdir()):
            path.chmod(0o644 if index % 2 else 0o600)
            os.utime(path, (EPOCH + index + 1, EPOCH + index + 1))
        repeated = self.root / "repeated"
        second = self.run_stage(destination=repeated)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(initial, inventory(repeated))


if __name__ == "__main__":
    unittest.main()
