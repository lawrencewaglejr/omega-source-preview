#!/usr/bin/python3
import argparse
import base64
import hashlib
import importlib.util
import io
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]
VERIFIER_PATH = REPOSITORY / "image/scripts/verify-builder-archive.py"
LOCK = REPOSITORY / "image/locks/builder.lock"
MANIFEST_PATH = REPOSITORY / "image/locks/builder-tree.manifest"
BUILD = REPOSITORY / "image/scripts/build.sh"
CONFIG_VERIFIER = REPOSITORY / "image/scripts/verify-builder-config.py"
DIGEST = "5fb1d564d9cbe0064310e1a2123bfaa0782d7010c2545c38383020cf353321ca"
RELATIVE = pathlib.Path("cache/objects/sha256") / DIGEST
spec = importlib.util.spec_from_file_location("builder_archive_verifier", VERIFIER_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load builder archive verifier")
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)

INPUT_CACHE_ROOT = None


def clean_env(extra=None):
    result = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "XDG_CONFIG_HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    if extra:
        result.update(extra)
    return result


def run(command, env=None):
    return subprocess.run(command, env=env or clean_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True)


def copy_cache(root, source=None):
    root = pathlib.Path(root)
    root.mkdir(mode=0o700)
    directory = root / "cache/objects/sha256"
    directory.mkdir(parents=True, mode=0o700)
    target = root / RELATIVE
    shutil.copyfile(source or (INPUT_CACHE_ROOT / RELATIVE), target)
    os.chmod(target, 0o600)
    return target


def git_oid(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def manifest_for(entries, root="fixture-root", root_override=None):
    # entries: path -> (mode, bytes-or-target)
    built = {}
    dirs = {""}
    for path, (mode, value) in entries.items():
        parts = path.split("/")
        for index in range(1, len(parts)):
            dirs.add("/".join(parts[:index]))
        if mode == "120000":
            data = value.encode()
            built[path] = verifier.ManifestEntry(mode, "blob", git_oid("blob", data), len(data), path, value)
        else:
            built[path] = verifier.ManifestEntry(mode, "blob", git_oid("blob", value), len(value), path, None)
    for directory in dirs:
        if directory:
            built[directory] = verifier.ManifestEntry("040000", "tree", "0" * 40, 0, directory, None)
    root_tree, tree_ids = verifier.reconstruct_trees(built)
    for path, entry in list(built.items()):
        if entry.mode == "040000":
            built[path] = verifier.ManifestEntry("040000", "tree", tree_ids[path], 0, path, None)
    return verifier.Manifest(built, root_override or root_tree, root)


def make_tar(path, manifest, transforms=None, extra_members=None, omit=None):
    transforms = transforms or {}
    extra_members = extra_members or []
    omit = set(omit or [])
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        root_info = tarfile.TarInfo(manifest.archive_root)
        root_info.type = tarfile.DIRTYPE
        root_info.mode = 0o775
        archive.addfile(root_info)
        for entry_path, entry in sorted(manifest.entries.items()):
            if entry_path in omit:
                continue
            info = tarfile.TarInfo(manifest.archive_root + "/" + entry_path)
            if entry.mode == "040000":
                info.type = tarfile.DIRTYPE
                info.mode = 0o775
                data = None
            elif entry.mode == "120000":
                info.type = tarfile.SYMTYPE
                info.mode = 0o777
                info.linkname = entry.target
                data = None
            else:
                data = transforms.get(entry_path, {}).get("data")
                if data is None:
                    # Tests use the OID-compatible fixture bytes below.
                    data = transforms.get(entry_path, {}).get("original", b"ok")
                info.type = tarfile.REGTYPE
                info.mode = 0o775 if entry.mode == "100755" else 0o664
                info.size = len(data)
            for key, value in transforms.get(entry_path, {}).items():
                if key not in ("data", "original"):
                    setattr(info, key, value)
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
        for info, data in extra_members:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.temp = pathlib.Path(tempfile.mkdtemp(prefix="omega-builder-enforcement-test-", dir="/tmp"))
        os.chmod(self.temp, 0o700)

    def tearDown(self):
        shutil.rmtree(self.temp)

    def assert_error(self, code, function, *args):
        with self.assertRaises(verifier.ValidationError) as caught:
            function(*args)
        self.assertEqual(str(caught.exception), code)

    def test_01_exact_locked_archive(self):
        result = run([str(VERIFIER_PATH), "--mode", "verify-only", "--input-cache-root", str(INPUT_CACHE_ROOT), "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH)])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("BUILDER_ARCHIVE_VALID=YES", result.stdout)
        self.assertIn("BUILDER_CODE_EXECUTED=NO", result.stdout)

    def test_02_private_extraction(self):
        destination = self.temp / "source"
        result = run([str(VERIFIER_PATH), "--mode", "extract", "--input-cache-root", str(INPUT_CACHE_ROOT), "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH), "--destination", str(destination)])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((destination / "rpi-image-gen").stat().st_mode), 0o755)
        self.assertTrue((destination / "docs/schemas").is_symlink())

    def test_03_missing_archive(self):
        root = self.temp / "cache-root"; root.mkdir(mode=0o700)
        result = run([str(VERIFIER_PATH), "--mode", "verify-only", "--input-cache-root", str(root), "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH)])
        self.assertIn("ARCHIVE_OBJECT_MISSING", result.stdout)

    def test_04_wrong_digest(self):
        target = copy_cache(self.temp / "cache-root")
        data = bytearray(target.read_bytes()); data[-1] ^= 1; target.write_bytes(data); os.chmod(target, 0o600)
        result = run([str(VERIFIER_PATH), "--mode", "verify-only", "--input-cache-root", str(self.temp / "cache-root"), "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH)])
        self.assertIn("ARCHIVE_OBJECT_SHA256_MISMATCH", result.stdout)

    def test_05_wrong_content_addressed_filename(self):
        root = self.temp / "cache-root"; root.mkdir(mode=0o700); directory = root / "cache/objects/sha256"; directory.mkdir(parents=True, mode=0o700)
        shutil.copyfile(INPUT_CACHE_ROOT / RELATIVE, directory / (DIGEST + ".wrong"))
        result = run([str(VERIFIER_PATH), "--mode", "verify-only", "--input-cache-root", str(root), "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH)])
        self.assertIn("ARCHIVE_OBJECT_MISSING", result.stdout)

    def test_06_symlinked_archive(self):
        root = self.temp / "cache-root"; root.mkdir(mode=0o700); directory = root / "cache/objects/sha256"; directory.mkdir(parents=True, mode=0o700)
        os.symlink(INPUT_CACHE_ROOT / RELATIVE, root / RELATIVE)
        result = run([str(VERIFIER_PATH), "--mode", "verify-only", "--input-cache-root", str(root), "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH)])
        self.assertIn("ARCHIVE_OBJECT_SYMLINK_COMPONENT", result.stdout)

    def test_07_symlinked_cache_parent(self):
        root = self.temp / "cache-root"; root.mkdir(mode=0o700); real = self.temp / "real-cache"; (real / "objects/sha256").mkdir(parents=True, mode=0o700)
        os.symlink(real, root / "cache")
        result = run([str(VERIFIER_PATH), "--mode", "verify-only", "--input-cache-root", str(root), "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH)])
        self.assertIn("ARCHIVE_OBJECT_SYMLINK_COMPONENT", result.stdout)

    def test_08_unsafe_permissions(self):
        target = copy_cache(self.temp / "cache-root"); os.chmod(target, 0o620)
        result = run([str(VERIFIER_PATH), "--mode", "verify-only", "--input-cache-root", str(self.temp / "cache-root"), "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH)])
        self.assertIn("ARCHIVE_OBJECT_PERMISSIONS_UNSAFE", result.stdout)

    def test_09_hardlinked_archive(self):
        target = copy_cache(self.temp / "cache-root"); os.link(target, self.temp / "second-link")
        result = run([str(VERIFIER_PATH), "--mode", "verify-only", "--input-cache-root", str(self.temp / "cache-root"), "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH)])
        self.assertIn("ARCHIVE_OBJECT_LINK_COUNT", result.stdout)

    def test_09a_archive_replacement_during_validation(self):
        manifest = self.simple_manifest()
        archive = self.structural(manifest)
        replacement = self.temp / "replacement.tar.gz"
        shutil.copyfile(archive, replacement)
        original_open = verifier.tarfile.open

        def replace_after_pin(*args, **kwargs):
            os.replace(replacement, archive)
            return original_open(*args, **kwargs)

        with mock.patch.object(verifier.tarfile, "open", side_effect=replace_after_pin):
            self.assert_error("ARCHIVE_INODE_REPLACED", verifier.validate_archive, archive, manifest)

    def test_09b_archive_metadata_change_during_validation(self):
        manifest = self.simple_manifest()
        archive = self.structural(manifest)
        original_open = verifier.tarfile.open

        def change_after_pin(*args, **kwargs):
            metadata = archive.stat()
            os.utime(
                archive,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
            )
            return original_open(*args, **kwargs)

        with mock.patch.object(verifier.tarfile, "open", side_effect=change_after_pin):
            self.assert_error("ARCHIVE_METADATA_CHANGED", verifier.validate_archive, archive, manifest)

    def copied_policy(self, replacement=None, manifest_change=None):
        locks = self.temp / "locks"; locks.mkdir(mode=0o700)
        lock = locks / "builder.lock"; manifest = locks / "builder-tree.manifest"
        text = LOCK.read_text()
        if replacement:
            old, new = replacement; text = text.replace(old, new)
        lock.write_text(text); manifest.write_bytes(MANIFEST_PATH.read_bytes())
        os.chmod(lock, 0o600); os.chmod(manifest, 0o600)
        if manifest_change:
            manifest.write_bytes(manifest.read_bytes() + manifest_change)
        return lock, manifest

    def run_policy(self, lock, manifest):
        return run([str(VERIFIER_PATH), "--mode", "verify-only", "--input-cache-root", str(INPUT_CACHE_ROOT), "--lock", str(lock), "--manifest", str(manifest)])

    def test_10_manifest_mismatch(self):
        lock, manifest = self.copied_policy(manifest_change=b"x")
        self.assertIn("BUILDER_MANIFEST_SHA256_MISMATCH", self.run_policy(lock, manifest).stdout)

    def test_11_altered_tag_role(self):
        lock, manifest = self.copied_policy(("builder_release_tag_role: informational-only-not-a-trust-anchor", "builder_release_tag_role: trust-anchor"))
        self.assertIn("BUILDER_LOCK_POLICY_MISMATCH_BUILDER_RELEASE_TAG_ROLE", self.run_policy(lock, manifest).stdout)

    def test_12_altered_trust_binding(self):
        lock, manifest = self.copied_policy(("release_authentication: operationally-approved-by-human-risk-acceptance", "release_authentication: unresolved"))
        self.assertIn("BUILDER_LOCK_POLICY_MISMATCH_RELEASE_AUTHENTICATION", self.run_policy(lock, manifest).stdout)

    def test_13_altered_evidence_binding(self):
        lock, manifest = self.copied_policy(("builder_key_validation_sha256: ce122f491d1b83f7da96e943c4dc1c6b410de7969e2adc8c7b1b4dd5689cca59", "builder_key_validation_sha256: " + "0" * 64))
        self.assertIn("builder_key_validation_sha256", lock.read_text())
        # verify.sh binds the evidence hash; the archive verifier deliberately treats it as audit-only.
        image = self.temp / "image"; shutil.copytree(REPOSITORY / "image", image); (image / "locks/builder.lock").write_text(lock.read_text())
        result = run([str(image / "scripts/verify.sh"), "--image-root", str(image)])
        self.assertIn("invalid builder_key_validation_sha256", result.stdout)

    def selector_result(self, selector):
        return run([str(BUILD), "--preflight", selector, "value"], clean_env({"OMEGA_NETWORK_MODE": "offline"}))

    def test_14_arbitrary_worktree_selector(self): self.assertIn("UNKNOWN_ARGUMENT=--builder-dir", self.selector_result("--builder-dir").stdout)
    def test_15_branch_selector(self): self.assertIn("UNKNOWN_ARGUMENT=--branch", self.selector_result("--branch").stdout)
    def test_16_tag_selector(self): self.assertIn("UNKNOWN_ARGUMENT=--tag", self.selector_result("--tag").stdout)
    def test_17_latest_release_selector(self): self.assertIn("UNKNOWN_ARGUMENT=--latest-release", self.selector_result("--latest-release").stdout)
    def test_18_url_selector(self): self.assertIn("UNKNOWN_ARGUMENT=--url", self.selector_result("--url").stdout)

    def test_19_offline_preflight_consumes_archive(self):
        result = run([str(BUILD), "--preflight", "--source-root", str(REPOSITORY), "--input-cache-root", str(INPUT_CACHE_ROOT)], clean_env({"OMEGA_NETWORK_MODE": "offline"}))
        self.assertIn("BUILDER_ARCHIVE_VALID=YES", result.stdout)
        self.assertIn("BUILDER_CODE_EXECUTED=CONFIG-METADATA-AND-PIPELINE-ONLY", result.stdout)
        self.assertIn("CONFIG_NETWORK_ISOLATION=VERIFIED", result.stdout)
        self.assertIn("CONSTRUCTION_NETWORK_ISOLATION=VERIFIED", result.stdout)
        self.assertIn("SERVICE_INPUT_CACHE=VERIFIED", result.stdout)
        self.assertIn("BUILD_READINESS_CHECK=PASS", result.stdout)
        architecture = os.uname().machine
        if architecture in {"aarch64", "arm64"}:
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("BUILD_PREFLIGHT=PASS", result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                f"unsupported build architecture: {architecture}; expected native arm64",
                result.stdout,
            )

    def test_20_missing_archive_precedes_readiness(self):
        root = self.temp / "cache-root"; root.mkdir(mode=0o700)
        result = run([str(BUILD), "--preflight", "--source-root", str(REPOSITORY), "--input-cache-root", str(root)], clean_env({"OMEGA_NETWORK_MODE": "offline"}))
        self.assertIn("ARCHIVE_OBJECT_MISSING", result.stdout)
        self.assertNotIn("BUILD_READINESS_BLOCKED", result.stdout)

    def structural(self, manifest, transforms=None, extra=None, omit=None):
        archive = self.temp / "fixture.tar.gz"; make_tar(archive, manifest, transforms, extra, omit); return archive

    def simple_manifest(self, mode="100644", data=b"ok", root_override=None):
        return manifest_for({"file": (mode, data)}, root_override=root_override)

    def test_21_path_traversal(self):
        m=self.simple_manifest(); info=tarfile.TarInfo(m.archive_root+"/../escape"); info.type=tarfile.REGTYPE; info.mode=0o664; info.size=2
        self.assert_error("ARCHIVE_PATH_COMPONENT", verifier.validate_archive, self.structural(m, extra=[(info,b"ok")]), m)

    def test_22_duplicate_path(self):
        m=self.simple_manifest(); info=tarfile.TarInfo(m.archive_root+"/file"); info.type=tarfile.REGTYPE; info.mode=0o664; info.size=2
        self.assert_error("ARCHIVE_DUPLICATE_PATH", verifier.validate_archive, self.structural(m, extra=[(info,b"ok")]), m)

    def test_23_absolute_path(self):
        m=self.simple_manifest(); info=tarfile.TarInfo("/absolute"); info.type=tarfile.REGTYPE; info.mode=0o664; info.size=2
        self.assert_error("ARCHIVE_PATH_ABSOLUTE", verifier.validate_archive, self.structural(m, extra=[(info,b"ok")]), m)

    def special_type(self, typeflag, code):
        m=self.simple_manifest(); info=tarfile.TarInfo(m.archive_root+"/special"); info.type=typeflag; info.mode=0o600
        self.assert_error(code, verifier.validate_archive, self.structural(m, extra=[(info,None)]), m)

    def test_24_device_entry(self): self.special_type(tarfile.CHRTYPE,"ARCHIVE_DEVICE")
    def test_25_fifo_entry(self): self.special_type(tarfile.FIFOTYPE,"ARCHIVE_FIFO")
    def test_26_socket_entry(self): self.special_type(b"s","ARCHIVE_SOCKET")
    def test_27_hard_link_entry(self): self.special_type(tarfile.LNKTYPE,"ARCHIVE_HARD_LINK")

    def test_28_unsafe_mode(self):
        m=self.simple_manifest(); self.assert_error("ARCHIVE_SPECIAL_MODE", verifier.validate_archive, self.structural(m,{"file":{"original":b"ok","mode":0o4775}}),m)

    def test_29_unexpected_root(self):
        m=self.simple_manifest(); info=tarfile.TarInfo("other-root/file"); info.type=tarfile.REGTYPE; info.mode=0o664; info.size=2
        self.assert_error("ARCHIVE_UNEXPECTED_ROOT", verifier.validate_archive, self.structural(m,extra=[(info,b"ok")]),m)

    def test_30_escaping_symlink(self):
        m=manifest_for({"link":("120000","../../escape")}); self.assert_error("SYMLINK_TARGET_ESCAPE", verifier.validate_archive,self.structural(m),m)

    def test_31_unexpected_executable_bit(self):
        m=self.simple_manifest(); self.assert_error("ARCHIVE_FILE_MODE",verifier.validate_archive,self.structural(m,{"file":{"original":b"ok","mode":0o775}}),m)

    def test_32_tree_mismatch(self):
        m=self.simple_manifest(root_override="0"*40); self.assert_error("ARCHIVE_ROOT_TREE_MISMATCH",verifier.validate_archive,self.structural(m),m)

    def test_33_untracked_archive_entry(self):
        m=self.simple_manifest(); info=tarfile.TarInfo(m.archive_root+"/extra"); info.type=tarfile.REGTYPE; info.mode=0o664; info.size=2
        self.assert_error("ARCHIVE_UNTRACKED_ENTRY",verifier.validate_archive,self.structural(m,extra=[(info,b"ok")]),m)

    def test_34_missing_archive_entry(self):
        m=self.simple_manifest(); self.assert_error("ARCHIVE_MISSING_ENTRY",verifier.validate_archive,self.structural(m,omit={"file"}),m)

    def test_35_git_content(self):
        m=self.simple_manifest(); info=tarfile.TarInfo(m.archive_root+"/.git/config"); info.type=tarfile.REGTYPE; info.mode=0o664; info.size=2
        self.assert_error("ARCHIVE_GIT_CONTENT",verifier.validate_archive,self.structural(m,extra=[(info,b"ok")]),m)

    def test_36_gitmodules_content(self):
        m=self.simple_manifest(); info=tarfile.TarInfo(m.archive_root+"/.gitmodules"); info.type=tarfile.REGTYPE; info.mode=0o664; info.size=2
        self.assert_error("ARCHIVE_GITMODULES",verifier.validate_archive,self.structural(m,extra=[(info,b"ok")]),m)

    def test_37_git_lfs_pointer(self):
        data=b"version https://git-lfs.github.com/spec/v1\noid sha256:"+b"0"*64+b"\nsize 1\n"; m=self.simple_manifest(data=data)
        self.assert_error("ARCHIVE_GIT_LFS_POINTER",verifier.validate_archive,self.structural(m,{"file":{"original":data}}),m)

    def test_38_submodule_manifest_mode(self):
        path=self.temp/"manifest"; body=("omega-builder-tree-manifest-v1\nproject\trpi-image-gen\nrelease_label\tv2.8.0\nrelease_tag_role\tinformational-only-not-a-trust-anchor\ncommit\t"+verifier.COMMIT+"\nroot_tree\t"+verifier.TREE+"\narchive_sha256\t"+verifier.ARCHIVE_SHA256+"\narchive_top_level\t"+verifier.ARCHIVE_ROOT+"\nentry_count\t1\nmode\ttype\toid\tsize\tpath\ttarget_base64\n160000\tcommit\t"+"0"*40+"\t0\tsubmodule\t-\n").encode(); path.write_bytes(body); os.chmod(path,0o600)
        policy={"builder_tree_manifest_sha256":hashlib.sha256(body).hexdigest()}
        self.assert_error("BUILDER_MANIFEST_MODE",verifier.parse_manifest,path,policy)

    def test_39_control_character_path(self):
        m=self.simple_manifest(); info=tarfile.TarInfo(m.archive_root+"/bad\x01name"); info.type=tarfile.REGTYPE; info.mode=0o664; info.size=2
        self.assert_error("ARCHIVE_PATH_CONTROL_CHARACTER",verifier.validate_archive,self.structural(m,extra=[(info,b"ok")]),m)

    def test_40_build_mode_stops_at_native_architecture_gate(self):
        if os.uname().machine in {"aarch64", "arm64"}:
            self.skipTest("full construction is exercised on the native release builder")
        output = self.temp / "release"
        result=run([str(BUILD),"--build","--source-root",str(REPOSITORY),"--input-cache-root",str(INPUT_CACHE_ROOT),"--output-dir",str(output)],clean_env({"OMEGA_NETWORK_MODE":"offline"}))
        self.assertIn("BUILDER_CODE_EXECUTED=CONFIG-METADATA-AND-PIPELINE-ONLY",result.stdout)
        self.assertIn("CONSTRUCTION_NETWORK_ISOLATION=VERIFIED",result.stdout)
        self.assertIn("SERVICE_INPUT_CACHE=VERIFIED",result.stdout)
        self.assertIn("BUILD_READINESS_CHECK=PASS",result.stdout)
        self.assertIn(
            f"unsupported build architecture: {os.uname().machine}; expected native arm64",
            result.stdout,
        )
        self.assertIn("VERIFIED_BUILDER_DIRECTORY=",result.stdout)
        self.assertNotIn("FULL_IMAGE_CONSTRUCTION_NOT_IMPLEMENTED",result.stdout)
        self.assertFalse(output.exists())

    def extracted_builder(self):
        destination = self.temp / "builder"
        result = run([
            str(VERIFIER_PATH), "--mode", "extract",
            "--input-cache-root", str(INPUT_CACHE_ROOT),
            "--lock", str(LOCK), "--manifest", str(MANIFEST_PATH),
            "--destination", str(destination),
        ])
        self.assertEqual(result.returncode, 0, result.stdout)
        return destination

    def config_result(self, image_root, *, isolated=True):
        builder = self.extracted_builder()
        workspace = self.temp / "config-workspace"
        workspace.mkdir(mode=0o700)
        host_namespace = os.readlink("/proc/self/ns/net")
        command = [
            sys.executable, "-B", str(CONFIG_VERIFIER),
            "--builder-root", str(builder),
            "--omega-image-root", str(image_root),
            "--workspace", str(workspace),
            "--lock", str(pathlib.Path(image_root) / "locks/builder.lock"),
            "--host-network-namespace", host_namespace,
        ]
        if isolated:
            command = ["/usr/bin/unshare", "-Urn", "--", *command]
        return run(command)

    def test_41_authenticated_config_plan(self):
        result = self.config_result(REPOSITORY / "image")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("BUILDER_CONFIG_PLAN_ENTRIES=34", result.stdout)
        self.assertIn("BUILDER_CONFIG_PLAN_SHA256=c3f8efcccbed085eb6c38334e19568389e730641eb25bcca81a4dfd93cba796f", result.stdout)
        self.assertIn("BUILDER_CONFIG_COMPATIBILITY=VERIFIED-LOCAL-PLAN", result.stdout)

    def test_42_config_contract_mismatch(self):
        image = self.temp / "image"
        shutil.copytree(REPOSITORY / "image", image)
        config = image / "config/omega-rpi5-trixie-arm64.yaml"
        config.write_text(config.read_text().replace("timezone: UTC", "timezone: Europe/London"))
        result = self.config_result(image)
        self.assertIn("BUILDER_CONFIG_VALUE_MISMATCH_IGconf_locale_timezone", result.stdout)

    def test_43_config_requires_network_namespace(self):
        result = self.config_result(REPOSITORY / "image", isolated=False)
        self.assertIn("CONFIG_NETWORK_NAMESPACE_NOT_ISOLATED", result.stdout)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--input-cache-root",required=True); args=parser.parse_args()
    INPUT_CACHE_ROOT=pathlib.Path(args.input_cache_root)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(EnforcementTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"RESULT: {result.testsRun-result.failures.__len__()-result.errors.__len__()} passed, {len(result.failures)+len(result.errors)} failed")
    raise SystemExit(0 if result.wasSuccessful() else 1)
