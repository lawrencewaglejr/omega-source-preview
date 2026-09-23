#!/usr/bin/python3
"""Exercise locked offline inputs; pass --input-cache-root for integration tests."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
REPO = pathlib.Path(__file__).resolve().parents[2]
CACHE_ROOT: pathlib.Path | None = None


def load_verifier(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "image/scripts" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PACKAGES = load_verifier("omega_package_verifier", "verify-package-cache.py")
OCI = load_verifier("omega_oci_verifier", "verify-oci-cache.py")


def sha256(path: pathlib.Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def object_path(root: pathlib.Path, digest: str) -> pathlib.Path:
    return root / "cache/objects/sha256" / digest


def put_object(root: pathlib.Path, content: bytes) -> str:
    digest = hashlib.sha256(content).hexdigest()
    path = object_path(root, digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(0o600)
    return digest


class ManifestTests(unittest.TestCase):
    def test_checked_in_locks_and_manifests_agree(self):
        package_lock = PACKAGES.read_lock(REPO / "image/locks/packages.lock")
        packages = PACKAGES.parse_manifest(
            REPO / "image/locks/packages.manifest", package_lock["package_manifest_sha256"]
        )
        self.assertEqual(len(packages), int(package_lock["package_count"]))
        oci_lock = OCI.read_lock(REPO / "image/locks/oci-images.lock")
        images = OCI.parse_manifest(
            REPO / "image/locks/oci-images.manifest", oci_lock["image_manifest_sha256"]
        )
        self.assertEqual(len(images), int(oci_lock["image_count"]))

    def test_manifest_byte_tampering_is_rejected(self):
        for module, name, prefix, digest_key in (
            (PACKAGES, "packages", "PACKAGE", "package_manifest_sha256"),
            (OCI, "oci-images", "OCI", "image_manifest_sha256"),
        ):
            with self.subTest(manifest=name), tempfile.TemporaryDirectory() as directory:
                lock = module.read_lock(REPO / f"image/locks/{name}.lock")
                path = pathlib.Path(directory) / "manifest"
                path.write_bytes((REPO / f"image/locks/{name}.manifest").read_bytes() + b"\n")
                with self.assertRaisesRegex(module.ValidationError, f"{prefix}_MANIFEST_SHA256_MISMATCH"):
                    module.parse_manifest(path, lock[digest_key])

    def test_duplicate_package_identity_is_rejected(self):
        raw = (REPO / "image/locks/packages.manifest").read_bytes()
        malformed = raw + raw.splitlines(keepends=True)[4]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest"
            path.write_bytes(malformed)
            with self.assertRaisesRegex(PACKAGES.ValidationError, "PACKAGE_IDENTITY_DUPLICATE"):
                PACKAGES.parse_manifest(path, hashlib.sha256(malformed).hexdigest())

    def test_package_upstream_traversal_is_rejected(self):
        lines = (REPO / "image/locks/packages.manifest").read_text().splitlines()
        fields = lines[4].split("\t")
        repository = fields[5].split(",")[0]
        fields[6] = f"{repository}=../../escape.deb"
        lines[4] = "\t".join(fields)
        malformed = ("\n".join(lines) + "\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest"
            path.write_bytes(malformed)
            with self.assertRaisesRegex(PACKAGES.ValidationError, "PACKAGE_UPSTREAM_PATH_INVALID"):
                PACKAGES.parse_manifest(path, hashlib.sha256(malformed).hexdigest())


class CacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if CACHE_ROOT is None:
            raise unittest.SkipTest("supply --input-cache-root to test genuine cached inputs")
        cls.root = PACKAGES.require_directory(CACHE_ROOT, "TEST_CACHE")
        cls.package_lock = PACKAGES.read_lock(REPO / "image/locks/packages.lock")
        cls.packages = PACKAGES.parse_manifest(
            REPO / "image/locks/packages.manifest", cls.package_lock["package_manifest_sha256"]
        )
        cls.oci_lock = OCI.read_lock(REPO / "image/locks/oci-images.lock")
        cls.images = OCI.parse_manifest(
            REPO / "image/locks/oci-images.manifest", cls.oci_lock["image_manifest_sha256"]
        )
        cls.package = min(cls.packages, key=lambda package: package.size)
        cls.descriptor = min(
            (image.config for image in cls.images), key=lambda descriptor: descriptor.size
        )

    def test_genuine_package_cache_and_reproducible_repository(self):
        controls = {
            package.sha256: PACKAGES.verify_object(self.root, package) for package in self.packages
        }
        expected = (
            self.package_lock["offline_packages_index_sha256"],
            int(self.package_lock["offline_packages_index_bytes"]),
            self.package_lock["offline_release_sha256"],
            int(self.package_lock["offline_release_bytes"]),
        )
        for iteration in range(2):
            with self.subTest(iteration=iteration), tempfile.TemporaryDirectory() as directory:
                destination = pathlib.Path(directory) / "repository"
                self.assertEqual(PACKAGES.prepare_repository(destination, self.packages, controls), expected)
                PACKAGES.copy_packages(self.root, destination, self.packages)
                index = destination / "dists/omega/main/binary-arm64/Packages"
                release = destination / "dists/omega/Release"
                self.assertEqual((sha256(index), index.stat().st_size, sha256(release), release.stat().st_size), expected)
                self.assertEqual(len(list((destination / "pool").iterdir())), len(self.packages))
                for package in self.packages:
                    copied = destination / "pool" / f"{package.sha256}.deb"
                    original = object_path(self.root, package.sha256)
                    self.assertEqual((sha256(copied), copied.stat().st_size), (package.sha256, package.size))
                    self.assertNotEqual(
                        (copied.stat().st_dev, copied.stat().st_ino),
                        (original.stat().st_dev, original.stat().st_ino),
                    )
                    self.assertEqual(copied.stat().st_nlink, 1)

    def test_package_changed_bytes_size_links_and_permissions_are_rejected(self):
        for mutation, error in (
            ("bytes", "SHA256_MISMATCH"),
            ("truncate", "SIZE_MISMATCH"),
            ("symlink", "OPEN_FAILED"),
            ("hardlink", "LINK_COUNT_INVALID"),
            ("writable", "PERMISSIONS_INVALID"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                target = object_path(root, self.package.sha256)
                target.parent.mkdir(parents=True)
                shutil.copyfile(object_path(self.root, self.package.sha256), target)
                target.chmod(0o600)
                self.mutate(root, target, mutation)
                with self.assertRaisesRegex(PACKAGES.ValidationError, f"PACKAGE_OBJECT_{error}"):
                    PACKAGES.verify_object(root, self.package)

    def test_package_control_identity_must_match_manifest(self):
        wrong_package = dataclasses.replace(self.package, version=self.package.version + "+wrong")
        with self.assertRaisesRegex(PACKAGES.ValidationError, "PACKAGE_CONTROL_MISMATCH.*Version"):
            PACKAGES.verify_object(self.root, wrong_package)

    def test_matching_digest_does_not_make_invalid_deb_acceptable(self):
        content = b"This is not a Debian package archive.\n"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            digest = put_object(root, content)
            package = dataclasses.replace(self.package, sha256=digest, size=len(content))
            with self.assertRaisesRegex(PACKAGES.ValidationError, "PACKAGE_DEB_FORMAT_INVALID"):
                PACKAGES.verify_object(root, package)

    def test_package_copy_detects_input_changed_after_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            destination = root / "repository"
            destination.joinpath("pool").mkdir(parents=True)
            target = object_path(root, self.package.sha256)
            target.parent.mkdir(parents=True)
            target.write_bytes(b"replacement package")
            with self.assertRaisesRegex(PACKAGES.ValidationError, "OFFLINE_REPOSITORY_COPY_MISMATCH"):
                PACKAGES.copy_packages(root, destination, [self.package])

    @staticmethod
    def mutate(root, target, mutation):
        if mutation == "bytes":
            with target.open("r+b") as content:
                first = content.read(1)
                content.seek(0)
                content.write(bytes([first[0] ^ 0x01]))
        elif mutation == "truncate":
            with target.open("r+b") as content:
                content.truncate(target.stat().st_size - 1)
        elif mutation == "symlink":
            renamed = root / "actual-object"
            target.rename(renamed)
            target.symlink_to(renamed)
        elif mutation == "hardlink":
            os.link(target, root / "second-link")
        elif mutation == "writable":
            target.chmod(0o620)
        else:
            raise AssertionError(mutation)

    def test_oci_changed_bytes_size_links_and_permissions_are_rejected(self):
        for mutation, error in (
            ("bytes", "SHA256_MISMATCH"),
            ("truncate", "SIZE_MISMATCH"),
            ("symlink", "OPEN_FAILED"),
            ("hardlink", "METADATA_INVALID"),
            ("writable", "METADATA_INVALID"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                target = object_path(root, self.descriptor.sha256)
                target.parent.mkdir(parents=True)
                shutil.copyfile(object_path(self.root, self.descriptor.sha256), target)
                target.chmod(0o600)
                self.mutate(root, target, mutation)
                with self.assertRaisesRegex(OCI.ValidationError, f"OCI_OBJECT_{error}"):
                    OCI.verify_object(root, self.descriptor)

    def test_oci_index_without_arm64_target_is_rejected(self):
        image = self.images[0]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            index = json.loads(object_path(self.root, image.index_sha256).read_bytes())
            index["manifests"] = [
                item for item in index["manifests"] if item.get("platform", {}).get("architecture") != "arm64"
            ]
            digest = put_object(root, json.dumps(index).encode())
            with self.assertRaisesRegex(OCI.ValidationError, "OCI_INDEX_ARM64_SELECTION_INVALID"):
                OCI.verify_image(root, dataclasses.replace(image, index_sha256=digest))

    def test_oci_uncompressed_layer_digest_must_match(self):
        image = min(self.images, key=lambda item: min(layer.size for layer in item.layers))
        layer = min(image.layers, key=lambda item: item.size)
        with self.assertRaisesRegex(OCI.ValidationError, "OCI_LAYER_DIFFID_MISMATCH"):
            OCI.verify_rootfs_diffids(
                self.root,
                dataclasses.replace(image, layers=(layer,)),
                {"rootfs": {"diff_ids": ["sha256:" + "0" * 64]}},
            )

    def test_oci_matching_digest_does_not_make_invalid_gzip_acceptable(self):
        content = b"This is not a compressed container layer.\n"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            digest = put_object(root, content)
            descriptor = OCI.Descriptor(digest, len(content))
            OCI.verify_object(root, descriptor)
            with self.assertRaisesRegex(OCI.ValidationError, "OCI_LAYER_GZIP_INVALID"):
                OCI.verify_rootfs_diffids(
                    root,
                    dataclasses.replace(self.images[0], layers=(descriptor,)),
                    {"rootfs": {"diff_ids": ["sha256:" + "0" * 64]}},
                )

    def test_genuine_oci_cache_and_docker_archive(self):
        layers_by_image = {
            image.name: OCI.verify_image(self.root, image)[1] for image in self.images
        }
        expected = (self.oci_lock["offline_archive_sha256"], int(self.oci_lock["offline_archive_bytes"]))
        for iteration in range(2):
            with self.subTest(iteration=iteration), tempfile.TemporaryDirectory() as directory:
                destination = pathlib.Path(directory) / "services.tar"
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(OCI.prepare_archive(self.root, destination, self.images, layers_by_image), expected)
                self.assertEqual((sha256(destination), destination.stat().st_size), expected)
                with tarfile.open(destination, "r:") as archive:
                    manifest_file = archive.extractfile("manifest.json")
                    self.assertIsNotNone(manifest_file)
                    entries = json.load(manifest_file)
                    self.assertEqual(len(entries), len(self.images))
                    for image, entry in zip(self.images, entries, strict=True):
                        self.assertEqual(entry["RepoTags"], [f"docker.io/{image.repository}:{image.release_label}"])
                        config_file = archive.extractfile(entry["Config"])
                        self.assertIsNotNone(config_file)
                        config_bytes = config_file.read()
                        self.assertEqual(hashlib.sha256(config_bytes).hexdigest(), image.config.sha256)
                        config = json.loads(config_bytes)
                        self.assertEqual(len(entry["Layers"]), len(config["rootfs"]["diff_ids"]))
                        for name, diffid in zip(entry["Layers"], config["rootfs"]["diff_ids"], strict=True):
                            layer = archive.extractfile(name)
                            self.assertIsNotNone(layer)
                            self.assertEqual("sha256:" + hashlib.file_digest(layer, "sha256").hexdigest(), diffid)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-cache-root", type=pathlib.Path)
    arguments, remaining = parser.parse_known_args()
    CACHE_ROOT = arguments.input_cache_root
    unittest.main(argv=[sys.argv[0], *remaining])
