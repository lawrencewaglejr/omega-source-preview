#!/usr/bin/python3
"""Verify locked OCI objects and create a deterministic offline import archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
from dataclasses import dataclass
from typing import Any, BinaryIO, cast


class ValidationError(Exception):
    pass


@dataclass(frozen=True)
class Descriptor:
    sha256: str
    size: int


@dataclass(frozen=True)
class Image:
    name: str
    repository: str
    release_label: str
    index_sha256: str
    manifest: Descriptor
    config: Descriptor
    layers: tuple[Descriptor, ...]


@dataclass(frozen=True)
class Layer:
    descriptor: Descriptor
    diffid: str
    unpacked_size: int


LOCK_KEYS = {
    "schema", "status", "architecture", "service_scope", "reference_policy",
    "floating_tags", "network_at_construction", "image_manifest_path",
    "image_manifest_sha256", "image_count", "object_count", "cache_object_path_policy",
    "object_owner_policy", "object_permissions_policy", "object_link_policy",
    "object_validation", "offline_import_format", "offline_archive_sha256",
    "offline_archive_bytes", "pihole_reference",
    "pihole_index_sha256", "pihole_release_label", "pihole_release_label_role",
    "pihole_source_revision", "pihole_ftl_version", "pihole_packaging_owner",
    "evebox_reference", "evebox_index_sha256", "evebox_release_label",
    "evebox_release_label_role", "evebox_packaging_owner",
}


def require_directory(path: pathlib.Path, code: str) -> pathlib.Path:
    if not path.is_absolute():
        raise ValidationError(f"{code}_NOT_ABSOLUTE")
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ValidationError(f"{code}_MISSING") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValidationError(f"{code}_INVALID")
    if path.resolve() != path:
        raise ValidationError(f"{code}_NOT_CANONICAL")
    return path


def require_regular_file(path: pathlib.Path, code: str) -> pathlib.Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ValidationError(f"{code}_MISSING") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"{code}_INVALID")
    return path


def read_lock(path: pathlib.Path) -> dict[str, str]:
    require_regular_file(path, "OCI_LOCK")
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or any(byte < 0x20 or byte > 0x7E for byte in raw[:-1] if byte != 0x0A):
        raise ValidationError("OCI_LOCK_BYTES_INVALID")
    values: dict[str, str] = {}
    for number, line in enumerate(raw.decode("ascii").splitlines(), 1):
        if not re.fullmatch(r"[a-z][a-z0-9_]*: [!-~]+", line):
            raise ValidationError(f"OCI_LOCK_LINE_INVALID_{number}")
        key, value = line.split(": ", 1)
        if key in values:
            raise ValidationError(f"OCI_LOCK_KEY_DUPLICATE_{key}")
        values[key] = value
    if set(values) != LOCK_KEYS:
        raise ValidationError("OCI_LOCK_SCHEMA_KEYS_INVALID")
    expected = {
        "schema": "omega-oci-images-lock-v2",
        "status": "resolved",
        "architecture": "arm64",
        "service_scope": "pihole,evebox",
        "reference_policy": "digest-only",
        "floating_tags": "forbidden",
        "network_at_construction": "forbidden",
        "image_manifest_path": "locks/oci-images.manifest",
        "image_manifest_sha256": "32760a9e0dd793ea72166728a9fd20d24ce4ee552c9d4a35c3aafdcbee50bff4",
        "image_count": "2",
        "object_count": "22",
        "cache_object_path_policy": "cache/objects/sha256/<lowercase-sha256>",
        "object_owner_policy": "invoking-uid-or-root",
        "object_permissions_policy": "not-group-or-world-writable",
        "object_link_policy": "exactly-one",
        "object_validation": "index-manifest-config-layer-size-sha256-and-rootfs-diffid",
        "offline_import_format": "deterministic-docker-archive",
        "offline_archive_sha256": "6aaeb43b5db42febd12b099286d95cf00c2796068bace351b097cb0a8aebcd60",
        "offline_archive_bytes": "244305920",
        "pihole_reference": "docker.io/pihole/pihole@sha256:a29ad980775f38a8e7524a206ff9c125bc6fcfd9de8de1fc93d2de0671cc1d34",
        "pihole_index_sha256": "f7d1be836e3bc608b56d82fc9904f5a831cdfbc0dc9c6d58f94e4c985c70038b",
        "pihole_release_label": "2026.07.2",
        "pihole_release_label_role": "informational-only",
        "pihole_source_revision": "dd91b4847d97f0aac68bfefd1c108ed0627e6c68",
        "pihole_ftl_version": "v6.7",
        "pihole_packaging_owner": "official-pihole-image",
        "evebox_reference": "docker.io/jasonish/evebox@sha256:7ca9aab505eb0239cc3987a4cb30ff5864585d3856d1b3f0a66dbfb442ad987d",
        "evebox_index_sha256": "216ef6eb5bfcc1d8d9b13a41ba38eb067060e68c3970fa4579d07c8f5d5a9326",
        "evebox_release_label": "0.28.0",
        "evebox_release_label_role": "informational-only",
        "evebox_packaging_owner": "upstream-evebox-image",
    }
    for key, value in expected.items():
        if values.get(key) != value:
            raise ValidationError(f"OCI_LOCK_VALUE_INVALID_{key}")
    return values


def parse_descriptor(value: str, number: int) -> Descriptor:
    fields = value.split(":")
    if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]) or not re.fullmatch(r"[1-9][0-9]*", fields[1]):
        raise ValidationError(f"OCI_DESCRIPTOR_INVALID_{number}")
    return Descriptor(fields[0], int(fields[1]))


def parse_manifest(path: pathlib.Path, expected_digest: str) -> list[Image]:
    require_regular_file(path, "OCI_MANIFEST")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValidationError("OCI_MANIFEST_SHA256_MISMATCH")
    if not raw.endswith(b"\n"):
        raise ValidationError("OCI_MANIFEST_FINAL_NEWLINE_MISSING")
    if any(byte not in (0x09, 0x0A) and not 0x20 <= byte <= 0x7E for byte in raw):
        raise ValidationError("OCI_MANIFEST_BYTES_INVALID")
    lines = raw.decode("ascii").splitlines()
    expected_header = [
        "omega-oci-images-manifest-v1", "architecture\tarm64", "image_count\t2",
        "object_count\t22",
        "columns\tname\trepository\trelease_label\tindex_sha256\tmanifest_sha256\tmanifest_size\tconfig_sha256\tconfig_size\tlayers_sha256_size",
    ]
    if lines[:5] != expected_header:
        raise ValidationError("OCI_MANIFEST_HEADER_INVALID")
    images: list[Image] = []
    for number, line in enumerate(lines[5:], 6):
        fields = line.split("\t")
        if len(fields) != 9:
            raise ValidationError(f"OCI_MANIFEST_FIELDS_INVALID_{number}")
        name, repository, release_label, index_digest = fields[:4]
        if name not in {"evebox", "pihole"} or not re.fullmatch(r"[a-z0-9-]+/[a-z0-9-]+", repository):
            raise ValidationError(f"OCI_IMAGE_IDENTITY_INVALID_{number}")
        if not re.fullmatch(r"[0-9A-Za-z.+-]+", release_label) or not re.fullmatch(r"[0-9a-f]{64}", index_digest):
            raise ValidationError(f"OCI_IMAGE_REFERENCE_INVALID_{number}")
        manifest = parse_descriptor(f"{fields[4]}:{fields[5]}", number)
        config = parse_descriptor(f"{fields[6]}:{fields[7]}", number)
        layers = tuple(parse_descriptor(item, number) for item in fields[8].split(","))
        images.append(Image(name, repository, release_label, index_digest, manifest, config, layers))
    if [image.name for image in images] != ["evebox", "pihole"]:
        raise ValidationError("OCI_MANIFEST_IMAGE_ORDER_INVALID")
    objects = {
        digest
        for image in images
        for digest in (
            image.index_sha256, image.manifest.sha256, image.config.sha256,
            *(layer.sha256 for layer in image.layers),
        )
    }
    if len(objects) != 22:
        raise ValidationError("OCI_MANIFEST_OBJECT_COUNT_MISMATCH")
    return images


def open_object(root: pathlib.Path, digest: str) -> tuple[int, os.stat_result, pathlib.Path]:
    path = root / "cache/objects/sha256" / digest
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValidationError(f"OCI_OBJECT_OPEN_FAILED_{digest}") from exc
    metadata = os.fstat(fd)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.getuid()}
        or metadata.st_mode & 0o022
    ):
        os.close(fd)
        raise ValidationError(f"OCI_OBJECT_METADATA_INVALID_{digest}")
    return fd, metadata, path


def verify_object(root: pathlib.Path, descriptor: Descriptor, *, capture: bool = False) -> bytes | None:
    fd, before, path = open_object(root, descriptor.sha256)
    try:
        if before.st_size != descriptor.size:
            raise ValidationError(f"OCI_OBJECT_SIZE_MISMATCH_{descriptor.sha256}")
        sha256 = hashlib.sha256()
        content = bytearray() if capture else None
        with os.fdopen(os.dup(fd), "rb", closefd=True) as source:
            while chunk := source.read(1024 * 1024):
                sha256.update(chunk)
                if content is not None:
                    content.extend(chunk)
        if sha256.hexdigest() != descriptor.sha256:
            raise ValidationError(f"OCI_OBJECT_SHA256_MISMATCH_{descriptor.sha256}")
        after = os.fstat(fd)
        current = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_uid, before.st_gid) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_uid, after.st_gid
        ) or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ValidationError(f"OCI_OBJECT_CHANGED_{descriptor.sha256}")
        return bytes(content) if content is not None else None
    finally:
        os.close(fd)


def json_object(data: bytes | None, code: str) -> dict[str, Any]:
    try:
        value = json.loads(data or b"")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError(f"{code}_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{code}_JSON_NOT_OBJECT")
    return value


def descriptor_from_json(value: Any, code: str) -> Descriptor:
    if not isinstance(value, dict):
        raise ValidationError(f"{code}_DESCRIPTOR_INVALID")
    digest = value.get("digest")
    size = value.get("size")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or not isinstance(size, int):
        raise ValidationError(f"{code}_DESCRIPTOR_INVALID")
    return Descriptor(digest.removeprefix("sha256:"), size)


def verify_rootfs_diffids(root: pathlib.Path, image: Image, config: dict[str, Any]) -> tuple[Layer, ...]:
    rootfs = config.get("rootfs")
    diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
    if not isinstance(diff_ids, list) or len(diff_ids) != len(image.layers):
        raise ValidationError(f"OCI_CONFIG_DIFFIDS_INVALID_{image.name}")
    verified: list[Layer] = []
    for layer, expected in zip(image.layers, diff_ids, strict=True):
        if not isinstance(expected, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
            raise ValidationError(f"OCI_CONFIG_DIFFID_INVALID_{image.name}")
        fd, before, path = open_object(root, layer.sha256)
        try:
            digest = hashlib.sha256()
            try:
                with os.fdopen(os.dup(fd), "rb", closefd=True) as compressed:
                    with gzip.GzipFile(fileobj=compressed, mode="rb") as stream:
                        unpacked_size = 0
                        while chunk := stream.read(1024 * 1024):
                            digest.update(chunk)
                            unpacked_size += len(chunk)
            except (OSError, EOFError) as exc:
                raise ValidationError(f"OCI_LAYER_GZIP_INVALID_{image.name}") from exc
            if f"sha256:{digest.hexdigest()}" != expected:
                raise ValidationError(f"OCI_LAYER_DIFFID_MISMATCH_{image.name}")
            after = os.fstat(fd)
            current = path.lstat()
            if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size) or (
                current.st_dev, current.st_ino
            ) != (before.st_dev, before.st_ino):
                raise ValidationError(f"OCI_LAYER_CHANGED_{image.name}")
        finally:
            os.close(fd)
        verified.append(Layer(layer, expected.removeprefix("sha256:"), unpacked_size))
    return tuple(verified)


def verify_image(root: pathlib.Path, image: Image) -> tuple[str, tuple[Layer, ...]]:
    index_path = root / "cache/objects/sha256" / image.index_sha256
    index_size = index_path.lstat().st_size
    index = json_object(verify_object(root, Descriptor(image.index_sha256, index_size), capture=True), "OCI_INDEX")
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise ValidationError(f"OCI_INDEX_MANIFESTS_INVALID_{image.name}")
    matches = []
    for value in manifests:
        if not isinstance(value, dict):
            continue
        platform = value.get("platform")
        if isinstance(platform, dict) and platform.get("os") == "linux" and platform.get("architecture") == "arm64":
            descriptor = descriptor_from_json(value, "OCI_INDEX")
            if descriptor == image.manifest:
                matches.append(value)
    if len(matches) != 1:
        raise ValidationError(f"OCI_INDEX_ARM64_SELECTION_INVALID_{image.name}")
    manifest = json_object(verify_object(root, image.manifest, capture=True), "OCI_IMAGE_MANIFEST")
    if manifest.get("schemaVersion") != 2 or descriptor_from_json(manifest.get("config"), "OCI_CONFIG") != image.config:
        raise ValidationError(f"OCI_IMAGE_MANIFEST_CONFIG_INVALID_{image.name}")
    layer_values = manifest.get("layers")
    if not isinstance(layer_values, list) or tuple(
        descriptor_from_json(value, "OCI_LAYER") for value in layer_values
    ) != image.layers:
        raise ValidationError(f"OCI_IMAGE_MANIFEST_LAYERS_INVALID_{image.name}")
    config = json_object(verify_object(root, image.config, capture=True), "OCI_CONFIG")
    if config.get("architecture") != "arm64" or config.get("os") != "linux":
        raise ValidationError(f"OCI_CONFIG_PLATFORM_INVALID_{image.name}")
    for layer in image.layers:
        verify_object(root, layer)
    layers = verify_rootfs_diffids(root, image, config)
    run_config = config.get("config")
    if not isinstance(run_config, dict):
        raise ValidationError(f"OCI_RUN_CONFIG_INVALID_{image.name}")
    if image.name == "pihole":
        labels = run_config.get("Labels")
        if not isinstance(labels, dict) or labels.get("org.opencontainers.image.version") != "2026.07.2" or labels.get("org.opencontainers.image.revision") != "dd91b4847d97f0aac68bfefd1c108ed0627e6c68":
            raise ValidationError("OCI_PIHOLE_PROVENANCE_LABELS_INVALID")
    elif run_config.get("Entrypoint") != ["/docker-entrypoint.sh"] or run_config.get("Cmd") != ["/bin/evebox"]:
        raise ValidationError("OCI_EVEBOX_RUN_CONFIG_INVALID")
    media_type = manifest.get("mediaType")
    if not isinstance(media_type, str) or media_type not in {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }:
        raise ValidationError(f"OCI_MANIFEST_MEDIA_TYPE_INVALID_{image.name}")
    return media_type, layers


def tar_info(name: str, *, size: int = 0, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name + ("/" if directory else ""))
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o755 if directory else 0o644
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 1787801458
    info.size = 0 if directory else size
    return info


def prepare_archive(
    root: pathlib.Path,
    destination: pathlib.Path,
    images: list[Image],
    layers_by_image: dict[str, tuple[Layer, ...]],
) -> tuple[str, int]:
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise ValidationError("OCI_ARCHIVE_DESTINATION_INVALID")
    parent = require_directory(destination.parent, "OCI_ARCHIVE_PARENT")
    if parent != destination.parent:
        raise ValidationError("OCI_ARCHIVE_PARENT_INVALID")
    docker_manifest = []
    for image in images:
        docker_manifest.append({
            "Config": f"{image.config.sha256}.json",
            "RepoTags": [f"docker.io/{image.repository}:{image.release_label}"],
            "Layers": [f"{layer.descriptor.sha256}/layer.tar" for layer in layers_by_image[image.name]],
        })
    manifest_bytes = (json.dumps(docker_manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    with destination.open("xb") as raw_archive:
        with tarfile.open(fileobj=raw_archive, mode="w", format=tarfile.GNU_FORMAT) as archive:
            archive.addfile(tar_info("manifest.json", size=len(manifest_bytes)), io.BytesIO(manifest_bytes))
            for image in images:
                config_bytes = verify_object(root, image.config, capture=True)
                assert config_bytes is not None
                archive.addfile(
                    tar_info(f"{image.config.sha256}.json", size=len(config_bytes)),
                    io.BytesIO(config_bytes),
                )
            seen_layers: set[str] = set()
            for image in images:
                for layer in layers_by_image[image.name]:
                    digest = layer.descriptor.sha256
                    if digest in seen_layers:
                        continue
                    seen_layers.add(digest)
                    archive.addfile(tar_info(digest, directory=True))
                    source = root / "cache/objects/sha256" / digest
                    with source.open("rb") as compressed:
                        with gzip.GzipFile(fileobj=compressed, mode="rb") as content:
                            archive.addfile(
                                tar_info(f"{digest}/layer.tar", size=layer.unpacked_size),
                                cast(BinaryIO, content),
                            )
    os.chmod(destination, 0o600)
    with destination.open("rb") as completed_archive:
        archive_digest = hashlib.file_digest(completed_archive, "sha256").hexdigest()
    print(f"OCI_ARCHIVE_SHA256={archive_digest}")
    print(f"OCI_ARCHIVE_BYTES={destination.stat().st_size}")
    return archive_digest, destination.stat().st_size


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-cache-root", required=True, type=pathlib.Path)
    parser.add_argument("--lock", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--prepare-archive", type=pathlib.Path)
    args = parser.parse_args()
    root = require_directory(args.input_cache_root, "INPUT_CACHE_ROOT")
    require_directory(root / "cache", "INPUT_CACHE_DIRECTORY")
    require_directory(root / "cache/objects", "INPUT_OBJECTS_DIRECTORY")
    require_directory(root / "cache/objects/sha256", "INPUT_SHA256_DIRECTORY")
    lock = read_lock(args.lock)
    images = parse_manifest(args.manifest, lock["image_manifest_sha256"])
    verified = {image.name: verify_image(root, image) for image in images}
    if args.prepare_archive is not None:
        archive_identity = prepare_archive(
            root,
            args.prepare_archive,
            images,
            {name: result[1] for name, result in verified.items()},
        )
        if archive_identity != (lock["offline_archive_sha256"], int(lock["offline_archive_bytes"])):
            raise ValidationError("OCI_ARCHIVE_IDENTITY_MISMATCH")
    print("OCI_OBJECTS_VERIFIED=22")
    print("OCI_IMAGES_VERIFIED=2")
    print("OCI_CACHE=VERIFIED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
