#!/usr/bin/python3
"""Verify OMEGA's exact Debian package set and prepare its offline APT view."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass


class ValidationError(Exception):
    pass


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    architecture: str
    size: int
    sha256: str
    repositories: str
    upstream_paths: str


LOCK_KEYS = {
    "schema",
    "status",
    "architecture",
    "service_scope",
    "version_policy",
    "installer_policy",
    "package_manifest_path",
    "package_manifest_sha256",
    "package_count",
    "cache_object_path_policy",
    "package_owner_policy",
    "package_permissions_policy",
    "package_link_policy",
    "package_archive_validation",
    "offline_repository_suite",
    "offline_repository_component",
    "offline_repository_trust",
    "offline_packages_index_sha256",
    "offline_packages_index_bytes",
    "offline_release_sha256",
    "offline_release_bytes",
    "suricata_package",
    "docker_packages",
    "wazuh_agent_package",
    "tailscale_package",
    "pihole_delivery",
    "evebox_delivery",
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
    require_regular_file(path, "PACKAGE_LOCK")
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or any(byte < 0x20 or byte > 0x7E for byte in raw[:-1] if byte != 0x0A):
        raise ValidationError("PACKAGE_LOCK_BYTES_INVALID")
    values: dict[str, str] = {}
    for number, line in enumerate(raw.decode("ascii").splitlines(), 1):
        if not re.fullmatch(r"[a-z][a-z0-9_]*: [!-~]+", line):
            raise ValidationError(f"PACKAGE_LOCK_LINE_INVALID_{number}")
        key, value = line.split(": ", 1)
        if key in values:
            raise ValidationError(f"PACKAGE_LOCK_KEY_DUPLICATE_{key}")
        values[key] = value
    if set(values) != LOCK_KEYS:
        raise ValidationError("PACKAGE_LOCK_SCHEMA_KEYS_INVALID")
    expected = {
        "schema": "omega-packages-lock-v2",
        "status": "resolved",
        "architecture": "arm64",
        "service_scope": "pihole,suricata,docker,evebox,wazuh-agent,tailscale",
        "version_policy": "exact-versions-only",
        "installer_policy": "verified-content-addressed-deb-only",
        "package_manifest_path": "locks/packages.manifest",
        "package_count": "313",
        "cache_object_path_policy": "cache/objects/sha256/<lowercase-sha256>",
        "package_owner_policy": "invoking-uid-or-root",
        "package_permissions_policy": "not-group-or-world-writable",
        "package_link_policy": "exactly-one",
        "package_archive_validation": "sha256-size-control-fields-and-debian-ar-format",
        "offline_repository_suite": "omega",
        "offline_repository_component": "main",
        "offline_repository_trust": "manifest-verified-local-content-only",
        "offline_packages_index_sha256": "195b39e0d30658ebd4663cc23764edaee07056fd6eef7748eaa218af88cd9d12",
        "offline_packages_index_bytes": "334587",
        "offline_release_sha256": "d751dd2b9a473d0d0ea0e95e6a7fcee22d13487fae087c9c575f1d9133398a7c",
        "offline_release_bytes": "246",
        "suricata_package": "suricata=1:7.0.10-1+deb13u4",
        "docker_packages": "docker.io=26.1.5+dfsg1-9+deb13u1,docker-cli=26.1.5+dfsg1-9+deb13u1,containerd=1.7.24~ds1-6+deb13u1,runc=1.1.15+ds1-2+b4,tini=0.19.0-3+b7",
        "wazuh_agent_package": "wazuh-agent=4.14.7-1",
        "tailscale_package": "tailscale=1.102.3",
        "pihole_delivery": "oci-image",
        "evebox_delivery": "oci-image",
    }
    for key, value in expected.items():
        if values.get(key) != value:
            raise ValidationError(f"PACKAGE_LOCK_VALUE_INVALID_{key}")
    if not re.fullmatch(r"[0-9a-f]{64}", values["package_manifest_sha256"]):
        raise ValidationError("PACKAGE_LOCK_MANIFEST_SHA256_INVALID")
    return values


def parse_manifest(path: pathlib.Path, expected_digest: str) -> list[Package]:
    require_regular_file(path, "PACKAGE_MANIFEST")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValidationError("PACKAGE_MANIFEST_SHA256_MISMATCH")
    if not raw.endswith(b"\n"):
        raise ValidationError("PACKAGE_MANIFEST_FINAL_NEWLINE_MISSING")
    if any(byte not in (0x09, 0x0A) and not 0x20 <= byte <= 0x7E for byte in raw):
        raise ValidationError("PACKAGE_MANIFEST_BYTES_INVALID")
    lines = raw.decode("ascii").splitlines()
    expected_header = [
        "omega-package-manifest-v1",
        "architecture\tarm64",
        "package_count\t313",
        "columns\tpackage\tversion\tarchitecture\tsize\tsha256\trepositories\tupstream_paths",
    ]
    if lines[:4] != expected_header:
        raise ValidationError("PACKAGE_MANIFEST_HEADER_INVALID")
    packages: list[Package] = []
    identities: set[tuple[str, str]] = set()
    allowed_repositories = {
        "debian-trixie",
        "debian-trixie-updates",
        "debian-trixie-security",
        "raspberrypi-trixie",
        "wazuh-stable",
        "tailscale-trixie",
    }
    for number, line in enumerate(lines[4:], 5):
        fields = line.split("\t")
        if len(fields) != 7:
            raise ValidationError(f"PACKAGE_MANIFEST_FIELDS_INVALID_{number}")
        name, version, architecture, size_text, digest, repositories, upstream_paths = fields
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name):
            raise ValidationError(f"PACKAGE_NAME_INVALID_{number}")
        if not version or "/" in version or not all(0x21 <= ord(char) <= 0x7E for char in version):
            raise ValidationError(f"PACKAGE_VERSION_INVALID_{number}")
        if architecture not in {"all", "arm64"}:
            raise ValidationError(f"PACKAGE_ARCHITECTURE_INVALID_{number}")
        if not re.fullmatch(r"[1-9][0-9]*", size_text):
            raise ValidationError(f"PACKAGE_SIZE_INVALID_{number}")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValidationError(f"PACKAGE_SHA256_INVALID_{number}")
        repository_list = repositories.split(",")
        if repository_list != sorted(set(repository_list)) or not set(repository_list) <= allowed_repositories:
            raise ValidationError(f"PACKAGE_REPOSITORIES_INVALID_{number}")
        path_repositories: list[str] = []
        for item in upstream_paths.split(","):
            if "=" not in item:
                raise ValidationError(f"PACKAGE_UPSTREAM_PATH_INVALID_{number}")
            repository, relative = item.split("=", 1)
            upstream_path = pathlib.PurePosixPath(relative)
            if (
                repository not in repository_list
                or relative.startswith("/")
                or not relative.endswith(".deb")
                or any(part in {"", ".", ".."} for part in upstream_path.parts)
                or not re.fullmatch(r"[A-Za-z0-9_./+~%-]+", relative)
            ):
                raise ValidationError(f"PACKAGE_UPSTREAM_PATH_INVALID_{number}")
            path_repositories.append(repository)
        if sorted(set(path_repositories)) != repository_list:
            raise ValidationError(f"PACKAGE_UPSTREAM_REPOSITORIES_MISMATCH_{number}")
        identity = (name, architecture)
        if identity in identities:
            raise ValidationError(f"PACKAGE_IDENTITY_DUPLICATE_{number}")
        identities.add(identity)
        packages.append(
            Package(name, version, architecture, int(size_text), digest, repositories, upstream_paths)
        )
    if len(packages) != 313:
        raise ValidationError("PACKAGE_MANIFEST_COUNT_MISMATCH")
    order = [(item.name.encode(), item.architecture.encode(), item.version.encode()) for item in packages]
    if order != sorted(order):
        raise ValidationError("PACKAGE_MANIFEST_ORDER_INVALID")
    return packages


def inspect_deb(fd: int, package: Package) -> str:
    tool = pathlib.Path("/usr/bin/dpkg-deb")
    metadata = tool.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(tool, os.X_OK):
        raise ValidationError("DPKG_DEB_TOOL_INVALID")
    completed = subprocess.run(
        [str(tool), "--field", f"/proc/self/fd/{fd}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        pass_fds=(fd,),
    )
    if completed.returncode != 0:
        raise ValidationError(f"PACKAGE_DEB_FORMAT_INVALID_{package.name}")
    try:
        control = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"PACKAGE_CONTROL_ENCODING_INVALID_{package.name}") from exc
    fields: dict[str, str] = {}
    for line in control.splitlines():
        if line.startswith((" ", "\t")):
            continue
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key] = value
    expected = {
        "Package": package.name,
        "Version": package.version,
        "Architecture": package.architecture,
    }
    for key, value in expected.items():
        if fields.get(key) != value:
            raise ValidationError(f"PACKAGE_CONTROL_MISMATCH_{package.name}_{key}")
    return control


def verify_object(root: pathlib.Path, package: Package) -> str:
    path = root / "cache/objects/sha256" / package.sha256
    expected_parent = root / "cache/objects/sha256"
    if path.parent.resolve() != expected_parent:
        raise ValidationError(f"PACKAGE_OBJECT_PATH_INVALID_{package.name}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValidationError(f"PACKAGE_OBJECT_OPEN_FAILED_{package.name}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValidationError(f"PACKAGE_OBJECT_NOT_REGULAR_{package.name}")
        if before.st_size != package.size:
            raise ValidationError(f"PACKAGE_OBJECT_SIZE_MISMATCH_{package.name}")
        if before.st_nlink != 1:
            raise ValidationError(f"PACKAGE_OBJECT_LINK_COUNT_INVALID_{package.name}")
        if before.st_uid not in {0, os.getuid()}:
            raise ValidationError(f"PACKAGE_OBJECT_OWNER_INVALID_{package.name}")
        if before.st_mode & 0o022:
            raise ValidationError(f"PACKAGE_OBJECT_PERMISSIONS_INVALID_{package.name}")
        with os.fdopen(os.dup(fd), "rb", closefd=True) as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != package.sha256:
            raise ValidationError(f"PACKAGE_OBJECT_SHA256_MISMATCH_{package.name}")
        control = inspect_deb(fd, package)
        after = os.fstat(fd)
        current = path.lstat()
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_uid, before.st_gid)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_uid, after.st_gid):
            raise ValidationError(f"PACKAGE_OBJECT_CHANGED_{package.name}")
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ValidationError(f"PACKAGE_OBJECT_REPLACED_{package.name}")
        return control
    finally:
        os.close(fd)


def prepare_repository(
    destination: pathlib.Path,
    packages: list[Package],
    controls: dict[str, str],
) -> tuple[str, int, str, int]:
    if not destination.is_absolute():
        raise ValidationError("OFFLINE_REPOSITORY_NOT_ABSOLUTE")
    if destination.exists() or destination.is_symlink():
        raise ValidationError("OFFLINE_REPOSITORY_DESTINATION_EXISTS")
    require_directory(destination.parent, "OFFLINE_REPOSITORY_PARENT")
    pool = destination / "pool"
    index_directory = destination / "dists/omega/main/binary-arm64"
    pool.mkdir(parents=True, mode=0o755)
    index_directory.mkdir(parents=True, mode=0o755)
    package_paragraphs: list[str] = []
    for package in packages:
        filename = f"pool/{package.sha256}.deb"
        package_paragraphs.append(
            controls[package.sha256].rstrip("\n")
            + f"\nFilename: {filename}\nSize: {package.size}\nSHA256: {package.sha256}\n"
        )
    packages_bytes = ("\n".join(package_paragraphs)).encode("utf-8")
    packages_path = index_directory / "Packages"
    packages_path.write_bytes(packages_bytes)
    os.chmod(packages_path, 0o644)
    digest = hashlib.sha256(packages_bytes).hexdigest()
    release = (
        "Origin: OMEGA\nLabel: OMEGA Offline\nSuite: omega\nCodename: omega\n"
        "Date: Thu, 27 Aug 2026 03:30:58 UTC\nArchitectures: arm64\nComponents: main\n"
        f"SHA256:\n {digest} {len(packages_bytes)} main/binary-arm64/Packages\n"
    )
    release_path = destination / "dists/omega/Release"
    release_path.write_text(release, encoding="ascii")
    os.chmod(release_path, 0o644)
    for directory in (
        destination,
        destination / "dists",
        destination / "dists/omega",
        destination / "dists/omega/main",
        index_directory,
        pool,
    ):
        os.chmod(directory, 0o755)
    release_bytes = release.encode("ascii")
    return digest, len(packages_bytes), hashlib.sha256(release_bytes).hexdigest(), len(release_bytes)


def copy_packages(root: pathlib.Path, destination: pathlib.Path, packages: list[Package]) -> None:
    for package in packages:
        source = root / "cache/objects/sha256" / package.sha256
        target = destination / "pool" / f"{package.sha256}.deb"
        with source.open("rb") as source_file, target.open("xb") as target_file:
            shutil.copyfileobj(source_file, target_file, length=1024 * 1024)
        os.chmod(target, 0o644)
        with target.open("rb") as copied:
            copied_digest = hashlib.file_digest(copied, "sha256").hexdigest()
        if copied_digest != package.sha256:
            raise ValidationError(f"OFFLINE_REPOSITORY_COPY_MISMATCH_{package.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-cache-root", required=True, type=pathlib.Path)
    parser.add_argument("--lock", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--prepare-repository", type=pathlib.Path)
    args = parser.parse_args()
    root = require_directory(args.input_cache_root, "INPUT_CACHE_ROOT")
    require_directory(root / "cache", "INPUT_CACHE_DIRECTORY")
    require_directory(root / "cache/objects", "INPUT_OBJECTS_DIRECTORY")
    require_directory(root / "cache/objects/sha256", "INPUT_SHA256_DIRECTORY")
    lock = read_lock(args.lock)
    packages = parse_manifest(args.manifest, lock["package_manifest_sha256"])
    controls: dict[str, str] = {}
    for package in packages:
        controls[package.sha256] = verify_object(root, package)
    if args.prepare_repository is not None:
        repository_identity = prepare_repository(args.prepare_repository, packages, controls)
        expected_identity = (
            lock["offline_packages_index_sha256"],
            int(lock["offline_packages_index_bytes"]),
            lock["offline_release_sha256"],
            int(lock["offline_release_bytes"]),
        )
        if repository_identity != expected_identity:
            raise ValidationError("OFFLINE_REPOSITORY_IDENTITY_MISMATCH")
        copy_packages(root, args.prepare_repository, packages)
        print(f"OFFLINE_APT_REPOSITORY={args.prepare_repository}")
    print(f"PACKAGE_OBJECTS_VERIFIED={len(packages)}")
    print("PACKAGE_CACHE=VERIFIED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
