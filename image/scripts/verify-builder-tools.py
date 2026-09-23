#!/usr/bin/python3
"""Verify and stage rpi-image-gen's exact offline host-tool sources."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import shutil
import stat
import sys
from dataclasses import dataclass


class ValidationError(Exception):
    pass


@dataclass(frozen=True)
class ToolSource:
    name: str
    filename: str
    size: int
    sha256: str


EXPECTED = (
    ToolSource("bdebstrap", "bdebstrap-0.7.0.tar.gz", 33465, "c8675f637af16a4471c8f61627895d21e56ef5d4bd13fa2a18cd01513395a009"),
    ToolSource("genimage", "genimage-20.tar.gz", 116964, "4cadce884f920a4663c59652f1b87787772628ee4e2867a48e94c69f122fae57"),
    ToolSource("libconfuse", "libconfuse-3.3.tar.gz", 123482, "cb90c06f2dbec971792af576d5b9a382fb3c4ca2b1deea55ea262b403f4e641e"),
)


def require_directory(path: pathlib.Path, code: str) -> pathlib.Path:
    if not path.is_absolute():
        raise ValidationError(f"{code}_NOT_ABSOLUTE")
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ValidationError(f"{code}_MISSING") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or path.resolve() != path:
        raise ValidationError(f"{code}_INVALID")
    return path


def parse_manifest(path: pathlib.Path) -> tuple[ToolSource, ...]:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as exc:
        raise ValidationError("BUILDER_TOOLS_MANIFEST_UNREADABLE") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError("BUILDER_TOOLS_MANIFEST_INVALID")
    if not raw.endswith(b"\n") or any(byte not in (9, 10) and not 0x20 <= byte <= 0x7E for byte in raw):
        raise ValidationError("BUILDER_TOOLS_MANIFEST_BYTES_INVALID")
    lines = raw.decode("ascii").splitlines()
    if lines[:3] != [
        "omega-builder-tools-manifest-v1",
        "object_count\t3",
        "columns\tname\tfilename\tsize\tsha256",
    ]:
        raise ValidationError("BUILDER_TOOLS_MANIFEST_HEADER_INVALID")
    sources: list[ToolSource] = []
    for number, line in enumerate(lines[3:], 4):
        fields = line.split("\t")
        if len(fields) != 4 or not re.fullmatch(r"[a-z0-9-]+", fields[0]) or not re.fullmatch(r"[A-Za-z0-9.+-]+", fields[1]):
            raise ValidationError(f"BUILDER_TOOLS_MANIFEST_LINE_INVALID_{number}")
        if not re.fullmatch(r"[1-9][0-9]*", fields[2]) or not re.fullmatch(r"[0-9a-f]{64}", fields[3]):
            raise ValidationError(f"BUILDER_TOOLS_MANIFEST_LINE_INVALID_{number}")
        sources.append(ToolSource(fields[0], fields[1], int(fields[2]), fields[3]))
    if tuple(sources) != EXPECTED:
        raise ValidationError("BUILDER_TOOLS_MANIFEST_CONTENT_INVALID")
    return tuple(sources)


def verify_object(root: pathlib.Path, source: ToolSource) -> pathlib.Path:
    path = root / "cache/objects/sha256" / source.sha256
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValidationError(f"BUILDER_TOOL_OBJECT_OPEN_FAILED_{source.name}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != source.size:
            raise ValidationError(f"BUILDER_TOOL_OBJECT_SIZE_INVALID_{source.name}")
        if before.st_uid not in {0, os.getuid()} or before.st_mode & 0o022 or before.st_nlink != 1:
            raise ValidationError(f"BUILDER_TOOL_OBJECT_METADATA_INVALID_{source.name}")
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as content:
            digest = hashlib.file_digest(content, "sha256").hexdigest()
        if digest != source.sha256:
            raise ValidationError(f"BUILDER_TOOL_OBJECT_SHA256_MISMATCH_{source.name}")
        after = os.fstat(descriptor)
        current = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mode) != (after.st_dev, after.st_ino, after.st_size, after.st_mode):
            raise ValidationError(f"BUILDER_TOOL_OBJECT_CHANGED_{source.name}")
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ValidationError(f"BUILDER_TOOL_OBJECT_REPLACED_{source.name}")
    finally:
        os.close(descriptor)
    return path


def stage(destination: pathlib.Path, verified: list[tuple[ToolSource, pathlib.Path]]) -> None:
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise ValidationError("BUILDER_TOOL_CACHE_DESTINATION_INVALID")
    require_directory(destination.parent, "BUILDER_TOOL_CACHE_PARENT")
    destination.mkdir(mode=0o700)
    for source, path in verified:
        target = destination / source.filename
        with path.open("rb") as input_file, target.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
        os.chmod(target, 0o600)
        with target.open("rb") as completed:
            if hashlib.file_digest(completed, "sha256").hexdigest() != source.sha256:
                raise ValidationError(f"BUILDER_TOOL_STAGE_MISMATCH_{source.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-cache-root", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--stage-directory", type=pathlib.Path)
    args = parser.parse_args()
    root = require_directory(args.input_cache_root, "INPUT_CACHE_ROOT")
    require_directory(root / "cache/objects/sha256", "INPUT_SHA256_DIRECTORY")
    sources = parse_manifest(args.manifest)
    verified = [(source, verify_object(root, source)) for source in sources]
    if args.stage_directory is not None:
        stage(args.stage_directory, verified)
        print(f"BUILDER_TOOL_CACHE={args.stage_directory}")
    print("BUILDER_TOOL_OBJECTS_VERIFIED=3")
    print("BUILDER_TOOL_SOURCES=VERIFIED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
