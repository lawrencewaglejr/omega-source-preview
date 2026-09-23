#!/usr/bin/python3
"""Verify the exact onboarding source payload and stage a clean application tree."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

FILES = frozenset({
    "appliance.py", "server.py", "wazuh_mirror.py", "wazuh-manager-setup.md",
    "static/app.js", "static/index.html", "static/style.css",
})


class PayloadError(Exception):
    pass


def directory(path: Path) -> Path:
    if not path.is_absolute() or path.resolve() != path or not path.is_dir():
        raise PayloadError("ONBOARDING_DIRECTORY_INVALID")
    return path


def read_file(root: Path, relative: str, limit: int = 2 * 1024 * 1024) -> bytes:
    directory(root)
    path = root
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(part in {".", ".."} for part in parts):
        raise PayloadError("ONBOARDING_PATH_INVALID")
    for part in parts[:-1]:
        path = path / part
        if path.is_symlink() or not path.is_dir():
            raise PayloadError("ONBOARDING_PARENT_INVALID")
    path = path / parts[-1]
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_size > limit
                or before.st_uid not in {0, os.getuid()} or before.st_mode & 0o022
                or before.st_nlink != 1):
            raise PayloadError("ONBOARDING_FILE_METADATA_INVALID")
        with os.fdopen(os.dup(fd), "rb") as source:
            raw = source.read(limit + 1)
        after = os.fstat(fd)
        current = path.lstat()
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mode,
                                 info.st_uid, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
        if len(raw) != before.st_size or identity(before) != identity(after) or identity(before) != identity(current):
            raise PayloadError("ONBOARDING_FILE_CHANGED")
        return raw
    finally:
        os.close(fd)


def verified_files(source_root: Path, manifest: Path) -> dict[str, bytes]:
    directory(source_root)
    directory(manifest.parent)
    raw = read_file(manifest.parent, manifest.name)
    if not raw.endswith(b"\n") or any(byte not in (9, 10) and not 32 <= byte <= 126 for byte in raw):
        raise PayloadError("ONBOARDING_MANIFEST_BYTES_INVALID")
    rows = raw.decode("ascii").splitlines()
    if rows[:3] != ["omega-onboarding-manifest-v1", f"file_count\t{len(FILES)}", "columns\tsize\tsha256\tpath"]:
        raise PayloadError("ONBOARDING_MANIFEST_HEADER_INVALID")
    result = {}
    for row in rows[3:]:
        fields = row.split("\t")
        if len(fields) != 3:
            raise PayloadError("ONBOARDING_MANIFEST_ROW_INVALID")
        size, digest, relative = fields
        if not re.fullmatch(r"[1-9][0-9]*", size) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PayloadError("ONBOARDING_MANIFEST_ROW_INVALID")
        if relative not in FILES or relative in result:
            raise PayloadError("ONBOARDING_MANIFEST_PATH_INVALID")
        # Manifest paths describe the installed tree. External source assets
        # have fixed mappings; manifest text cannot select arbitrary directories.
        source_directory = {
            "wazuh_mirror.py": "dashboard",
            "wazuh-manager-setup.md": "docs",
        }.get(relative, "onboarding")
        content = read_file(source_root / source_directory, relative)
        if len(content) != int(size) or hashlib.sha256(content).hexdigest() != digest:
            raise PayloadError("ONBOARDING_CONTENT_MISMATCH_" + relative)
        result[relative] = content
    if set(result) != FILES or list(result) != sorted(result):
        raise PayloadError("ONBOARDING_MANIFEST_MEMBERSHIP_INVALID")
    return result


def stage(files: dict[str, bytes], destination: Path) -> None:
    directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise PayloadError("ONBOARDING_DESTINATION_EXISTS")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1787801458"))
    with tempfile.TemporaryDirectory(prefix=".omega-onboarding-", dir=destination.parent) as temp:
        root = Path(temp)
        for relative, content in sorted(files.items()):
            target = root / relative
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(content)
            target.chmod(0o644)
            os.utime(target, (epoch, epoch))
        for path in [*root.rglob("*"), root]:
            if path.is_dir():
                path.chmod(0o755)
                os.utime(path, (epoch, epoch))
        # The build operates inside a private directory and refuses collisions.
        if destination.exists() or destination.is_symlink():
            raise PayloadError("ONBOARDING_DESTINATION_EXISTS")
        root.rename(destination)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    files = verified_files(args.source_root, args.manifest)
    if args.destination is not None:
        stage(files, args.destination)
        print(f"ONBOARDING_FILES_STAGED={len(files)}")
    print("ONBOARDING_PAYLOAD_VALID=YES")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PayloadError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
