#!/usr/bin/python3
"""Normalize timestamps of named ext4 inodes before genimage packages it."""

from __future__ import annotations

import pathlib
import re
import stat
import subprocess
import sys
import tempfile

EPOCH = 1787801458


def debugfs(image: pathlib.Path, commands: list[str], write: bool = False) -> str:
    with tempfile.NamedTemporaryFile(mode="w", encoding="ascii") as batch:
        batch.write("\n".join(commands) + "\n")
        batch.flush()
        result = subprocess.run(
            ["/usr/sbin/debugfs", *(["-w"] if write else []), "-f", batch.name, str(image)],
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "E2FSPROGS_FAKE_TIME": str(EPOCH)},
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True,
        )
    errors = [line for line in result.stderr.splitlines() if not line.startswith("debugfs ")]
    if errors:
        raise RuntimeError("debugfs failed: " + "; ".join(errors))
    return result.stdout


def normalize(image: pathlib.Path) -> None:
    metadata = image.lstat()
    if not image.is_absolute() or image.resolve() != image or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("ext4 image must be a canonical regular file")
    inodes = {2}
    visited: set[int] = set()
    pending = {2}
    while pending:
        current = sorted(pending - visited)
        if not current:
            break
        visited.update(current)
        output = debugfs(image, [f"ls -p <{inode}>" for inode in current])
        pending = set()
        rows = 0
        for line in output.splitlines():
            match = re.match(r"^/([0-9]+)/([0-7]{6})/[0-9]+/[0-9]+/", line)
            if match is None:
                continue
            inode, mode = int(match[1]), int(match[2], 8)
            if inode == 0:
                continue
            rows += 1
            inodes.add(inode)
            if stat.S_ISDIR(mode) and inode not in visited:
                pending.add(inode)
        if rows < 2 * len(current):
            raise RuntimeError("incomplete ext4 directory enumeration")
    commands = []
    for inode in sorted(inodes):
        for field in ("atime", "mtime", "ctime", "crtime"):
            commands.append(f"set_inode_field <{inode}> {field} @{EPOCH}")
            commands.append(f"set_inode_field <{inode}> {field}_extra 0")
    for field in ("mtime", "wtime", "lastcheck", "mkfs_time"):
        commands.append(f"set_super_value {field} @{EPOCH}")
    debugfs(image, commands, write=True)
    print(f"EXT4_TIMESTAMPS_NORMALIZED={len(inodes)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: normalize-ext4.py /absolute/root.ext4")
    normalize(pathlib.Path(sys.argv[1]))
