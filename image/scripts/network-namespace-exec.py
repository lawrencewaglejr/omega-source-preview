#!/usr/bin/python3
"""Verify an isolated network namespace, then optionally execute a command."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import stat
import sys


def fail(code: str) -> None:
    print(f"NETWORK_NAMESPACE_ERROR={code}", file=sys.stderr)
    raise SystemExit(1)


def validate_namespace(value: str, kind: str, code: str) -> None:
    if not re.fullmatch(rf"{kind}:\[[0-9]+\]", value):
        fail(code)


def verify_id_map(path: pathlib.Path, code: str) -> None:
    rows = []
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) != 3 or not all(field.isdecimal() for field in fields):
            fail(f"{code}_INVALID")
        rows.append(tuple(int(field) for field in fields))
    if (
        len(rows) < 2
        or rows[0][0] != 0
        or rows[0][2] != 1
        or rows[1][0] != 1
        or rows[1][2] < 65535
    ):
        fail(f"{code}_INSUFFICIENT")


def verify(
    host_namespace: str,
    host_mount_namespace: str | None,
    require_subordinate_mapping: bool,
) -> str:
    validate_namespace(host_namespace, "net", "HOST_NAMESPACE_INVALID")
    current = os.readlink("/proc/self/ns/net")
    if current == host_namespace:
        fail("NOT_ISOLATED")

    devices = pathlib.Path("/proc/net/dev").read_text(encoding="ascii").splitlines()[2:]
    interfaces = {line.split(":", 1)[0].strip() for line in devices if ":" in line}
    if interfaces != {"lo"}:
        fail("EXTERNAL_INTERFACE_PRESENT")
    routes = pathlib.Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    if any(line.strip() for line in routes):
        fail("IPV4_ROUTE_PRESENT")
    if host_mount_namespace is not None:
        validate_namespace(host_mount_namespace, "mnt", "HOST_MOUNT_NAMESPACE_INVALID")
        if os.readlink("/proc/self/ns/mnt") == host_mount_namespace:
            fail("MOUNT_NAMESPACE_NOT_ISOLATED")
        print("CONSTRUCTION_MOUNT_ISOLATION=VERIFIED", flush=True)
    if require_subordinate_mapping:
        verify_id_map(pathlib.Path("/proc/self/uid_map"), "UID_MAPPING")
        verify_id_map(pathlib.Path("/proc/self/gid_map"), "GID_MAPPING")
        print("CONSTRUCTION_ID_MAPPING=VERIFIED", flush=True)
    return current


def validate_command(command: list[str]) -> None:
    if not command:
        return
    executable = pathlib.Path(command[0])
    if not executable.is_absolute():
        fail("COMMAND_NOT_ABSOLUTE")
    try:
        metadata = executable.lstat()
    except FileNotFoundError:
        fail("COMMAND_MISSING")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("COMMAND_INVALID")
    if not os.access(executable, os.X_OK):
        fail("COMMAND_NOT_EXECUTABLE")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-network-namespace", required=True)
    parser.add_argument("--host-mount-namespace")
    parser.add_argument("--require-subordinate-mapping", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    current = verify(
        args.host_network_namespace,
        args.host_mount_namespace,
        args.require_subordinate_mapping,
    )
    validate_command(command)
    print(f"CONSTRUCTION_NETWORK_NAMESPACE={current}", flush=True)
    print("CONSTRUCTION_NETWORK_ISOLATION=VERIFIED", flush=True)
    if not command:
        return 0
    os.execvpe(command[0], command, os.environ.copy())
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError) as error:
        fail(str(error))
