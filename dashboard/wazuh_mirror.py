#!/usr/bin/python3
"""Device-owned, read-only Wazuh manager mirror; no SSH agent or remote setup."""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time

STATE = "/var/lib/omega-wazuh-mirror"
IMPORT = "/var/lib/omega-wazuh-import"
LOCK = "/run/omega-wazuh-mirror/connector.lock"
CACHE = "/var/cache/omega-wazuh-mirror"
ALIAS = "omega-wazuh-manager"
SOURCES = ("alerts", "archives")
TRANSFER_TIMEOUT = 45
RETRY_SECONDS = 15
MIN_FREE_BYTES = 2 * 1024 ** 3


class MirrorError(ValueError):
    pass


def require(value, message):
    if not value:
        raise MirrorError(message)


def public_key(value):
    """Accept one ordinary Ed25519 public key, never authorized_keys options."""
    require(isinstance(value, str) and len(value) <= 512 and "\n" not in value
            and "\r" not in value, "Supply one Ed25519 public key line.")
    parts = value.split()
    require(2 <= len(parts) <= 3 and parts[0] == "ssh-ed25519",
            "An ssh-ed25519 public key is required.")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise MirrorError("Invalid public key encoding.") from exc
    require(len(raw) == 51 and raw[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20",
            "Invalid Ed25519 key structure.")
    canonical = "ssh-ed25519 " + base64.b64encode(raw).decode("ascii")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return canonical, fingerprint


def validate_config(config):
    require(isinstance(config, dict) and set(config) == {"host", "user", "port", "host_key"},
            "Manager settings require exactly host, user, port, and host_key.")
    host = config["host"]
    require(isinstance(host, str) and 1 <= len(host) <= 253 and "%" not in host,
            "Supply a literal manager DNS name or IP address.")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        require(all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in host.split(".")), "Invalid manager hostname.")
        require(not re.fullmatch(r"[0-9.]+", host), "Invalid manager IP address.")
        host = host.lower()
    require(isinstance(config["user"], str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", config["user"])
            and config["user"] != "root", "Use a dedicated non-root manager reader account.")
    require(type(config["port"]) is int and 1 <= config["port"] <= 65535,
            "Manager port must be an integer from 1 to 65535.")
    key, _ = public_key(config["host_key"])
    return {"host": host, "user": config["user"], "port": config["port"], "host_key": key}


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON setting.")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MirrorError("Expected valid JSON settings.") from exc


def open_directory(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "Expected an absolute directory.")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_file(path, owner=None, mode=None):
    parent = open_directory(Path(path).parent)
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Expected a singly linked regular file.")
        if owner is not None:
            require(info.st_uid == owner, "Unexpected file owner.")
        if mode is not None:
            require(stat.S_IMODE(info.st_mode) == mode, "Unexpected file permissions.")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(path, limit=16384, owner=None, mode=None):
    fd = open_file(path, owner=owner, mode=mode)
    try:
        data = os.read(fd, limit + 1)
        require(len(data) <= limit, "File exceeds size limit.")
        return data
    finally:
        os.close(fd)


def atomic_write(path, data, mode, *, exclusive=False, owner=None, group=None):
    """Publish complete files; a failed transfer never exposes its partial bytes."""
    path = Path(path)
    parent = open_directory(path.parent)
    temporary = ".omega-" + os.urandom(16).hex()
    fd = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        os.fchmod(fd, mode)
        if owner is not None:
            os.fchown(fd, owner, group if group is not None else -1)
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(fd)
        if exclusive:
            os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(temporary, dir_fd=parent)
        else:
            os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def known_hosts(config):
    # HostKeyAlias is fixed. The port-qualified spelling also supports OpenSSH
    # versions that add the nondefault port while looking up the explicit alias.
    return f"{ALIAS},[{ALIAS}]:{config['port']} {config['host_key']}\n"


def ssh_command(config, state):
    options = {
        "HostName": config["host"], "HostKeyAlias": ALIAS,
        "UserKnownHostsFile": str(state / "known_hosts"), "GlobalKnownHostsFile": "/dev/null",
        "StrictHostKeyChecking": "yes", "UpdateHostKeys": "no", "VerifyHostKeyDNS": "no",
        "HostKeyAlgorithms": "ssh-ed25519", "IdentityAgent": "none", "IdentitiesOnly": "yes",
        "BatchMode": "yes", "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
        "PreferredAuthentications": "publickey", "ForwardAgent": "no", "ClearAllForwardings": "yes",
        "ProxyCommand": "none", "ProxyJump": "none", "ControlMaster": "no", "ControlPath": "none",
        "ConnectTimeout": "8", "ConnectionAttempts": "1", "ServerAliveInterval": "5",
        "ServerAliveCountMax": "2", "LogLevel": "ERROR",
    }
    command = ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-i", str(state / "id_ed25519"),
               "-l", config["user"], "-p", str(config["port"])]
    for name, value in options.items():
        command.extend(["-o", name + "=" + value])
    return command


def rsync_command(config, state, destination, source, *, basis=None):
    require(source in SOURCES, "Unsupported manager source.")
    # rrsync -ro /var/ossec/logs maps these fixed relative roots. Do not use
    # --protect-args: rrsync intentionally rejects it. No input controls paths.
    command = ["/usr/bin/rsync", "-rtp", "--no-links", "--no-devices", "--no-specials",
            "--chmod=D2750,F640", "--timeout=30", "--exclude=.*", "--include=*/",
            "--include=*.json", "--include=*.json.gz", "--exclude=*", "-e",
            shlex.join(ssh_command(config, state))]
    if basis is not None:
        command.append("--copy-dest=" + str(basis))
    return command + [ALIAS + ":" + source + "/", str(destination) + "/"]


def publish_file(staged, target, *, active=False):
    """Preserve active cursor inodes and keep every replaced generation."""
    staged, target = Path(staged), Path(target)
    new_fd = open_file(staged)
    parent = open_directory(target.parent)
    temporary = ".omega-" + os.urandom(16).hex()
    output = None
    try:
        new_info = os.fstat(new_fd)
        old_info, prefix = None, False
        try:
            old_fd = open_file(target)
        except FileNotFoundError:
            old_fd = None
        if old_fd is not None:
            try:
                old_info = os.fstat(old_fd)
                prefix = new_info.st_size >= old_info.st_size
                remaining = old_info.st_size
                while prefix and remaining:
                    chunk = os.read(old_fd, min(1024 * 1024, remaining))
                    prefix = bool(chunk) and chunk == os.read(new_fd, len(chunk))
                    remaining -= len(chunk)
            finally:
                os.close(old_fd)
        if old_info and prefix and new_info.st_size == old_info.st_size:
            return
        if active and old_info and prefix:
            output = os.open(target.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=parent)
            current = os.fstat(output)
            require((current.st_ino, current.st_dev, current.st_size) ==
                    (old_info.st_ino, old_info.st_dev, old_info.st_size), "Published source changed unexpectedly.")
            os.lseek(new_fd, old_info.st_size, os.SEEK_SET)
        else:
            os.lseek(new_fd, 0, os.SEEK_SET)
            output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o640, dir_fd=parent)
            os.fchmod(output, 0o640)
        while True:
            chunk = os.read(new_fd, 1024 * 1024)
            if not chunk:
                break
            while chunk:
                chunk = chunk[os.write(output, chunk):]
        os.fsync(output)
        if not (active and old_info and prefix):
            os.utime(output, ns=(new_info.st_atime_ns, new_info.st_mtime_ns))
            if old_info:
                suffix = ".json.gz" if target.name.endswith(".json.gz") else ".json"
                retained = target.name.removesuffix(suffix) + ".omega-" + os.urandom(16).hex() + suffix
                if active:
                    retained = target.name + ".omega-" + os.urandom(16).hex() + ".json"
                os.rename(target.name, retained, src_dir_fd=parent, dst_dir_fd=parent)
            os.replace(temporary, target.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(new_fd)
        if output is not None:
            os.close(output)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def publish_tree(staged, destination, source):
    active = staged / (source + ".json")
    descriptor = open_file(active)
    os.close(descriptor)
    # Complete rotations go first. The active file is appended/replaced last.
    for folder, directories, names in os.walk(staged, followlinks=False):
        require(all(not (Path(folder) / name).is_symlink() for name in directories),
                "Unexpected symlink in manager transfer.")
        relative = Path(folder).relative_to(staged)
        target_folder = destination / relative
        if not target_folder.exists():
            parent = open_directory(target_folder.parent)
            try:
                os.mkdir(target_folder.name, 0o2750, dir_fd=parent)
            finally:
                os.close(parent)
        for name in names:
            candidate = Path(folder) / name
            require(not candidate.is_symlink(), "Unexpected symlink in manager transfer.")
            if candidate != active and not name.startswith(".") and name.endswith((".json", ".json.gz")):
                publish_file(candidate, target_folder / name)
    publish_file(active, destination / active.name, active=True)


def bounded_run(command, *, timeout):
    """Kill the whole rsync/SSH process group on timeout; never capture log data."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
    try:
        return subprocess.CompletedProcess(command, process.wait(timeout=timeout))
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise


def sync_once(config, state=Path(STATE), destination=Path(IMPORT), *, cache=Path(CACHE), runner=bounded_run,
              clock=time.time, disk_usage=shutil.disk_usage):
    config = validate_config(config)
    outcomes = {name: {"ok": False, "error": "pending"} for name in SOURCES}

    def publish():
        value = {"checked_at": dt.datetime.fromtimestamp(clock(), dt.timezone.utc).isoformat(),
                 "sources": outcomes, "coverage": "Available manager files only; upstream-deleted history cannot be recovered."}
        atomic_write(destination / "sync-status.json", (json.dumps(value) + "\n").encode(), 0o640)
        return value

    publish()
    for source in SOURCES:
        try:
            require(disk_usage(destination).free >= MIN_FREE_BYTES, "low_space")
            with tempfile.TemporaryDirectory(prefix=source + "-", dir=cache) as temporary:
                staged = Path(temporary) / "transfer"
                staged.mkdir(mode=0o700)
                result = runner(rsync_command(config, state, staged, source, basis=destination / source),
                                timeout=TRANSFER_TIMEOUT)
                ok = result.returncode == 0
                outcomes[source] = {"ok": ok, "exit_code": result.returncode}
                if not ok:
                    outcomes[source]["error"] = "transfer_failed"
                else:
                    publish_tree(staged, destination / source, source)
        except subprocess.TimeoutExpired:
            outcomes[source] = {"ok": False, "error": "timeout"}
        except MirrorError as exc:
            outcomes[source] = {"ok": False, "error": "low_space" if str(exc) == "low_space" else "source_unreadable"}
        except (OSError, subprocess.SubprocessError):
            outcomes[source] = {"ok": False, "error": "source_unreadable"}
        publish()
    return publish()


def status(root=Path("/"), *, clock=time.time):
    root = Path(root)
    state, destination = root / STATE.lstrip("/"), root / IMPORT.lstrip("/")
    result = {"configured": (state / "config.json").is_file(),
              "identity_ready": (state / "id_ed25519.pub").is_file(), "ready": False,
              "sync": None, "message": "Manager connection is not configured."}
    if result["configured"]:
        result["message"] = "Waiting for successful manager transfers."
        try:
            value = parse_json(read_file(destination / "sync-status.json"))
            timestamp = dt.datetime.fromisoformat(value["checked_at"])
            require(timestamp.tzinfo is not None, "Heartbeat needs a timezone.")
            age = clock() - timestamp.timestamp()
            result["sync"] = value
            result["ready"] = -60 <= age <= 120 and all(value["sources"][name]["ok"] is True for name in SOURCES)
            result["message"] = ("Both manager logs were transferred successfully." if result["ready"]
                                 else "Manager transfers are pending, failing, or stale. Retained files remain available.")
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            pass
    return result


def acquire_lock(path):
    path = Path(path)
    parent = open_directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid(),
                "Unsafe mirror lock file.")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    require(os.geteuid() != 0, "The manager mirror must run as its non-root service account.")
    state, destination = Path(STATE), Path(IMPORT)
    directory = open_directory(state)
    try:
        info = os.fstat(directory)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "Manager settings directory must be private and owned by the mirror account.")
    finally:
        os.close(directory)
    config = validate_config(parse_json(read_file(state / "config.json", owner=os.geteuid(), mode=0o600)))
    require(read_file(state / "known_hosts", owner=os.geteuid(), mode=0o600).decode() == known_hosts(config),
            "Manager host binding differs from its verified settings.")
    read_file(state / "id_ed25519", owner=os.geteuid(), mode=0o600)
    lock = acquire_lock(LOCK)
    try:
        while True:
            sync_once(config, state, destination)
            if args.once:
                break
            time.sleep(RETRY_SECONDS)
    finally:
        os.close(lock)


if __name__ == "__main__":
    main()
