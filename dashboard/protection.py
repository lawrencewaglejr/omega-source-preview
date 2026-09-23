"""Private setup preferences. Saving never activates filtering or message access."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import stat
import threading

from devices import _directory, _read


class ProtectionSetup:
    def __init__(self, path=None, demo=False):
        self.path = Path(path) if path else None
        self.demo = demo
        self.lock = threading.RLock()
        self.error = None
        self.state = {"version": 1, "adult_filter": False, "message_review": False, "updated": None}
        if not demo and self.path:
            try:
                self.state = self.validate(json.loads(_read(self.path, 4096, private=True)))
            except FileNotFoundError:
                pass
            except (OSError, ValueError, TypeError, RecursionError):
                self.error = "Saved setup is inaccessible or invalid. Repair it before saving new preferences."

    @staticmethod
    def validate(value):
        if not isinstance(value, dict) or set(value) != {"version", "adult_filter", "message_review", "updated"}:
            raise ValueError("Invalid setup preferences")
        if type(value["version"]) is not int or value["version"] != 1 or any(type(value[k]) is not bool for k in ("adult_filter", "message_review")):
            raise ValueError("Invalid setup preferences")
        if value["updated"] is not None:
            if not isinstance(value["updated"], str) or len(value["updated"]) > 64 or dt.datetime.fromisoformat(value["updated"]).tzinfo is None:
                raise ValueError("Invalid setup timestamp")
        return value

    def snapshot(self):
        with self.lock:
            return {"available": not self.error and bool(self.demo or self.path),
                    "preferences": copy.deepcopy(self.state), "demo": self.demo,
                    "filtering_active": False, "message_access_active": False,
                    "notice": self.error or ("Setup preferences only. Filtering and message access are not active." if self.demo or self.path else "Setup storage is not configured.")}

    def save(self, adult_filter, message_review):
        if type(adult_filter) is not bool or type(message_review) is not bool:
            raise ValueError("Choose valid setup options")
        with self.lock:
            if self.error or not (self.demo or self.path):
                raise OSError("Setup preferences are unavailable")
            value = {"version": 1, "adult_filter": adult_filter, "message_review": message_review,
                     "updated": dt.datetime.now(dt.timezone.utc).isoformat()}
            if not self.demo:
                directory = _directory(self.path.parent, private=True)
                name = ".protection-" + secrets.token_hex(12)
                try:
                    try:
                        existing = os.stat(self.path.name, dir_fd=directory, follow_symlinks=False)
                        if not stat.S_ISREG(existing.st_mode) or existing.st_uid != os.getuid() or existing.st_mode & 0o077 or existing.st_nlink != 1:
                            raise OSError("Unsafe setup file")
                    except FileNotFoundError:
                        pass
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    with os.fdopen(fd, "wb") as output:
                        output.write(json.dumps(value).encode())
                        output.flush()
                        os.fsync(output.fileno())
                    os.replace(name, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
                    os.fsync(directory)
                finally:
                    try:
                        os.unlink(name, dir_fd=directory)
                    except FileNotFoundError:
                        pass
                    os.close(directory)
            self.state = value
            return self.snapshot()
