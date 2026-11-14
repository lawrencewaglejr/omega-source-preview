"""Bounded, local network inventory and durable new-device notifications.

This observes a configured dnsmasq/Pi-hole IPv4 lease file; it does not scan,
block, or prove a device is currently online. A hostname is reported by DHCP.
An optional Pi-hole network database supplies DNS/neighbor observations when
another router provides DHCP. Neither source reports every Wi-Fi association.
Device roles and friendly names come from explicit local labels or CSV, never
from guessed fingerprints. A changed/randomized MAC is a different identity.
"""
from __future__ import annotations

import copy
import csv
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time

MAX_DEVICES = 1024
MAX_EVENTS = 200
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_MAPPING_BYTES = 512 * 1024
MAX_DATABASE_ROWS = 8192
RECENT_OBSERVATION_SECONDS = 300
DATABASE_TIMEOUT_SECONDS = 0.5
DEVICE_TYPES = {"Unknown", "Laptop", "Tablet", "Phone", "Desktop", "TV", "Console", "Router", "Appliance", "Other"}
MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")
LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
DEVICE_KEYS = {"id", "mac", "ip", "hostname", "display_name", "vendor", "owner", "role", "device_type", "trust_level", "notes", "first_seen", "last_seen", "lease_expires", "observed_in_latest_lease", "observation_source", "in_current_source"}
EVENT_KEYS = {"id", "type", "device_id", "display_name", "hostname", "ip", "created_at", "read"}
SOURCES = {"dhcp_leases": "DHCP lease observations", "pihole_network": "Pi-hole network observations", "network_scan": "Authorized network scan", "sample_data": "Sample devices"}


def _mac(value):
    value = value.lower()
    if not MAC.fullmatch(value) or value == "00:00:00:00:00:00" or int(value[:2], 16) & 1:
        raise ValueError("Invalid device MAC")
    return value


def _hostname(value):
    value = value.rstrip(".")
    return value if len(value) <= 253 and all(LABEL.fullmatch(label) for label in value.split(".")) else ""


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Invalid timestamp")
    if dt.datetime.fromisoformat(value).tzinfo is None:
        raise ValueError("Timestamp needs timezone")
    return value


def _directory(path, private=False):
    """Open every path component without following symlinks, avoiding FIFO hangs."""
    path = Path(os.path.abspath(path))
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("State directory must be owned by the dashboard user with mode 0700")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read(path, limit, private=False):
    path = Path(path)
    directory = _directory(path.parent, private)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ValueError("Expected a bounded regular file")
            if private and (info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1):
                raise ValueError("State file must be private and owned by the dashboard user")
            data = source.read(limit + 1)
            if len(data) > limit:
                raise ValueError("File exceeds limit")
            return data.decode("utf-8")
    finally:
        os.close(directory)


def _leases(path):
    leases = {}
    invalid = 0
    for line in _read(path, MAX_SOURCE_BYTES).splitlines():
        if not line.strip():
            continue
        fields = line.split()
        try:
            if len(fields) != 5:
                raise ValueError("Expected dnsmasq IPv4 lease")
            expires, mac, address, hostname, _client_id = fields
            expires = int(expires)
            if expires < 0 or expires > 253402300799:
                raise ValueError("Invalid expiry")
            mac = _mac(mac)
            address = ipaddress.IPv4Address(address)
            if address.is_unspecified or address.is_multicast or address.is_loopback:
                raise ValueError("Invalid client address")
            entry = {"mac": mac, "ip": str(address), "hostname": _hostname(hostname), "lease_expires": expires}
            current_expiry = leases.get(mac, {}).get("lease_expires")
            if current_expiry is None or expires == 0 or (current_expiry != 0 and expires >= current_expiry):
                leases[mac] = entry
        except ValueError:
            invalid += 1
    if len(leases) > MAX_DEVICES:
        raise ValueError("Lease inventory exceeds device capacity")
    return leases, invalid


def _pihole_network(path, now):
    """Read current Pi-hole network tables, never query history or change FTL.

    Schema: https://github.com/pi-hole/FTL/blob/master/src/database/network-table.c
    Coverage: https://docs.pi-hole.net/ftldns/configfile/#database-network
    Use normal read-only SQLite locking, not immutable=1 (FTL may use WAL).
    """
    path = Path(os.path.abspath(path))
    directory = _directory(path.parent)
    descriptor = None
    connection = None
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Pi-hole database must be a regular file")
        # SQLite opens its own descriptor and may use existing journal/WAL
        # companions. Reject links and non-regular companions before opening.
        companions = set()
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                companion = os.stat(path.name + suffix, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISREG(companion.st_mode):
                    raise ValueError("Unsafe database companion")
                companions.add(suffix)
            except FileNotFoundError:
                pass
        # mode=ro alone can still create missing WAL/SHM files in a writable
        # directory. Require FTL's existing companions so this reader never
        # creates them; do not use immutable=1 on a live changing database.
        if os.pread(descriptor, 2, 18) == b"\x02\x02" and not {"-wal", "-shm"}.issubset(companions):
            raise ValueError("WAL database requires existing FTL WAL and SHM files")
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=DATABASE_TIMEOUT_SECONDS)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        deadline = time.monotonic() + DATABASE_TIMEOUT_SECONDS
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        if hasattr(connection, "setlimit"):
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
            connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384)
            connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        schema = connection.execute("SELECT name, type, sql FROM sqlite_master WHERE name IN ('network', 'network_addresses')").fetchall()
        if len(schema) != 2 or any(kind != "table" or not definition or not definition.lstrip().upper().startswith("CREATE TABLE") for _name, kind, definition in schema):
            raise ValueError("Unsupported Pi-hole network schema")
        # Explicit bounded columns prevent oversized source strings from
        # multiplying into a large in-memory result set.
        rows = connection.execute("SELECT substr(n.hwaddr,1,80), substr(a.ip,1,80), substr(a.name,1,254), n.firstSeen, a.lastSeen, n.lastQuery, substr(n.macVendor,1,101) FROM network_addresses AS a JOIN network AS n ON n.id=a.network_id LIMIT ?", (MAX_DATABASE_ROWS + 1,)).fetchall()
        after = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(after.st_mode) or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("Pi-hole database changed identity while reading")
        if len(rows) > MAX_DATABASE_ROWS:
            raise ValueError("Pi-hole network addresses exceed capacity")
    finally:
        if connection is not None:
            connection.close()
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)
    records = {}
    skipped = 0
    for mac, address, hostname, first_seen, last_seen, last_query, vendor in rows:
        try:
            # Pi-hole legitimately has ip-* placeholder identities. They cannot
            # be tracked as a MAC, so do not pretend they are separate devices.
            if not isinstance(mac, str) or not isinstance(address, str):
                raise ValueError("Missing identity")
            mac = _mac(mac)
            address = ipaddress.ip_address(address)
            if address.is_unspecified or address.is_multicast or address.is_loopback or "%" in str(address):
                raise ValueError("Unsupported network address")
            if any(type(value) is not int or value < 0 or value > now + 60 for value in (first_seen, last_seen, last_query)):
                raise ValueError("Invalid observation timestamp")
            observed = max(last_seen, last_query)
            if first_seen <= 0 or observed <= 0 or first_seen > observed:
                raise ValueError("Missing observation timestamp")
            entry = {"mac": mac, "ip": str(address), "hostname": _hostname(hostname) if isinstance(hostname, str) else "", "vendor": " ".join(vendor.split())[:100] if isinstance(vendor, str) else "", "lease_expires": 0, "first_seen": dt.datetime.fromtimestamp(min(first_seen, now), dt.timezone.utc).isoformat(), "last_seen": dt.datetime.fromtimestamp(min(observed, now), dt.timezone.utc).isoformat(), "address_observed": last_seen}
            # A MAC may have several IPv4/IPv6 addresses. Show the address with
            # the latest source observation, with a stable tie-breaker.
            previous = records.get(mac)
            if previous is None or (last_seen, address.version == 4, str(address)) > (previous["address_observed"], ipaddress.ip_address(previous["ip"]).version == 4, previous["ip"]):
                records[mac] = entry
        except (ValueError, OverflowError, OSError):
            skipped += 1
    if len(records) > MAX_DEVICES:
        raise ValueError("Pi-hole devices exceed capacity")
    if rows and not records:
        raise ValueError("No usable MAC observations in Pi-hole network tables")
    for record in records.values():
        record.pop("address_observed")
    return records, skipped


def _mapping(path):
    if path is None:
        return {}, ""
    try:
        reader = csv.DictReader(io.StringIO(_read(path, MAX_MAPPING_BYTES)))
        if not reader.fieldnames or not {"mac", "hostname", "role"}.issubset(reader.fieldnames):
            raise ValueError("Inventory columns missing")
        entries = {}
        for row in reader:
            try:
                mac = _mac(row.get("mac", ""))
            except (ValueError, AttributeError):
                continue
            entries[mac] = {key: " ".join((row.get(key) or "").split())[:limit] for key, limit in (("hostname", 253), ("vendor", 100), ("owner", 100), ("role", 80), ("trust_level", 32), ("notes", 300))}
        return entries, ""
    except (OSError, ValueError, UnicodeError, csv.Error):
        return {}, "Device labels are unavailable; showing source evidence only."


def _scan_observations(path, now):
    if not path:
        return {}, ""
    try:
        data = json.loads(_read(Path(path), MAX_MAPPING_BYTES))
        when = data["collected_at"]
        _timestamp(when)
        if dt.datetime.fromisoformat(when).timestamp() > now + 60 or len(data["devices"]) > MAX_DEVICES:
            raise ValueError("Invalid scan")
        records = {}
        for row in data["devices"]:
            mac = _mac(row["mac"])
            address = ipaddress.ip_address(row["ip"])
            if not address.is_private or address.is_loopback or address.is_multicast or address.is_unspecified:
                raise ValueError("Unsupported scan address")
            hostname = _hostname(row.get("hostname", ""))
            kind = row.get("device_type", "Unknown")
            if kind not in DEVICE_TYPES:
                raise ValueError("Unsupported device type")
            services = row.get("services", [])
            if not isinstance(services, list) or len(services) > 100:
                raise ValueError("Too many scan services")
            for service in services:
                if type(service.get("port")) is not int or not 1 <= service["port"] <= 65535 or service.get("state") not in {"open", "closed", "filtered"} or service.get("protocol") not in {"tcp", "udp"}:
                    raise ValueError("Invalid scanned service")
            records[mac] = {"mac":mac,"ip":str(address),"hostname":hostname,"vendor":str(row.get("vendor", ""))[:100],"device_type":kind,"hostname_source":str(row.get("hostname_source", ""))[:100],"services":services,"observed_at":when,"notice":str(row.get("notice", ""))[:300]}
        return records, ""
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return {}, "Saved network scan is unavailable or invalid."


def _validate_state(state):
    if not isinstance(state, dict) or set(state) != {"version", "baseline_established", "devices", "events", "updated", "custom_labels", "source", "baseline_at"} or type(state["version"]) is not int or state["version"] != 2:
        raise ValueError("Unsupported device state")
    if not isinstance(state["source"], str) or state["source"] not in SOURCES:
        raise ValueError("Unsupported observation source")
    if type(state["baseline_established"]) is not bool or not isinstance(state["devices"], dict) or not isinstance(state["events"], list):
        raise ValueError("Invalid device state")
    if len(state["devices"]) > MAX_DEVICES or len(state["events"]) > MAX_EVENTS:
        raise ValueError("Device state exceeds capacity")
    if state["updated"] is not None:
        _timestamp(state["updated"])
    if not state["baseline_established"] and (state["devices"] or state["events"] or state["updated"]):
        raise ValueError("Invalid baseline")
    if state["baseline_established"] and state["updated"] is None:
        raise ValueError("Established baseline needs observation time")
    if state["baseline_established"]:
        _timestamp(state["baseline_at"])
    elif state["baseline_at"] is not None:
        raise ValueError("Unexpected baseline time")
    if not isinstance(state["custom_labels"], dict) or len(state["custom_labels"]) > MAX_DEVICES:
        raise ValueError("Invalid device labels")
    for key, label in state["custom_labels"].items():
        if key not in state["devices"] or not isinstance(label, dict) or set(label) != {"display_name", "device_type"}:
            raise ValueError("Invalid device label")
        _validate_label(label["display_name"], label["device_type"])
    for key, device in state["devices"].items():
        if not isinstance(device, dict) or set(device) != DEVICE_KEYS or _mac(key) != key or device["id"] != key or device["mac"] != key:
            raise ValueError("Invalid device identity")
        for field in DEVICE_KEYS - {"lease_expires", "observed_in_latest_lease", "in_current_source"}:
            if not isinstance(device[field], str) or len(device[field]) > 300:
                raise ValueError("Invalid device field")
        if str(ipaddress.ip_address(device["ip"])) != device["ip"] or _hostname(device["hostname"]) != device["hostname"]:
            raise ValueError("Invalid device address")
        _timestamp(device["first_seen"])
        _timestamp(device["last_seen"])
        if type(device["lease_expires"]) is not int or not 0 <= device["lease_expires"] <= 253402300799 or type(device["observed_in_latest_lease"]) is not bool:
            raise ValueError("Invalid lease evidence")
        if device["observation_source"] not in SOURCES or type(device["in_current_source"]) is not bool:
            raise ValueError("Invalid observation source")
    ids = set()
    for event in state["events"]:
        if not isinstance(event, dict) or set(event) != EVENT_KEYS or event["type"] != "new_device" or type(event["read"]) is not bool:
            raise ValueError("Invalid device event")
        for field in EVENT_KEYS - {"read"}:
            if not isinstance(event[field], str) or len(event[field]) > 300:
                raise ValueError("Invalid event field")
        if not re.fullmatch(r"[0-9a-f]{24}", event["id"]) or event["id"] in ids or event["device_id"] not in state["devices"]:
            raise ValueError("Invalid event identity")
        ids.add(event["id"])
        _timestamp(event["created_at"])
        if _hostname(event["hostname"]) != event["hostname"]:
            raise ValueError("Invalid event hostname")
        ipaddress.ip_address(event["ip"])
    return state


def _load_state(state):
    # Validate a narrowly defined migration, preserving all identities, labels,
    # and read markers. Unrecognized/corrupt state never becomes a new baseline.
    legacy_keys = {"version", "baseline_established", "devices", "events", "updated", "custom_labels"}
    if isinstance(state, dict) and type(state.get("version")) is int and state["version"] == 1 and set(state) == legacy_keys:
        state = copy.deepcopy(state)
        state.update({"version": 2, "source": "dhcp_leases", "baseline_at": state["updated"]})
        if not isinstance(state["devices"], dict):
            raise ValueError("Invalid legacy device state")
        for device in state["devices"].values():
            if not isinstance(device, dict) or set(device) != DEVICE_KEYS - {"observation_source", "in_current_source"}:
                raise ValueError("Invalid legacy device record")
            device.update({"observation_source": "dhcp_leases", "in_current_source": device["observed_in_latest_lease"]})
    return _validate_state(state)


def _validate_label(display_name, device_type):
    if not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 80 or any(not char.isprintable() for char in display_name):
        raise ValueError("Device name must contain 1–80 printable characters")
    if not isinstance(device_type, str) or device_type not in DEVICE_TYPES:
        raise ValueError("Choose a supported device type")


class DeviceDiscovery:
    """Call poll() in a background worker, and snapshot() in request handlers.

    Live mode requires an existing private (0700) directory for state_file.
    Invalid/unwritable state fails closed; existing state is never reset. The
    first successful poll establishes a silent baseline before alerts begin.
    The registry retains identities up to MAX_DEVICES rather than forgetting
    devices and falsely rediscovering them. Events retain the newest MAX_EVENTS.
    """

    def __init__(self, lease_file=None, state_file=None, mapping_file=None, demo=False, pihole_database=None, scan_file=None):
        self.lease_file = Path(lease_file) if lease_file else None
        self.pihole_database = Path(pihole_database) if pihole_database else None
        if self.lease_file and self.pihole_database:
            raise ValueError("Select one device source: DHCP leases or Pi-hole network database")
        self.state_file = Path(state_file) if state_file else None
        self.mapping_file = Path(mapping_file) if mapping_file else None
        self.scan_file = scan_file
        self.scan_records = {}
        self.demo = bool(demo)
        self.source = "sample_data" if self.demo else "pihole_network" if self.pihole_database else "dhcp_leases"
        self._lock = threading.RLock()
        self._state = {"version": 2, "baseline_established": False, "devices": {}, "events": [], "updated": None, "custom_labels": {}, "source": self.source, "baseline_at": None}
        self._available = False
        self._invalid = 0
        self._skipped = 0
        self._fatal = ""
        self._notice = "Device discovery is not configured. Select a DHCP lease file or Pi-hole network database and private state file."
        if self.demo:
            self._state = demo_state()
            self._available = True
            self._notice = "Sample devices and notifications. This preview is not monitoring your network."
        elif (self.lease_file or self.pihole_database) and self.state_file:
            try:
                self._state = _load_state(json.loads(_read(self.state_file, MAX_STATE_BYTES, private=True)))
                self._notice = "Waiting for the next network observation."
            except FileNotFoundError:
                self._notice = "Waiting for the first successful network observation."
            except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                self._fatal = "Device state is invalid or inaccessible. Discovery is stopped to avoid false notifications; repair the state file before restarting."
                self._notice = self._fatal
        self.snapshot()  # Publish an initial view before background polling starts.

    def _save(self, state):
        _validate_state(state)
        raw = json.dumps(state, ensure_ascii=True, separators=(",", ":")).encode()
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError("Device state exceeds byte capacity")
        directory = _directory(self.state_file.parent, private=True)
        temp_name = ".omega-devices-" + secrets.token_hex(12)
        created = False
        try:
            try:
                info = os.stat(self.state_file.name, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                    raise ValueError("Unsafe device state target")
            except FileNotFoundError:
                pass
            descriptor = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            created = True
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_name, self.state_file.name, src_dir_fd=directory, dst_dir_fd=directory)
            created = False
            os.fsync(directory)
        finally:
            if created:
                os.unlink(temp_name, dir_fd=directory)
            os.close(directory)

    def poll(self):
        with self._lock:
            if self.demo or self._fatal or not (self.lease_file or self.pihole_database) or not self.state_file:
                return self.snapshot()
            observed_at = dt.datetime.now(dt.timezone.utc)
            now = observed_at.isoformat()
            try:
                if self.pihole_database:
                    leases, self._skipped = _pihole_network(self.pihole_database, observed_at.timestamp())
                    self._invalid = 0
                else:
                    leases, self._invalid = _leases(self.lease_file)
                    if self._invalid:
                        raise ValueError("Incomplete lease evidence")
            except (OSError, ValueError, UnicodeError, sqlite3.Error):
                self._available = False
                source_name = "Pi-hole network observations" if self.pihole_database else "DHCP leases"
                self._notice = f"{source_name} are unavailable, malformed, or exceed capacity. No new-device events were created; saved devices may be stale."
                return self.snapshot()
            labels, label_notice = _mapping(self.mapping_file)
            self.scan_records, scan_notice = _scan_observations(self.scan_file, observed_at.timestamp())
            scan_only = set()
            if self.pihole_database:
                for mac, scan in self.scan_records.items():
                    if mac not in leases:
                        scan_only.add(mac)
                        leases[mac] = {key:scan[key] for key in ("mac", "ip", "hostname", "vendor")}
                        leases[mac].update(lease_expires=0, first_seen=scan["observed_at"], last_seen=scan["observed_at"])
                    elif not leases[mac]["hostname"]:
                        leases[mac]["hostname"] = scan["hostname"]
            next_state = copy.deepcopy(self._state)
            source_baseline = next_state["baseline_established"] and next_state["source"] == self.source
            baseline_epoch = dt.datetime.fromisoformat(next_state["baseline_at"]).timestamp() if source_baseline else observed_at.timestamp()
            for device in next_state["devices"].values():
                device["observed_in_latest_lease"] = False
                device["in_current_source"] = False
            capacity_reached = False
            for mac, lease in leases.items():
                previous = next_state["devices"].get(mac)
                # An old lease is historical evidence, not a new arrival. Keep
                # known identities, but only discover an unknown active lease.
                if not self.pihole_database and previous is None and lease["lease_expires"] != 0 and lease["lease_expires"] <= observed_at.timestamp():
                    continue
                if previous is None and len(next_state["devices"]) >= MAX_DEVICES:
                    capacity_reached = True
                    continue
                label = labels.get(mac, {})
                # Placeholder inventory names must not hide a reported hostname.
                friendly = label.get("hostname", "")
                if friendly.lower() in {"unknown", "*", "none", "n/a"}:
                    friendly = ""
                first_seen = lease["first_seen"] if self.pihole_database else now
                if previous:
                    first_seen = min(first_seen, previous["first_seen"])
                device = {"id": mac, **lease, "display_name": friendly or lease["hostname"] or "Unnamed device", "vendor": label.get("vendor", "") or lease.get("vendor", ""), "owner": label.get("owner", ""), "role": label.get("role", "") or "Unclassified", "device_type": label.get("role", "") if label.get("role", "") in DEVICE_TYPES else "Unknown", "trust_level": label.get("trust_level", "") or "unreviewed", "notes": label.get("notes", ""), "first_seen": first_seen, "last_seen": lease["last_seen"] if self.pihole_database else now, "observed_in_latest_lease": not bool(self.pihole_database), "observation_source": self.source, "in_current_source": True}
                device.update(next_state["custom_labels"].get(mac, {}))
                if mac in scan_only:
                    device["observation_source"] = "network_scan"
                scan = self.scan_records.get(mac)
                if scan and device["device_type"] == "Unknown" and mac not in next_state["custom_labels"]:
                    device["device_type"] = scan["device_type"]
                    device["role"] = scan["device_type"]
                next_state["devices"][mac] = device
                source_observed = dt.datetime.fromisoformat(device["last_seen"]).timestamp()
                fresh_arrival = not self.pihole_database or (observed_at.timestamp() - RECENT_OBSERVATION_SECONDS <= source_observed <= observed_at.timestamp() and source_observed >= int(baseline_epoch))
                if previous is None and source_baseline and fresh_arrival:
                    next_state["events"].append({"id": hashlib.sha256((mac + now).encode()).hexdigest()[:24], "type": "new_device", "device_id": mac, "display_name": device["display_name"], "hostname": device["hostname"], "ip": device["ip"], "created_at": now, "read": False})
            next_state["events"] = next_state["events"][-MAX_EVENTS:]
            next_state["baseline_established"] = True
            if not source_baseline:
                next_state["baseline_at"] = now
            next_state["source"] = self.source
            next_state["updated"] = now
            try:
                self._save(next_state)
            except (OSError, ValueError, TypeError, KeyError):
                self._available = False
                self._notice = "Device state could not be saved. Discovery is stopped to avoid lost or duplicate notifications; check the private state directory and restart."
                self._fatal = self._notice
                return self.snapshot()
            self._state = next_state
            self._available = True
            notices = ["Pi-hole DNS/neighbor observations do not report every Wi-Fi join or prove a device is currently online. Showing the most recently observed address per MAC; stale records never create arrival notifications." if self.pihole_database else "DHCP observations do not prove a device is currently online. Devices outside this DHCP source may not appear."]
            if self._skipped:
                notices.append(f"Skipped {self._skipped} source records without a usable MAC, address, or observation time.")
            if label_notice:
                notices.append(label_notice)
            if scan_notice:
                notices.append(scan_notice)
            if capacity_reached:
                notices.append("Device history is full; additional identities are not recorded or notified.")
            if len(next_state["events"]) == MAX_EVENTS:
                notices.append(f"Only the newest {MAX_EVENTS} device notifications are retained.")
            self._notice = " ".join(notices)
            return self.snapshot()

    def snapshot(self):
        # A slow read/fsync in poll() must not hold every dashboard request.
        # Published views contain only previously completed state updates.
        if not self._lock.acquire(blocking=False):
            result = copy.deepcopy(self._published_snapshot)
            result['refreshing'] = True
            result['notice'] = 'Updating device observations; showing the last saved snapshot. ' + result['notice']
            now = time.time()
            for device in result['devices']:
                age = now - dt.datetime.fromisoformat(device['last_seen']).timestamp()
                device['recently_observed'] = result['available'] and device['in_current_source'] and 0 <= age <= RECENT_OBSERVATION_SECONDS
                if device['observation_source'] not in {'pihole_network', 'network_scan'}:
                    device['lease_active'] = device['observed_in_latest_lease'] and (device['lease_expires'] == 0 or device['lease_expires'] > now)
            return result
        try:
            result = self._snapshot_locked()
            result['refreshing'] = False
            self._published_snapshot = copy.deepcopy(result)
            return result
        finally:
            self._lock.release()

    def _snapshot_locked(self):
        with self._lock:
            data = copy.deepcopy(self._state)
            devices = sorted(data["devices"].values(), key=lambda row: (row["display_name"].lower(), row["mac"]))
            for device in devices:
                epoch = dt.datetime.fromisoformat(device["last_seen"]).timestamp()
                device["recently_observed"] = self._available and device["in_current_source"] and 0 <= time.time() - epoch <= RECENT_OBSERVATION_SECONDS
                device["lease_active"] = None if device["observation_source"] in {"pihole_network", "network_scan"} else device["observed_in_latest_lease"] and (device["lease_expires"] == 0 or device["lease_expires"] > time.time())
                scan = self.scan_records.get(device["mac"])
                device["addresses"] = list(dict.fromkeys([device["ip"]] + ([scan["ip"]] if scan else [])))
                device["hostname_source"] = scan["hostname_source"] if scan and scan["hostname"] == device["hostname"] else "Pi-hole hostname" if device["hostname"] and self.pihole_database else ""
                if scan:
                    device.update(scan_last_seen=scan["observed_at"], scan_services=copy.deepcopy(scan["services"]), scan_notice=scan["notice"], scan_reachable=True)
            events = list(reversed(data["events"]))
            return {"available": self._available, "notice": self._notice, "baseline_established": data["baseline_established"], "devices": devices, "events": events, "unread_count": sum(not event["read"] for event in events), "updated": data["updated"], "invalid_records": self._invalid, "skipped_records": self._skipped, "source": self.source, "source_label": SOURCES[self.source], "demo": self.demo}

    def acknowledge(self, event_id=None):
        """Persist read state for one event, or all events when id is None."""
        with self._lock:
            if self._fatal or (event_id is not None and (not isinstance(event_id, str) or not any(event["id"] == event_id for event in self._state["events"]))):
                return False
            state = copy.deepcopy(self._state)
            for event in state["events"]:
                if event_id is None or event["id"] == event_id:
                    event["read"] = True
            if not self.demo:
                if not self.state_file or not state["baseline_established"]:
                    return False
                try:
                    self._save(state)
                except (OSError, ValueError, TypeError, KeyError):
                    self._available = False
                    self._notice = "Notification read state could not be saved. Check the private state directory."
                    self._fatal = self._notice
                    return False
            self._state = state
            return True

    def label(self, device_id, display_name, device_type):
        """Assign a friendly name/type without rewriting the observed hostname."""
        _validate_label(display_name, device_type)
        with self._lock:
            if self._fatal or not isinstance(device_id, str) or device_id not in self._state["devices"]:
                return False
            state = copy.deepcopy(self._state)
            label = {"display_name": display_name.strip(), "device_type": device_type}
            state["custom_labels"][device_id] = label
            state["devices"][device_id].update(label)
            if not self.demo:
                try:
                    self._save(state)
                except (OSError, ValueError, TypeError, KeyError):
                    self._available = False
                    self._notice = "Device label could not be saved. Check the private state directory."
                    self._fatal = self._notice
                    return False
            self._state = state
            return True


def demo_state():
    """Explicit sample fixture: labels are curated, never inferred from DHCP."""
    now = dt.datetime.now(dt.timezone.utc)
    state = {"version": 2, "baseline_established": True, "devices": {}, "events": [], "updated": now.isoformat(), "custom_labels": {}, "source": "sample_data", "baseline_at": (now - dt.timedelta(days=1)).isoformat()}
    for index, name, hostname, role in ((12, "Work laptop", "example-laptop", "Laptop"), (24, "Family tablet", "family-ipad", "Tablet"), (51, "Living room TV", "living-room-tv", "TV")):
        mac = f"02:00:00:00:00:{index:02x}"
        seen = (now - dt.timedelta(minutes=2 if index == 24 else 120)).isoformat()
        device = {"id": mac, "mac": mac, "ip": f"192.168.50.{index}", "hostname": hostname, "display_name": name, "vendor": "", "owner": "Sample household", "role": role, "device_type": role, "trust_level": "unreviewed" if index == 24 else "trusted", "notes": "Sample inventory label", "first_seen": seen, "last_seen": now.isoformat(), "lease_expires": int(now.timestamp()) + 3600, "observed_in_latest_lease": True, "observation_source": "sample_data", "in_current_source": True}
        state["devices"][mac] = device
        if index == 24:
            state["events"].append({"id": hashlib.sha256((mac + seen).encode()).hexdigest()[:24], "type": "new_device", "device_id": mac, "display_name": name, "hostname": hostname, "ip": device["ip"], "created_at": seen, "read": False})
    return state
