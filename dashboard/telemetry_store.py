"""Durable, incremental local telemetry ingestion for OMEGA.

Complete readable records are processed, including available gzip rotations.
Memory/work per poll is bounded, not the tail of source history. The retained
ledger has explicit age/capacity limits. Original source records are preserved
separately from the bounded normalized fields used for AI evidence. A Wazuh
agent's diagnostic log is not a Wazuh manager alert source.
"""
from __future__ import annotations

import collections
import gzip
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time

UTC = dt.timezone.utc
MAX_RECORD_BYTES = 1024 * 1024
READ_CHUNK = 128 * 1024
LABELS = {"suricata": "Suricata network telemetry", "wazuh_alerts": "Wazuh manager alerts", "wazuh_archives": "Wazuh manager event archives", "pihole": "Pi-hole DNS activity"}


def _text(value, limit=400):
    if value is None or isinstance(value, (dict, list)):
        return ""
    return " ".join(str(value).split())[:limit]


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return ""


def _date(value):
    try:
        if isinstance(value, (float, int)) and not isinstance(value, bool):
            result = dt.datetime.fromtimestamp(value, UTC)
        elif isinstance(value, str):
            result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if result.tzinfo is None:
                return None
        else:
            return None
        return result.astimezone(UTC).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _pihole_text(value):
    """Keep undecodable SQLite text bytes in an explicit lossless representation.

    The query result remains JSON-serializable, while normalizers leave this
    structured value out of textual indicators. The original source is read-only.
    """
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return {"_omega_sqlite_text_hex": value.hex()}


def _now():
    return dt.datetime.now(UTC).isoformat()


def _directory(path, private=False):
    """Check every component, avoiding symlinks and unsafe state directories."""
    path = Path(os.path.abspath(path))
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        info = os.fstat(descriptor)
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("Telemetry state directory must be owned by this user with mode 0700")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _regular(path, private=False):
    directory = _directory(Path(path).parent, private)
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (private and (info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1)):
            os.close(fd)
            raise ValueError("Telemetry file must be a regular file with appropriate permissions")
        return fd, info
    finally:
        os.close(directory)


def _dict(value):
    return value if isinstance(value, dict) else {}


def normalize(stream, data, event_id):
    """Return bounded structured evidence; reject rows with no source identity."""
    if not isinstance(data, dict):
        raise ValueError("Event must be an object")
    event = {"id": event_id, "stream": stream, "source": "wazuh" if stream.startswith("wazuh") else stream,
             "timestamp": _date(data.get("timestamp")), "observed_at": _now(), "event_type": "",
             "severity": None, "title": "", "category": "", "source_ip": "", "destination_ip": "",
             "hostname": "", "domain": "", "agent_id": "", "agent_name": "", "rule_id": "", "action": "", "details": {}}
    details = event["details"]
    if stream == "suricata":
        if not isinstance(data.get("event_type"), str) or not data["event_type"]:
            raise ValueError("Missing Suricata event type")
        kind = _text(data["event_type"], 80)
        alert = _dict(data.get("alert"))
        event.update(event_type=kind, source_ip=_ip(data.get("src_ip")), destination_ip=_ip(data.get("dest_ip")),
                     title=_text(alert.get("signature")) if kind == "alert" else "Suricata " + kind,
                     category=_text(alert.get("category"), 150), action=_text(alert.get("action"), 80),
                     rule_id=_text(alert.get("signature_id"), 80))
        if kind == "alert":
            severity = alert.get("severity", 3)
            event["severity"] = severity if type(severity) is int and severity in (1, 2, 3) else 3
            details["signature_id"] = _text(alert.get("signature_id"),120)
        for key in ("src_port", "dest_port", "proto", "app_proto", "flow_id", "in_iface", "community_id"):
            if key in data:
                details[key] = _text(data[key], 120)
        dns, http, tls, flow = (_dict(data.get(key)) for key in ("dns", "http", "tls", "flow"))
        event["domain"] = _text(dns.get("rrname") or http.get("hostname") or tls.get("sni"), 253)
        if not event["domain"] and isinstance(dns.get("queries"), list) and dns["queries"]:
            event["domain"] = _text(_dict(dns["queries"][0]).get("rrname"), 253)
        for name, value in (("dns_type", dns.get("rrtype")), ("dns_rcode", dns.get("rcode")),
                            ("http_method", http.get("http_method")), ("http_status", http.get("status")),
                            ("tls_version", tls.get("version")), ("flow_state", flow.get("state")),
                            ("bytes_to_server", flow.get("bytes_toserver")), ("bytes_to_client", flow.get("bytes_toclient")),
                            ("packets_to_server", flow.get("pkts_toserver")), ("packets_to_client", flow.get("pkts_toclient"))):
            if value is not None:
                details[name] = _text(value, 100)
    elif stream.startswith("wazuh"):
        agent, rule, fields = (_dict(data.get(key)) for key in ("agent", "rule", "data"))
        if not (agent or rule or data.get("decoder")):
            raise ValueError("Missing Wazuh event structure")
        level = rule.get("level")
        try:
            level = int(level) if level is not None else None
        except (TypeError, ValueError):
            level = None
        event.update(event_type="alert" if rule else "event", title=_text(rule.get("description")) or "Wazuh collected event",
                     category=_text(_dict(data.get("decoder")).get("name"), 150),
                     source_ip=_ip(fields.get("srcip") or fields.get("src_ip")), destination_ip=_ip(fields.get("dstip") or fields.get("dest_ip")),
                     hostname=_text(agent.get("name"), 253), agent_id=_text(agent.get("id"), 80), agent_name=_text(agent.get("name"), 253),
                     rule_id=_text(rule.get("id"), 80), action=_text(fields.get("action"), 80))
        event["severity"] = (1 if level >= 12 else 2 if level >= 7 else 3) if level is not None and rule else None
        details["rule_level"] = level
        details["agent_ip"] = _ip(agent.get("ip"))
        details["location"] = _text(data.get("location"), 250)
        if "suricata" in details["location"].lower() and "eve.json" in details["location"].lower():
            details["origin"] = "suricata"
            details["origin_timestamp"] = _date(fields.get("timestamp"))
            details["flow_id"] = _text(fields.get("flow_id"),120)
            details["community_id"] = _text(fields.get("community_id"),120)
            details["signature_id"] = _text(_dict(fields.get("alert")).get("signature_id"),120)
            details["origin_event_type"] = _text(fields.get("event_type"),80)
        details["manager"] = _text(_dict(data.get("manager")).get("name"), 100)
        for key in ("groups", "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc"):
            if isinstance(rule.get(key), list):
                details[key] = [_text(value, 80) for value in rule[key][:32]]
        mitre = _dict(rule.get("mitre"))
        for key in ("id", "tactic", "technique"):
            if isinstance(mitre.get(key), list):
                details["mitre_" + key] = [_text(value, 150) for value in mitre[key][:32]]
        syscheck = _dict(data.get("syscheck"))
        for key in ("path", "event", "mode", "sha256_before", "sha256_after"):
            if key in syscheck:
                details["file_" + key] = _text(syscheck[key], 350)
        for key in ("srcport", "dstport", "protocol", "status", "system_name"):
            if key in fields:
                details[key] = _text(fields[key], 150)
        vulnerability = _dict(fields.get("vulnerability"))
        for key in ("cve", "severity", "status", "title"):
            if key in vulnerability:
                details["vulnerability_" + key] = _text(vulnerability[key], 350)
    elif stream == "pihole":
        binary_fields = sorted(key for key, value in data.items()
                               if isinstance(value, dict) and set(value) == {"_omega_sqlite_text_hex"})
        if binary_fields:
            details["binary_text_fields"] = binary_fields
        event.update(event_type="dns", title="Pi-hole DNS query", source_ip=_ip(data.get("client")),
                     hostname=_text(data.get("hostname"), 253), domain=_text(data.get("domain"), 253),
                     action=_text(data.get("status"), 80), category="DNS activity")
        for key in ("query_id", "query_type", "status", "forward", "reply_type", "reply_time", "dnssec", "additional_info"):
            if data.get(key) is not None:
                details[key] = _text(data[key], 250)
    else:
        raise ValueError("Unsupported telemetry stream")
    return event


class TelemetryStore:
    def __init__(self, state_file, eve_path=None, wazuh_alerts_path=None, wazuh_archives_path=None,
                 pihole_database=None, retention_days=30, max_events=2000000, wazuh_sync_status=None, from_now=False):
        self.path = Path(os.path.abspath(state_file))
        self.sources = {"suricata": eve_path, "wazuh_alerts": wazuh_alerts_path,
                        "wazuh_archives": wazuh_archives_path, "pihole": pihole_database}
        self.retention_days = max(1, min(int(retention_days), 3650))
        self.max_events = max(1, int(max_events))
        self.wazuh_sync_status = Path(wazuh_sync_status) if wazuh_sync_status else None
        self.lock = threading.RLock()
        self.gzip_readers = {}
        self.last_maintenance = 0
        self.batch_totals = None
        self.read_snapshot_connection = None
        directory = _directory(self.path.parent, private=True)
        try:
            try:
                descriptor = os.open(self.path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                os.close(descriptor)
            except FileExistsError:
                pass
        finally:
            os.close(directory)
        fd, _ = _regular(self.path, private=True)
        os.close(fd)
        self.db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            self.db.close()
            raise ValueError("Unsupported telemetry state version")
        original_table_exists = bool(self.db.execute("SELECT 1 FROM sqlite_master WHERE name='original_events'").fetchone())
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, stream TEXT NOT NULL, source TEXT NOT NULL,
                timestamp TEXT, observed_at TEXT NOT NULL, event_type TEXT NOT NULL,
                severity INTEGER, title TEXT, category TEXT, source_ip TEXT,
                destination_ip TEXT, hostname TEXT, domain TEXT, rule_id TEXT,
                payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_time ON events(timestamp, id);
            CREATE INDEX IF NOT EXISTS events_stream ON events(stream);
            CREATE INDEX IF NOT EXISTS events_alert ON events(event_type, severity);
            CREATE INDEX IF NOT EXISTS events_source_time ON events(source,event_type,timestamp);
            CREATE TABLE IF NOT EXISTS cursors (
                stream TEXT NOT NULL, identity TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 0,
                offset INTEGER NOT NULL DEFAULT 0, pending BLOB NOT NULL DEFAULT X'',
                dropping INTEGER NOT NULL DEFAULT 0, anchor BLOB NOT NULL DEFAULT X'',
                PRIMARY KEY(stream, identity));
            CREATE TABLE IF NOT EXISTS health (stream TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS totals (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS original_events (id TEXT NOT NULL, stream TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(id,stream));
            CREATE TABLE IF NOT EXISTS event_counts (stream TEXT NOT NULL, kind TEXT NOT NULL, events INTEGER NOT NULL, first TEXT, last TEXT, PRIMARY KEY(stream,kind));
            CREATE TRIGGER IF NOT EXISTS events_count_insert AFTER INSERT ON events BEGIN
                INSERT INTO event_counts(stream,kind,events,first,last) VALUES (new.stream,new.event_type,1,new.timestamp,new.timestamp)
                ON CONFLICT(stream,kind) DO UPDATE SET events=events+1,
                    first=CASE WHEN first IS NULL OR excluded.first<first THEN excluded.first ELSE first END,
                    last=CASE WHEN last IS NULL OR excluded.last>last THEN excluded.last ELSE last END;
            END;
            CREATE TRIGGER IF NOT EXISTS events_count_delete AFTER DELETE ON events BEGIN
                UPDATE event_counts SET events=events-1 WHERE stream=old.stream AND kind=old.event_type;
            END;
            PRAGMA user_version=1;
        """)
        if not original_table_exists:
            # Re-read available sources once to preserve original fields for
            # events ingested by the earlier normalized-only prototype.
            self.db.execute("DELETE FROM cursors")
        saved_start = self.db.execute("SELECT value FROM metadata WHERE name='collection_started'").fetchone()
        if from_now and not saved_start:
            if self.db.execute("SELECT 1 FROM events LIMIT 1").fetchone():
                raise ValueError("Start-from-now collection requires a new ledger; existing evidence is preserved separately")
            self.db.execute("INSERT INTO metadata(name,value) VALUES ('collection_started',?)",(_now(),))
            saved_start = self.db.execute("SELECT value FROM metadata WHERE name='collection_started'").fetchone()
        self.collection_started = saved_start[0] if saved_start else None
        self.db.commit()
        self.release_completed_archives()

    def close(self):
        with self.lock:
            for reader in self.gzip_readers.values():
                source = reader.fileobj
                reader.close()
                if source:
                    source.close()
            self.gzip_readers.clear()
            self.db.close()

    def freeze(self):
        """Pin a consistent read transaction without copying a multi-GB ledger.

        Writers continue through WAL. The caller must close promptly so old WAL
        pages can be reclaimed; report generation also monitors free disk space.
        """
        frozen = object.__new__(TelemetryStore)
        frozen.path, frozen.sources = self.path, dict(self.sources)
        frozen.retention_days, frozen.max_events = self.retention_days, self.max_events
        frozen.wazuh_sync_status = self.wazuh_sync_status
        frozen.collection_started = self.collection_started
        frozen.lock, frozen.gzip_readers = threading.RLock(), {}
        connection = sqlite3.connect(self.path.as_uri()+"?mode=ro",uri=True,timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            connection.execute("SELECT id FROM events LIMIT 1").fetchone()
        except Exception:
            connection.close()
            raise
        frozen.db = frozen.read_snapshot_connection = connection
        return frozen

    def _increment(self, key, value=1):
        if self.batch_totals is not None:
            self.batch_totals[key] += value
            return
        self.db.execute("INSERT INTO totals(name,value) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value", (key, value))

    def _store(self, stream, data, origin):
        timestamp = _date(data.get("timestamp")) if isinstance(data,dict) else None
        if self.collection_started and timestamp and timestamp < self.collection_started:
            self._increment(stream+":before_start")
            return
        stable = origin
        if stream == "suricata" and data.get("timestamp"):
            stable = "suricata:" + json.dumps(data, sort_keys=True, separators=(",", ":"))
        if stream.startswith("wazuh") and data.get("id"):
            # The manager's same event may exist in both alerts and archives.
            stable = "wazuh:" + _text(data.get("id"), 100) + ":" + _text(data.get("timestamp"), 80) + ":" + _text(_dict(data.get("agent")).get("id"), 80)
        event_id = hashlib.sha256(stable.encode()).hexdigest()[:24]
        event = normalize(stream, data, event_id)
        columns = ("id", "stream", "source", "timestamp", "observed_at", "event_type", "severity", "title", "category", "source_ip", "destination_ip", "hostname", "domain", "rule_id")
        cursor = self.db.execute("INSERT OR IGNORE INTO events (" + ",".join(columns) + ",payload) VALUES (" + ",".join("?" for _ in range(len(columns) + 1)) + ")", tuple(event[key] for key in columns) + (json.dumps(event, separators=(",", ":")),))
        self.db.execute("INSERT OR IGNORE INTO original_events(id,stream,record) VALUES (?,?,?)",(event_id,stream,json.dumps(data,separators=(",",":"))))
        self._increment(stream + ":valid")
        self._increment("total_records")
        if cursor.rowcount:
            self._increment("total_ingested")
        else:
            self._increment(stream + ":duplicates")

    def _cursor(self, stream, identity):
        row = self.db.execute("SELECT * FROM cursors WHERE stream=? AND identity=?", (stream, identity)).fetchone()
        return dict(row) if row else {"stream": stream, "identity": identity, "generation": 0, "offset": 0, "pending": b"", "dropping": 0, "anchor": b""}

    def _save_cursor(self, cursor):
        self.db.execute("INSERT OR REPLACE INTO cursors(stream,identity,generation,offset,pending,dropping,anchor) VALUES (:stream,:identity,:generation,:offset,:pending,:dropping,:anchor)", cursor)

    def _log_files(self, path, stream=None, include_consumed=False):
        path = Path(os.path.abspath(path))
        directory = _directory(path.parent)
        files, compressed, unsafe = [], 0, 0
        try:
            candidates = [path.parent / name for name in os.listdir(directory)]
            if path.name in {"alerts.json", "archives.json"}:
                prefix = "ossec-alerts-" if path.name == "alerts.json" else "ossec-archive-"
                errors = []
                for folder, directories, names in os.walk(path.parent,followlinks=False,onerror=errors.append):
                    for name in list(directories):
                        if (Path(folder)/name).is_symlink():
                            directories.remove(name)
                            unsafe += 1
                    candidates.extend(Path(folder)/name for name in names if name.startswith(prefix) and name.endswith((".json", ".json.gz")))
                unsafe += len(errors)
            for candidate in candidates:
                name = candidate.name
                nested = candidate.parent != path.parent
                if not nested and name != path.name and not name.startswith(path.name + "."):
                    continue
                info = candidate.lstat()
                if not stat.S_ISREG(info.st_mode):
                    unsafe += 1
                    continue
                if self.collection_started and candidate != path and info.st_mtime < dt.datetime.fromisoformat(self.collection_started).timestamp():
                    continue
                if self.collection_started and name.endswith('.gz') and self.db.execute("SELECT 1 FROM metadata WHERE name=?",(f'ignore:{stream}:{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}',)).fetchone():
                    continue
                if not include_consumed and name.endswith('.gz') and self.db.execute("SELECT 1 FROM metadata WHERE name=?", (self._archive_marker(stream, info),)).fetchone():
                    continue
                if name.endswith((".bz2", ".xz", ".zip", ".zst")):
                    compressed += 1
                    continue
                files.append((0 if candidate == path else info.st_mtime_ns, str(candidate), candidate))
        finally:
            os.close(directory)
        return sorted(files), compressed, unsafe

    @staticmethod
    def _archive_marker(stream, info):
        return f'consumed_archive:{stream}:{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}'

    def release_completed_archives(self):
        """Release expanded copies only after their committed cursor reaches EOF.

        Keep the original gzip and every retained event. A durable marker for
        the exact source version prevents re-expansion/re-import after restart.
        Mark before unlinking, so interrupted cleanup can safely retry.
        """
        folder = self.path.parent / 'archive-cache'
        if not folder.exists():
            return 0
        directory = _directory(folder, private=True)
        released = 0
        try:
            for stream, source in self.sources.items():
                if not source or stream == 'pihole':
                    continue
                try:
                    files, _, _ = self._log_files(source, stream, include_consumed=True)
                except OSError:
                    continue
                for _, _, original in files:
                    if not original.name.endswith('.gz'):
                        continue
                    try:
                        descriptor, info = _regular(original)
                        os.close(descriptor)
                        identity = hashlib.sha256(f'{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}'.encode()).hexdigest()
                        if identity in self.gzip_readers:
                            continue
                        marker = self._archive_marker(stream, info)
                        recorded = self.db.execute('SELECT 1 FROM metadata WHERE name=?', (marker,)).fetchone()
                        target, complete = folder / (identity+'.json'), folder / (identity+'.done')
                        if not recorded:
                            descriptor, _ = _regular(complete, private=True)
                            os.close(descriptor)
                            descriptor, cached = _regular(target, private=True)
                            try:
                                cursor = self._cursor(stream, f'{cached.st_dev}:{cached.st_ino}')
                                if cursor['offset'] != cached.st_size or cursor['pending'] or cursor['dropping'] or cursor['anchor'] != os.pread(descriptor, min(64, cached.st_size), 0):
                                    continue
                            finally:
                                os.close(descriptor)
                            # The source must still be the same immutable version.
                            if original.stat() != info:
                                continue
                            with self.db:
                                self.db.execute('INSERT OR IGNORE INTO metadata(name,value) VALUES (?,?)', (marker, _now()))
                        for cached_path in (target, complete):
                            try:
                                descriptor, cached = _regular(cached_path, private=True)
                                os.close(descriptor)
                                cached_path.unlink()
                                released += cached.st_blocks * 512
                            except FileNotFoundError:
                                pass
                    except OSError:
                        continue
            if released:
                os.fsync(directory)
        finally:
            os.close(directory)
        return released

    def _baseline_stream(self, stream, path):
        """Skip pre-existing bytes/rows once, then retain all subsequent cursors."""
        key = 'baseline:'+stream
        if not self.collection_started or self.db.execute("SELECT 1 FROM metadata WHERE name=?",(key,)).fetchone():
            return
        if stream == 'pihole':
            connection, info = self._pihole_connection(path)
            try:
                names = dict(connection.execute("SELECT name,type FROM sqlite_master WHERE name IN ('query_storage','queries')"))
                table = 'query_storage' if names.get('query_storage') == 'table' else 'queries' if names.get('queries') == 'table' else None
                if table is None: raise ValueError('Unsupported Pi-hole query history')
                cursor = self._cursor(stream,f'{info.st_dev}:{info.st_ino}')
                cursor['offset'] = connection.execute('SELECT COALESCE(MAX(id),0) FROM '+table).fetchone()[0]
                self._save_cursor(cursor)
            finally:
                connection.close()
        else:
            # Existing archives are outside this run, including a rotation made
            # between application startup and this source's first poll.
            files, _, _ = self._log_files(path,stream)
            if not any(candidate == Path(os.path.abspath(path)) for _,_,candidate in files):
                raise ValueError('Current source log is unavailable')
            for _,_,candidate in files:
                descriptor, info = _regular(candidate)
                try:
                    if candidate.name.endswith('.gz'):
                        self.db.execute("INSERT OR IGNORE INTO metadata(name,value) VALUES (?,?)",(f'ignore:{stream}:{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}',_now()))
                        continue
                    cursor = self._cursor(stream,f'{info.st_dev}:{info.st_ino}')
                    cursor['offset'] = info.st_size
                    cursor['anchor'] = os.pread(descriptor,min(64,info.st_size),0)
                    tail = os.pread(descriptor,min(MAX_RECORD_BYTES,info.st_size),max(0,info.st_size-MAX_RECORD_BYTES))
                    cursor['pending'] = tail.rsplit(b'\n',1)[-1] if tail else b''
                    self._save_cursor(cursor)
                finally:
                    os.close(descriptor)
        self.db.execute("INSERT INTO metadata(name,value) VALUES (?,?)",(key,_now()))

    def _expand_gzip(self, path, budget):
        """Expand bounded chunks into private resumable cache; never read all into RAM."""
        fd, info = _regular(path)
        os.close(fd)
        identity = hashlib.sha256(f"{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}".encode()).hexdigest()
        folder = self.path.parent / "archive-cache"
        folder.mkdir(mode=0o700, exist_ok=True)
        checked = _directory(folder, private=True); os.close(checked)
        target = folder / (identity + ".json")
        complete = folder / (identity + ".done")
        if complete.exists():
            return target, True
        if not target.exists():
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        descriptor, current = _regular(target, private=True)
        os.close(descriptor)
        reader = self.gzip_readers.get(identity)
        if reader is None:
            descriptor, _ = _regular(path)
            reader = gzip.GzipFile(fileobj=os.fdopen(descriptor, "rb"))
            reader.seek(current.st_size)
            self.gzip_readers[identity] = reader
        chunk = reader.read(max(1, budget))
        if chunk:
            with target.open("ab") as output:
                output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        else:
            source = reader.fileobj
            reader.close(); self.gzip_readers.pop(identity, None)
            if source:
                source.close()
            descriptor = os.open(complete, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        return target, not bool(chunk)

    def _read_log_file(self, stream, candidate, budget, recent=False):
        used, backlog, pending_records = 0, 0, 0
        fd, info = _regular(candidate)
        try:
            identity = str(info.st_dev) + ":" + str(info.st_ino)
            cursor = self._cursor(stream, identity + (":recent" if recent else ""))
            if recent and not cursor["offset"] and info.st_size > budget:
                start = max(0, info.st_size-budget)
                tail = os.pread(fd,min(MAX_RECORD_BYTES,info.st_size-start),start)
                newline = tail.find(b"\n")
                cursor["offset"] = start+newline+1 if newline >= 0 else info.st_size
            anchor = cursor["anchor"]
            if info.st_size < cursor["offset"] or (anchor and os.pread(fd, len(anchor), 0) != anchor):
                cursor.update(generation=cursor["generation"] + 1, offset=0, pending=b"", dropping=0, anchor=b"")
                if not recent:
                    self._increment(stream + ":resets")
            if not cursor["anchor"] and info.st_size:
                cursor["anchor"] = os.pread(fd, min(64, info.st_size), 0)
            while used < budget and cursor["offset"] < info.st_size:
                chunk = os.pread(fd, min(READ_CHUNK, budget - used, info.st_size - cursor["offset"]), cursor["offset"])
                if not chunk:
                    break
                used += len(chunk)
                for segment in chunk.splitlines(keepends=True):
                    cursor["offset"] += len(segment)
                    complete = segment.endswith(b"\n")
                    if cursor["dropping"] or len(cursor["pending"]) + len(segment) > MAX_RECORD_BYTES:
                        cursor["pending"] = b""
                        cursor["dropping"] = 1
                        if complete:
                            cursor["dropping"] = 0
                            if not recent:
                                self._increment(stream + ":invalid")
                        continue
                    cursor["pending"] += segment
                    if not complete:
                        continue
                    line = cursor["pending"].strip()
                    cursor["pending"] = b""
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if not isinstance(data, dict):
                            raise ValueError("Event is not an object")
                        self._store(stream, data, f"{stream}:{identity}:{cursor['generation']}:{cursor['offset']}")
                    except (ValueError, TypeError, UnicodeError, RecursionError):
                        if not recent:
                            self._increment(stream + ":invalid")
                self._save_cursor(cursor)
            self._save_cursor(cursor)
            backlog += max(0, info.st_size - cursor["offset"])
            pending_records += bool(cursor["pending"] or cursor["dropping"])
        finally:
            os.close(fd)
        return used, backlog, pending_records

    def _poll_log(self, stream, path, budget):
        files, compressed, unsafe = self._log_files(path,stream)
        if not files:
            raise ValueError("No readable uncompressed telemetry files are available")
        used, backlog, pending_records, gzip_pending = 0, 0, 0, 0
        permission_unread = 0
        # Keep current detections visible while importing older history.
        if budget >= READ_CHUNK:
            for _, _, candidate in files:
                if candidate == Path(os.path.abspath(path)):
                    descriptor, info = _regular(candidate); os.close(descriptor)
                    identity = str(info.st_dev) + ":" + str(info.st_ino)
                    cursor = self._cursor(stream,identity)
                    if info.st_size-cursor["offset"] > budget:
                        used, _, _ = self._read_log_file(stream,candidate,min(512*1024,budget//4),recent=True)
                    break
        for _, _, candidate in files:
            if candidate.name.endswith(".gz"):
                if used >= budget:
                    gzip_pending += 1
                    continue
                try:
                    candidate, complete = self._expand_gzip(candidate, budget - used)
                except PermissionError:
                    permission_unread += 1
                    gzip_pending += 1
                    continue
                except (OSError, EOFError):
                    compressed += 1
                    gzip_pending += 1
                    continue
                gzip_pending += not complete
            read, remaining, partial = self._read_log_file(stream,candidate,budget-used)
            used += read; backlog += remaining; pending_records += partial
        return {"backlog_bytes": backlog, "backlog_rows": 0, "caught_up": backlog == 0 and gzip_pending == 0 and compressed == 0 and unsafe == 0,
                "pending_records": pending_records, "rotated_files": max(0, len(files) - 1),
                "compressed_files_unread": compressed, "permission_files_unread": permission_unread, "gzip_archives_pending": gzip_pending, "unsafe_files_unread": unsafe}, used

    def _pihole_connection(self, path):
        path = Path(os.path.abspath(path))
        fd, info = _regular(path)
        try:
            companions = set()
            for suffix in ("-wal", "-shm", "-journal"):
                try:
                    sibling, _ = _regular(str(path) + suffix)
                    os.close(sibling)
                    companions.add(suffix)
                except FileNotFoundError:
                    pass
            if os.pread(fd, 2, 18) == b"\x02\x02" and not {"-wal", "-shm"}.issubset(companions):
                raise ValueError("Pi-hole WAL files are not available for a read-only snapshot")
            connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
            connection.row_factory = sqlite3.Row
            connection.text_factory = _pihole_text
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            deadline = time.monotonic() + 10
            connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            if hasattr(connection, "setlimit"):
                connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RECORD_BYTES)
                connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            after = path.stat(follow_symlinks=False)
            if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
                connection.close()
                raise ValueError("Pi-hole database changed identity")
            return connection, info
        finally:
            os.close(fd)

    def _poll_pihole(self, path, max_rows):
        connection, info = self._pihole_connection(path)
        try:
            schema = {row[0]: row[1] for row in connection.execute("SELECT name,type FROM sqlite_master WHERE name IN ('query_storage','queries','domain_by_id','client_by_id','forward_by_id','addinfo_by_id')")}
            table = "query_storage" if schema.get("query_storage") == "table" else "queries" if schema.get("queries") == "table" else None
            if not table:
                raise ValueError("Unsupported Pi-hole query-history schema")
            columns = {row[1] for row in connection.execute("PRAGMA table_info(" + table + ")")}
            if not {"id", "timestamp", "type", "status", "domain", "client"}.issubset(columns):
                raise ValueError("Pi-hole query-history columns are unavailable")
            fields = ["q.id AS query_id", "q.timestamp", "q.type AS query_type", "q.status"]
            joins = []
            for key, companion, value in (("domain", "domain_by_id", "domain"), ("client", "client_by_id", "ip"), ("forward", "forward_by_id", "forward"), ("additional_info", "addinfo_by_id", "content")):
                if key not in columns:
                    continue
                if schema.get(companion) == "table":
                    companion_columns = {row[1] for row in connection.execute("PRAGMA table_info(" + companion + ")")}
                    if {"id", value}.issubset(companion_columns):
                        alias = "j_" + key
                        joins.append(f"LEFT JOIN {companion} AS {alias} ON typeof(q.{key})='integer' AND {alias}.id=q.{key}")
                        fields.append(f"substr(CASE WHEN typeof(q.{key})='integer' THEN {alias}.{value} ELSE q.{key} END,1,350) AS {key}")
                        if key == "client" and "name" in companion_columns:
                            fields.append(f"substr({alias}.name,1,254) AS hostname")
                        continue
                fields.append(f"substr(q.{key},1,350) AS {key}")
            for key in ("reply_type", "reply_time", "dnssec", "list_id", "ede"):
                if key in columns:
                    fields.append("q." + key)
            identity = str(info.st_dev) + ":" + str(info.st_ino)
            cursor = self._cursor("pihole", identity)
            max_id = connection.execute("SELECT COALESCE(MAX(id),0) FROM " + table).fetchone()[0]
            if max_id < cursor["offset"]:
                cursor.update(offset=0, generation=cursor["generation"] + 1)
                self._increment("pihole:resets")
            boundary = dt.datetime.fromisoformat(self.collection_started).timestamp() if self.collection_started else None
            clause = " AND q.timestamp>=?" if boundary is not None else ""
            params = (cursor['offset'],boundary,max_rows) if boundary is not None else (cursor['offset'],max_rows)
            query = "SELECT " + ",".join(fields) + " FROM " + table + " AS q " + " ".join(joins) + " WHERE q.id>?"+clause+" ORDER BY q.id LIMIT ?"
            reader = connection.execute(query, params)
            rows = []
            while len(rows) < max_rows:
                try:
                    batch = reader.fetchmany(min(100, max_rows - len(rows)))
                except sqlite3.OperationalError as exc:
                    # Commit complete fetched batches when the read budget expires.
                    # A failed fetch may have read more rows: do not advance past
                    # the last returned row, so those rows are retried next poll.
                    if getattr(exc, "sqlite_errorcode", None) != sqlite3.SQLITE_INTERRUPT or not rows:
                        raise
                    break
                if not batch:
                    break
                rows.extend(batch)
            connection.set_progress_handler(None,0)
            for row in rows:
                data = dict(row)
                # Stable source query identity also prevents duplication if FTL
                # rewrites its database while preserving existing history.
                origin = "pihole:" + json.dumps([data.get(key) for key in ("query_id", "timestamp", "domain", "client", "query_type")], separators=(",", ":"))
                try:
                    self._store("pihole", data, origin)
                except (ValueError, TypeError, UnicodeError, RecursionError):
                    self._increment("pihole:invalid")
                cursor["offset"] = data["query_id"]
            if not rows and boundary is not None:
                cursor['offset'] = max_id
            self._save_cursor(cursor)
            remaining = connection.execute("SELECT COUNT(*) FROM " + table + " AS q WHERE q.id>?"+clause, (cursor['offset'],boundary) if boundary is not None else (cursor['offset'],)).fetchone()[0]
            return {"backlog_bytes": 0, "backlog_rows": remaining, "caught_up": remaining == 0,
                    "pending_records": 0, "rotated_files": 0, "compressed_files_unread": 0,
                    "unsafe_files_unread": 0, "source_high_water_id": max_id, "processed_high_water_id": cursor["offset"]}
        finally:
            connection.close()

    def poll(self, max_bytes=4 * 1024 * 1024, max_rows=5000, include_snapshot=True):
        """Ingest each configured source fairly, committing records and cursors together."""
        with self.lock:
            for stream, path in self.sources.items():
                health = {"id": stream, "label": LABELS[stream], "configured": bool(path), "available": False,
                          "notice": "Source is not configured.", "last_polled": _now(), "caught_up": False,
                          "backlog_bytes": 0, "backlog_rows": 0, "pending_records": 0,
                          "compressed_files_unread": 0, "unsafe_files_unread": 0, "rotated_files": 0}
                if path:
                    try:
                        with self.db:
                            self.batch_totals = collections.Counter()
                            self._baseline_stream(stream,path)
                            detail = self._poll_pihole(path, max(1, int(max_rows))) if stream == "pihole" else self._poll_log(stream, path, max(1, int(max_bytes)))[0]
                            counters = self.batch_totals
                            self.batch_totals = None
                            for key, value in counters.items():
                                self._increment(key,value)
                        health.update(detail, available=True, notice="")
                        if detail.get("permission_files_unread"):
                            health["notice"] = "Some compressed sources or expansion caches could not be accessed. Check collector read/write permissions."
                        elif detail["compressed_files_unread"]:
                            health["notice"] = "Some compressed sources could not be read completely. Check transfer completion, integrity and cache access."
                        elif not detail["caught_up"]:
                            health["notice"] = "Catching up on new events received since collection began." if self.collection_started else "Importing available source history; more records remain."
                    except (OSError, ValueError, sqlite3.Error, OverflowError) as exc:
                        # Include a useful class, never source data or raw SQL.
                        health["notice"] = "Source cannot currently be read (" + type(exc).__name__ + "). Check its path, format and read permissions."
                    finally:
                        self.batch_totals = None
                with self.db:
                    self.db.execute("INSERT OR REPLACE INTO health(stream,value) VALUES (?,?)", (stream, json.dumps(health)))
            self.release_completed_archives()
            if include_snapshot or time.monotonic()-self.last_maintenance > 60:
                with self.db:
                    cutoff = (dt.datetime.now(UTC) - dt.timedelta(days=self.retention_days)).isoformat()
                    removed = self.db.execute("DELETE FROM events WHERE timestamp<? OR (timestamp IS NULL AND observed_at<?)", (cutoff,cutoff)).rowcount
                    ready = self.db.execute("SELECT value FROM totals WHERE name='event_counts_ready'").fetchone()
                    count = self.db.execute("SELECT COALESCE(SUM(events),0) FROM event_counts").fetchone()[0] if ready and ready[0] else self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                    if count > self.max_events:
                        removed += self.db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY COALESCE(timestamp,observed_at),id LIMIT ?)", (count - self.max_events,)).rowcount
                    if removed:
                        self._increment("pruned_events", removed)
                        self.db.execute("INSERT OR REPLACE INTO totals(name,value) VALUES ('event_counts_ready',0)")
                        self.db.execute("DELETE FROM original_events WHERE id NOT IN (SELECT id FROM events)")
                self.last_maintenance = time.monotonic()
            if include_snapshot:
                return self.snapshot()
            states = [json.loads(row[0]) for row in self.db.execute("SELECT value FROM health")]
            return {"caught_up":all(row.get("caught_up",False) for row in states if row["configured"])}

    def snapshot(self, alert_limit=200):
        with self.lock:
            totals = dict(self.db.execute("SELECT name,value FROM totals"))
            if totals.get("event_counts_ready"):
                groups = list(self.db.execute("SELECT stream,kind,events,first,last FROM event_counts WHERE events>0"))
            else:
                groups = list(self.db.execute("SELECT stream,event_type,COUNT(*),MIN(timestamp),MAX(timestamp) FROM events GROUP BY stream,event_type"))
                if not self.read_snapshot_connection:
                    with self.db:
                        self.db.execute("DELETE FROM event_counts")
                        self.db.executemany("INSERT INTO event_counts(stream,kind,events,first,last) VALUES (?,?,?,?,?)",groups)
                        self.db.execute("INSERT OR REPLACE INTO totals(name,value) VALUES ('event_counts_ready',1)")
            grouped, type_counts = {}, collections.Counter()
            for stream, kind, count, first, last in groups:
                row = grouped.setdefault(stream,{"events":0,"alerts":0,"dns":0,"updated":None})
                row["events"] += count
                row["alerts"] += count if kind == "alert" else 0
                row["dns"] += count if kind == "dns" else 0
                if last and (not row["updated"] or last>row["updated"]): row["updated"]=last
                type_counts[("wazuh" if stream.startswith("wazuh") else stream,kind)] += count
            health = {row[0]: json.loads(row[1]) for row in self.db.execute("SELECT stream,value FROM health")}
            sources = []
            for stream, path in self.sources.items():
                row = health.get(stream, {"id": stream, "label": LABELS[stream], "configured": bool(path), "available": False, "notice": "Awaiting first telemetry poll.", "caught_up": False})
                row.update({key: grouped.get(stream, {}).get(key, None if key == "updated" else 0) for key in ("events", "alerts", "dns", "updated")})
                row.update(invalid=totals.get(stream + ":invalid", 0), total_records=totals.get(stream + ":valid", 0),
                           duplicate_records=totals.get(stream + ":duplicates", 0), resets=totals.get(stream + ":resets", 0), truncated=False)
                baseline = self.db.execute("SELECT value FROM metadata WHERE name=?",('baseline:'+stream,)).fetchone()
                row['collection_started'] = baseline[0] if baseline else None
                if stream.startswith("wazuh") and self.wazuh_sync_status:
                    try:
                        descriptor, _ = _regular(self.wazuh_sync_status)
                        with os.fdopen(descriptor,"rb") as status_file:
                            status = json.loads(status_file.read(16385))
                        updated = _date(status.get("checked_at"))
                        age = time.time()-dt.datetime.fromisoformat(updated).timestamp() if updated else float("inf")
                        result = status.get("sources",{}).get(stream.removeprefix("wazuh_"),{})
                        row["sync_current"] = -60 <= age <= 120 and result.get("ok") is True
                        row["sync_updated"] = updated
                    except (OSError,ValueError,TypeError,AttributeError):
                        row["sync_current"] = False
                    if not row["sync_current"]:
                        row["caught_up"] = False
                        row["notice"] = "Wazuh manager sync is stale or failing. Retained records remain available; new event coverage is unverified."
                sources.append(row)
            count = sum(row[2] for row in groups)
            first = min((row[3] for row in groups if row[3]),default=None)
            last = max((row[4] for row in groups if row[4]),default=None)
            types = [{"source": source,"event_type":kind,"count":number} for (source,kind),number in type_counts.most_common()]
            limitations = ["Counts and correlations cover retained normalized events, not all traffic or all historical activity.",
                           "AI uses normalized fields and selected examples; preserved original sensor records are available separately in the report export.",
                           "Gzip rotations are imported incrementally; corrupt/unsupported archives and upstream-deleted history are reported as gaps.",
                           "Wazuh non-alert events require manager JSON archives to be enabled and supplied separately."]
            if any(not item["available"] for item in sources):
                limitations.append("One or more sources are unavailable or unconfigured; combined coverage is incomplete.")
            if self.collection_started:
                limitations.append("Collection starts at the recorded cutover. Pre-existing history is intentionally excluded; each source's baseline time is recorded separately.")
            if any(item.get("pending_records") for item in sources):
                limitations.append("Incomplete source lines are retained in durable cursors until a terminating newline arrives.")
            coverage = {"retention_days": self.retention_days, "max_events": self.max_events,
                        "collection_started": self.collection_started,
                        "collection_mode": "from_now" if self.collection_started else "available_history",
                        "stored_events": count, "first_event": first, "last_event": last,
                        "total_ingested": totals.get("total_ingested", 0), "total_records": totals.get("total_records", 0),
                        "pruned_events": totals.get("pruned_events", 0),
                        "original_events_retained": self.db.execute("SELECT COUNT(*) FROM original_events").fetchone()[0],
                        "caught_up": all(row.get("caught_up", False) for row in sources if row["configured"]) and any(row["configured"] for row in sources),
                        "limitations": limitations}
            limit = max(0,min(int(alert_limit),10000))
            selected = {}
            if limit:
                for source, quota in (("wazuh",(limit+1)//2),("suricata",limit//2)):
                    for row in self.db.execute("SELECT id,payload FROM events WHERE source=? AND event_type='alert' ORDER BY timestamp DESC,id DESC LIMIT ?",(source,quota)):
                        selected[row[0]]=row[1]
                if len(selected)<limit:
                    for row in self.db.execute("SELECT id,payload FROM events WHERE event_type='alert' ORDER BY timestamp DESC,id DESC LIMIT ?",(limit,)):
                        if len(selected)>=limit: break
                        selected[row[0]]=row[1]
            alert_rows = [(payload,) for payload in selected.values()]
            alerts = []
            for row in alert_rows:
                event = json.loads(row[0])
                alerts.append({"id": event["id"], "timestamp": event["timestamp"], "signature": event["title"],
                               "severity": event["severity"] or 3, "source": event["source_ip"] or event["details"].get("agent_ip") or event["agent_name"] or "Unknown",
                               "destination": event["destination_ip"] or "Unknown", "category": event["category"],
                               "sensor": event["source"], "hostname": event["hostname"], "agent": event["agent_name"],
                               "rule_id": event["rule_id"], "rule_level": event["details"].get("rule_level"), "event_type": event["event_type"]})
            event_counts = collections.Counter()
            for item in types:
                event_counts[item["event_type"]] += item["count"]
            available = any(row["available"] for row in sources)
            return {"available": available, "notice": "" if available else "No configured telemetry source is readable.",
                    "events": count, "dns": event_counts["dns"], "alert_count": event_counts["alert"], "alerts": alerts,
                    "invalid": sum(row["invalid"] for row in sources), "truncated": False, "updated": last,
                    "stale": bool(last and time.time() - dt.datetime.fromisoformat(last).timestamp() > 300),
                    "sources": sources, "coverage": coverage, "event_types": types}

    def evidence(self, max_alerts=20, max_items=20):
        """Whole-ledger aggregates plus explicitly bounded high-priority examples."""
        with self.lock:
            snapshot = self.snapshot(alert_limit=0)
            groups = {}
            for key in ("domain", "rule_id", "source_ip"):
                groups[key] = [{"value": row[0], "count": row[1]} for row in self.db.execute("SELECT " + key + ",COUNT(*) FROM events WHERE " + key + "<>'' GROUP BY " + key + " ORDER BY COUNT(*) DESC LIMIT ?", (max(1, min(int(max_items), 100)),))]
            alerts = [json.loads(row[0]) for row in self.db.execute("SELECT payload FROM events WHERE event_type='alert' ORDER BY severity,timestamp DESC LIMIT ?", (max(0, min(int(max_alerts), 200)),))]
            return {"coverage": snapshot["coverage"], "sources": snapshot["sources"], "event_types": snapshot["event_types"],
                    "top_domains": groups["domain"], "top_rules": groups["rule_id"], "top_source_ips": groups["source_ip"],
                    "alert_examples": alerts, "alert_examples_limited": snapshot["alert_count"] > len(alerts)}

    def iter_events(self, since=None, until=None):
        """Stream one consistent SQLite read snapshot ordered by event time.

        Close or fully consume the iterator promptly so WAL checkpointing is not
        held open. No memory-wide event list is created by this method.
        """
        connection = self.read_snapshot_connection or sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=10)
        try:
            connection.execute("PRAGMA query_only=ON")
            conditions, parameters = [], []
            for value, operator in ((since, ">="), (until, "<=")):
                if value is not None:
                    stamp = _date(value)
                    if stamp is None:
                        raise ValueError("Report boundaries must include timezone")
                    conditions.append("timestamp" + operator + "?")
                    parameters.append(stamp)
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            for row in connection.execute("SELECT payload FROM events" + where + " ORDER BY timestamp,id", parameters):
                yield json.loads(row[0])
        finally:
            if not self.read_snapshot_connection:
                connection.close()

    def iter_original_events(self):
        connection = self.read_snapshot_connection or sqlite3.connect(self.path.as_uri()+"?mode=ro",uri=True,timeout=10)
        try:
            for row in connection.execute("SELECT o.id,o.stream,o.record FROM original_events o JOIN events e ON e.id=o.id ORDER BY e.timestamp,e.id"):
                yield {"id":row[0],"stream":row[1],"record":json.loads(row[2])}
        finally:
            if not self.read_snapshot_connection:
                connection.close()
