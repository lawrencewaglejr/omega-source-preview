#!/usr/bin/env python3
"""Durable ingestion, real schema joins and honest coverage regression tests."""
import datetime as dt
import gzip
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dashboard"))
from telemetry_store import MAX_RECORD_BYTES, TelemetryStore


def stamp(seconds=0):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()


def suricata(kind="dns", **extra):
    return {"timestamp": stamp(), "event_type": kind, "src_ip": "192.168.50.12", "dest_ip": "1.1.1.1", **extra}


def line(event):
    return json.dumps(event).encode() + b"\n"


class TelemetryTests(unittest.TestCase):
    def test_from_now_skips_old_history_and_resumes_across_restart_rotation(self):
        old=suricata(flow_id=1,timestamp=stamp(-600))
        self.eve.write_bytes(line(old))
        with gzip.open(self.root/'eve.json.9.gz','wb') as output: output.write(line(old))
        store=self.store(from_now=True)
        first=store.poll()
        self.assertEqual(first['events'],0)
        self.assertTrue(first['coverage']['caught_up'])
        started=first['coverage']['collection_started']
        with self.eve.open('ab') as output: output.write(line(suricata(flow_id=2)))
        self.assertEqual(store.poll()['events'],1)
        store.close()
        with self.eve.open('ab') as output: output.write(line(suricata(flow_id=3)))
        self.eve.rename(self.root/'eve.json.1')
        self.eve.write_bytes(line(suricata(flow_id=4)))
        store=self.store(from_now=True)
        result=store.poll()
        self.assertEqual(result['events'],3)
        self.assertEqual(result['coverage']['collection_started'],started)
        self.assertEqual({int(e['record']['flow_id']) for e in store.iter_original_events()},{2,3,4})

    def test_from_now_pihole_baselines_existing_rows(self):
        pihole=self.make_pihole()
        store=self.store(from_now=True,pihole_database=pihole)
        self.assertEqual(store.poll()['events'],0)
        with sqlite3.connect(pihole) as writer:
            writer.execute('INSERT INTO query_storage(timestamp,type,status,domain,client) VALUES(?,1,1,1,1)',(dt.datetime.now(dt.timezone.utc).timestamp(),))
        result=store.poll()
        self.assertEqual(result['events'],1)
        self.assertTrue(result['sources'][3]['caught_up'])

    def test_from_now_refuses_to_repurpose_existing_history(self):
        self.eve.write_bytes(line(suricata()))
        store=self.store();store.poll();store.close()
        with self.assertRaisesRegex(ValueError,'new ledger'):
            self.store(from_now=True)

    def test_current_events_arrive_during_history_backfill(self):
        rows=[suricata(flow_id=n,extra='x'*400) for n in range(1200)]
        self.eve.write_bytes(b''.join(line(row) for row in rows))
        store=self.store()
        first=store.poll(max_bytes=128*1024)
        self.assertFalse(first['coverage']['caught_up'])
        self.assertIn('1199',{str(row['record']['flow_id']) for row in store.iter_original_events()})
        for _ in range(20):
            result=store.poll(max_bytes=128*1024)
            if result['coverage']['caught_up']:break
        self.assertEqual(result['events'],1200)
        self.assertTrue(result['coverage']['caught_up'])

    def test_stale_wazuh_mirror_does_not_claim_current_coverage(self):
        alerts=self.root/'alerts.json'; alerts.write_bytes(b'')
        heartbeat=self.root/'sync-status.json'
        heartbeat.write_text(json.dumps({'checked_at':stamp(-3600),'sources':{'alerts':{'ok':True}}}))
        store=self.store(wazuh_alerts_path=alerts,wazuh_sync_status=heartbeat)
        view=store.poll(); source=next(row for row in view['sources'] if row['id']=='wazuh_alerts')
        self.assertTrue(source['available'])
        self.assertFalse(source['sync_current'])
        self.assertFalse(view['coverage']['caught_up'])
        self.assertIn('sync is stale',source['notice'])
        heartbeat.write_text(json.dumps({'checked_at':stamp(),'sources':{'alerts':{'ok':True}}}))
        self.assertTrue(next(row for row in store.snapshot()['sources'] if row['id']=='wazuh_alerts')['sync_current'])

    def test_gzip_history_is_incremental_and_restart_safe(self):
        records = [suricata(flow_id=n) for n in range(30)]
        with gzip.open(self.root / 'eve.json.1.gz','wb') as output:
            output.write(b''.join(line(row) for row in records))
        store = self.store()
        first = store.poll(max_bytes=300)
        self.assertFalse(first['coverage']['caught_up'])
        store.close()
        store = self.store()
        for _ in range(100):
            result = store.poll(max_bytes=300)
            if result['coverage']['caught_up']: break
        self.assertEqual(result['events'],30)
        self.assertTrue(result['coverage']['caught_up'])
        self.assertEqual(store.poll()['events'],30)

    def test_nested_wazuh_archives_are_imported(self):
        folder=self.root/'alerts'; nested=folder/'2026'/'Sep'; nested.mkdir(parents=True)
        current=folder/'alerts.json'; current.write_bytes(b'')
        with gzip.open(nested/'ossec-alerts-01.json.gz','wb') as output:
            output.write(line({'timestamp':stamp(),'id':'manager-one','agent':{'id':'001','name':'pi'},'rule':{'id':'100','level':10,'description':'Test alert'}}))
        store=self.store(wazuh_alerts_path=current)
        for _ in range(5): result=store.poll()
        self.assertEqual(result['alert_count'],1)
        self.assertEqual(next(row for row in result['sources'] if row['id']=='wazuh_alerts')['events'],1)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.eve = self.root / "eve.json"
        self.eve.write_bytes(b"")
        self.state = self.root / "telemetry.sqlite3"
        self.opened = []

    def tearDown(self):
        for store in self.opened:
            try:
                store.close()
            except sqlite3.ProgrammingError:
                pass
        self.temp.cleanup()

    def store(self, **kwargs):
        result = TelemetryStore(self.state, eve_path=self.eve, **kwargs)
        self.opened.append(result)
        return result

    def test_incremental_full_file_not_tail(self):
        self.eve.write_bytes(b"".join(line(suricata(flow_id=index)) for index in range(100)))
        store = self.store()
        snapshot = store.poll(max_bytes=300)
        self.assertFalse(snapshot["coverage"]["caught_up"])
        self.assertGreater(snapshot["sources"][0]["backlog_bytes"], 0)
        for _ in range(100):
            snapshot = store.poll(max_bytes=300)
            if snapshot["coverage"]["caught_up"]:
                break
        self.assertEqual(snapshot["events"], 100)
        self.assertEqual(snapshot["coverage"]["total_ingested"], 100)
        self.assertEqual(len(list(store.iter_events())), 100)

    def test_restart_preserves_partial_line_and_no_duplicate(self):
        first, second = line(suricata(flow_id=1)), line(suricata(flow_id=2))
        self.eve.write_bytes(first + second[:45])
        store = self.store()
        self.assertEqual(store.poll()["events"], 1)
        self.assertEqual(store.snapshot()["sources"][0]["pending_records"], 1)
        store.close()
        self.eve.write_bytes(first + second)
        resumed = self.store()
        snapshot = resumed.poll()
        self.assertEqual(snapshot["events"], 2)
        self.assertEqual(snapshot["sources"][0]["pending_records"], 0)
        self.assertEqual(resumed.poll()["events"], 2)

    def test_rotation_continues_unread_old_inode(self):
        original = b"".join(line(suricata(flow_id=index)) for index in range(10))
        self.eve.write_bytes(original)
        store = self.store()
        store.poll(max_bytes=100)
        self.eve.rename(self.root / "eve.json.1")
        self.eve.write_bytes(line(suricata(flow_id=999)))
        self.assertEqual(store.poll()["events"], 11)
        self.assertEqual(store.poll()["events"], 11)
        self.assertEqual(store.snapshot()["sources"][0]["rotated_files"], 1)

    def test_first_import_available_rotations(self):
        (self.root / "eve.json.1").write_bytes(line(suricata(flow_id=1)))
        (self.root / "eve.json.2").write_bytes(line(suricata(flow_id=2)))
        (self.root / "eve.json.3.gz").write_bytes(b"compressed placeholder")
        self.eve.write_bytes(line(suricata(flow_id=3)))
        snapshot = self.store().poll()
        self.assertEqual(snapshot["events"], 3)
        self.assertEqual(snapshot["sources"][0]["compressed_files_unread"], 1)
        self.assertIn("corrupt", snapshot["sources"][0]["notice"])

    def test_copytruncate_restarts_generation(self):
        self.eve.write_bytes(line(suricata(flow_id=123456789)))
        store = self.store()
        store.poll()
        self.eve.write_bytes(line(suricata(flow_id=1)))
        snapshot = store.poll()
        self.assertEqual(snapshot["events"], 2)
        self.assertEqual(snapshot["sources"][0]["resets"], 1)

    def test_malformed_and_oversized_line_does_not_skip_next(self):
        self.eve.write_bytes(b"not-json\n" + b"x" * (MAX_RECORD_BYTES + 100) + b"\n" + line(suricata()))
        store = self.store()
        snapshot = store.poll()
        self.assertEqual(snapshot["events"], 1)
        self.assertEqual(snapshot["invalid"], 2)
        self.assertEqual(store.poll()["invalid"], 2)

    def test_oversized_line_recovery_across_restart(self):
        self.eve.write_bytes(b"x" * (MAX_RECORD_BYTES + 100))
        store = self.store()
        self.assertEqual(store.poll()["invalid"], 0)
        store.close()
        with self.eve.open("ab") as file:
            file.write(b"\n" + line(suricata()))
        resumed = self.store()
        snapshot = resumed.poll()
        self.assertEqual(snapshot["invalid"], 1)
        self.assertEqual(snapshot["events"], 1)

    def test_age_and_capacity_retention_are_reported(self):
        events = [suricata(flow_id=index) for index in range(5)]
        events.append(suricata(timestamp=stamp(-40 * 86400)))
        self.eve.write_bytes(b"".join(line(event) for event in events))
        snapshot = self.store(max_events=3).poll()
        self.assertEqual(snapshot["events"], 3)
        self.assertEqual(snapshot["coverage"]["pruned_events"], 3)
        self.assertEqual(snapshot["coverage"]["total_ingested"], 6)

    def test_wazuh_streams_normalize_and_deduplicate(self):
        alerts, archives = self.root / "alerts.json", self.root / "archives.json"
        event = {"id": "179.23", "timestamp": stamp(), "rule": {"id": "5710", "level": 10, "description": "SSH authentication failure", "groups": ["authentication_failed"]}, "agent": {"id": "001", "name": "laptop", "ip": "192.168.50.12"}, "data": {"srcip": "192.168.50.88"}, "full_log": "private raw text"}
        alerts.write_bytes(line(event))
        archives.write_bytes(line(event) + line({"timestamp": stamp(), "agent": {"id": "001", "name": "laptop"}, "decoder": {"name": "syslog"}}))
        store = self.store(wazuh_alerts_path=alerts, wazuh_archives_path=archives)
        snapshot = store.poll()
        self.assertEqual(snapshot["events"], 2)
        self.assertEqual(snapshot["alert_count"], 1)
        self.assertEqual(snapshot["sources"][2]["duplicate_records"], 1)
        alert = snapshot["alerts"][0]
        self.assertEqual((alert["sensor"], alert["severity"], alert["rule_level"]), ("wazuh", 2, 10))
        normalized = next(event for event in store.iter_events() if event["event_type"] == "alert")
        self.assertEqual(normalized["details"]["agent_ip"], "192.168.50.12")
        self.assertNotIn("private raw text", json.dumps(normalized))

    def test_agent_diagnostic_file_not_accepted_as_alert_json(self):
        alerts = self.root / "ossec.log"
        alerts.write_bytes(b"2026/09/11 wazuh-agentd INFO Connected to server\n")
        snapshot = self.store(wazuh_alerts_path=alerts).poll()
        self.assertEqual(snapshot["alert_count"], 0)
        self.assertEqual(snapshot["sources"][1]["invalid"], 1)
        self.assertFalse(snapshot["sources"][2]["configured"])

    def make_pihole(self):
        path = self.root / "pihole-FTL.db"
        db = sqlite3.connect(path)
        db.executescript("""CREATE TABLE query_storage(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp INTEGER,type INTEGER,status INTEGER,domain INTEGER,client INTEGER,forward INTEGER,additional_info INTEGER,reply_type INTEGER,reply_time REAL,dnssec INTEGER,list_id INTEGER,ede INTEGER);
            CREATE TABLE domain_by_id(id INTEGER PRIMARY KEY,domain TEXT);
            CREATE TABLE client_by_id(id INTEGER PRIMARY KEY,ip TEXT,name TEXT);
            CREATE TABLE forward_by_id(id INTEGER PRIMARY KEY,forward TEXT);
            INSERT INTO domain_by_id VALUES(1,'example.com');
            INSERT INTO client_by_id VALUES(1,'192.168.50.12','laptop');
            INSERT INTO forward_by_id VALUES(1,'1.1.1.1#53');""")
        now = int(dt.datetime.now(dt.timezone.utc).timestamp())
        db.executemany("INSERT INTO query_storage(timestamp,type,status,domain,client,forward,reply_type,reply_time) VALUES(?,1,2,1,1,1,4,0.01)", [(now,)] * 5)
        db.commit()
        db.close()
        return path

    def test_pihole_real_integer_schema_history_and_restart(self):
        pihole = self.make_pihole()
        original = pihole.read_bytes()
        store = self.store(pihole_database=pihole)
        snapshot = store.poll(max_rows=2)
        self.assertEqual(snapshot["sources"][3]["backlog_rows"], 3)
        self.assertFalse(snapshot["coverage"]["caught_up"])
        store.close()
        store = self.store(pihole_database=pihole)
        snapshot = store.poll(max_rows=10)
        self.assertEqual(snapshot["events"], 5)
        self.assertEqual(snapshot["dns"], 5)
        event = next(store.iter_events())
        self.assertEqual((event["source_ip"], event["hostname"], event["domain"]), ("192.168.50.12", "laptop", "example.com"))
        self.assertEqual(store.poll()["events"], 5)
        self.assertEqual(pihole.read_bytes(), original)

    def test_pihole_legacy_text_schema(self):
        path = self.root / "legacy.db"
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE queries(id INTEGER PRIMARY KEY,timestamp INTEGER,type INTEGER,status INTEGER,domain TEXT,client TEXT)")
        db.execute("INSERT INTO queries VALUES(1,?,1,1,'example.com','192.168.50.12')", (int(dt.datetime.now(dt.timezone.utc).timestamp()),))
        db.commit()
        db.close()
        store = self.store(pihole_database=path)
        self.assertEqual(store.poll()["events"], 1)
        self.assertEqual(next(store.iter_events())["domain"], "example.com")

    def test_readonly_wal_sees_uncheckpointed_records(self):
        pihole = self.make_pihole()
        writer = sqlite3.connect(pihole)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("INSERT INTO query_storage(timestamp,type,status,domain,client) VALUES(?,1,1,1,1)", (int(dt.datetime.now(dt.timezone.utc).timestamp()),))
        writer.commit()
        try:
            snapshot = self.store(pihole_database=pihole).poll()
            self.assertEqual(snapshot["sources"][3]["events"], 6)
        finally:
            writer.close()

    def test_missing_source_preserves_collected_evidence(self):
        self.eve.write_bytes(line(suricata()))
        store = self.store()
        store.poll()
        self.eve.unlink()
        snapshot = store.poll()
        self.assertEqual(snapshot["events"], 1)
        self.assertFalse(snapshot["sources"][0]["available"])
        self.assertFalse(snapshot["coverage"]["caught_up"])

    def test_state_permissions_and_corruption_fail_closed(self):
        self.state.write_text("broken sqlite state")
        self.state.chmod(0o600)
        with self.assertRaises(sqlite3.DatabaseError):
            self.store()
        self.assertEqual(self.state.read_text(), "broken sqlite state")
        self.state.unlink()
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            self.store()

    def test_symlink_source_is_skipped_and_reported(self):
        real = self.root / "elsewhere"
        real.write_bytes(line(suricata()))
        self.eve.unlink()
        self.eve.symlink_to(real)
        store = self.store()
        snapshot = store.poll()
        self.assertFalse(snapshot["available"])
        self.assertEqual(snapshot["events"], 0)

    def test_evidence_covers_full_retained_history_examples_bounded(self):
        self.eve.write_bytes(b"".join(line(suricata("alert", alert={"signature": "Test", "severity": 2, "signature_id": 123})) for _ in range(10)))
        store = self.store()
        store.poll()
        evidence = store.evidence(max_alerts=2)
        self.assertEqual(evidence["coverage"]["stored_events"], 10)
        self.assertEqual(evidence["top_rules"], [{"value": "123", "count": 10}])
        self.assertEqual(len(evidence["alert_examples"]), 2)
        self.assertTrue(evidence["alert_examples_limited"])

    def test_event_iterator_time_order_and_boundaries(self):
        events = [suricata(timestamp=stamp(index)) for index in (-1, -3, -2)]
        self.eve.write_bytes(b"".join(line(event) for event in events))
        store = self.store()
        store.poll()
        result = list(store.iter_events())
        self.assertEqual([event["timestamp"] for event in result], sorted(event["timestamp"] for event in events))
        self.assertEqual(len(list(store.iter_events(since=events[2]["timestamp"]))), 2)


if __name__ == "__main__":
    unittest.main()
