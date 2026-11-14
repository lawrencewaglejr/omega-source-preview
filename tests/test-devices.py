#!/usr/bin/env python3
"""Fixture-only checks: no network scans, services, or external dependencies."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("omega_devices", ROOT / "dashboard/devices.py")
devices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(devices)

MAC_A = "02:11:22:33:44:55"
MAC_B = "02:11:22:33:44:66"


class DeviceDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.leases = self.root / "dnsmasq.leases"
        self.state = self.root / "devices.json"
        self.mapping = self.root / "devices.csv"

    def tearDown(self):
        self.directory.cleanup()

    def source(self, rows=None):
        if rows is None:
            rows = [(MAC_A, "192.168.50.12", "work-laptop")]
        self.leases.write_text("".join(f"0 {mac} {ip} {hostname} *\n" for mac, ip, hostname in rows))

    def service(self, mapping=False):
        return devices.DeviceDiscovery(self.leases, self.state, self.mapping if mapping else None)

    def test_dashboard_snapshot_does_not_wait_for_uncommitted_device_write(self):
        self.source()
        service = self.service()
        saved = service.poll()
        self.source([(MAC_A, '192.168.50.12', 'work-laptop'), (MAC_B, '192.168.50.24', 'example-tablet')])
        writing, release, returned = threading.Event(), threading.Event(), threading.Event()
        snapshots = []
        save = service._save
        def delayed_save(state):
            writing.set()
            if not release.wait(5):
                raise OSError('test write timed out')
            save(state)
        def read():
            snapshots.append(service.snapshot())
            returned.set()
        with patch.object(service, '_save', side_effect=delayed_save):
            writer = threading.Thread(target=service.poll)
            writer.start()
            try:
                self.assertTrue(writing.wait(2))
                reader = threading.Thread(target=read)
                reader.start()
                self.assertTrue(returned.wait(1), 'Snapshot blocked behind a device-state write')
                self.assertTrue(snapshots[0]['refreshing'])
                self.assertEqual(snapshots[0]['devices'], saved['devices'])
                self.assertEqual(snapshots[0]['events'], [])
                # A reader cannot mutate the published view for another request.
                snapshots[0]['devices'].clear()
                self.assertEqual(len(service.snapshot()['devices']), 1)
            finally:
                release.set()
                writer.join(3)
                if 'reader' in locals():
                    reader.join(3)
        current = service.snapshot()
        self.assertFalse(current['refreshing'])
        self.assertEqual(len(current['devices']), 2)
        self.assertEqual(current['unread_count'], 1)

    def test_silent_baseline_then_one_persistent_event(self):
        self.source()
        service = self.service()
        first = service.poll()
        self.assertTrue(first["available"])
        self.assertTrue(first["baseline_established"])
        self.assertEqual(first["events"], [])
        self.source([(MAC_A, "192.168.50.12", "work-laptop"), (MAC_B.upper(), "192.168.50.24", "family-tablet")])
        second = service.poll()
        self.assertEqual(second["unread_count"], 1)
        self.assertEqual(second["events"][0]["device_id"], MAC_B)
        self.assertEqual(second["events"][0]["hostname"], "family-tablet")
        for _ in range(3):
            self.assertEqual(len(service.poll()["events"]), 1)
        restarted = self.service()
        self.assertEqual(restarted.poll()["events"], second["events"])
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)

    def test_dhcp_address_and_hostname_change_keeps_identity(self):
        self.source()
        service = self.service()
        baseline = service.poll()["devices"][0]
        self.source([(MAC_A, "192.168.50.99", "renamed-host")])
        current = service.poll()
        self.assertEqual(len(current["devices"]), 1)
        self.assertEqual(current["devices"][0]["first_seen"], baseline["first_seen"])
        self.assertEqual(current["devices"][0]["ip"], "192.168.50.99")
        self.assertEqual(current["devices"][0]["hostname"], "renamed-host")
        self.assertEqual(current["events"], [])

    def test_absent_device_is_retained_without_offline_claim(self):
        self.source()
        service = self.service()
        service.poll()
        self.source([])
        current = service.poll()
        self.assertEqual(len(current["devices"]), 1)
        self.assertFalse(current["devices"][0]["observed_in_latest_lease"])
        self.assertNotIn("online", current["devices"][0])
        self.assertNotIn("offline", current["devices"][0])
        self.source()
        self.assertEqual(service.poll()["events"], [])

    def test_empty_successful_baseline_can_detect_first_arrival(self):
        self.source([])
        service = self.service()
        self.assertTrue(service.poll()["baseline_established"])
        self.source()
        self.assertEqual(service.poll()["unread_count"], 1)

    def test_unavailable_source_never_establishes_baseline(self):
        service = self.service()
        unavailable = service.poll()
        self.assertFalse(unavailable["available"])
        self.assertFalse(unavailable["baseline_established"])
        self.assertFalse(self.state.exists())
        self.source()
        self.assertEqual(service.poll()["events"], [])
        self.leases.unlink()
        stale = service.poll()
        self.assertFalse(stale["available"])
        self.assertEqual(len(stale["devices"]), 1)
        self.assertIn("stale", stale["notice"])

    def test_invalid_hostname_is_not_guessed_or_executed(self):
        for hostname in ("*", "<script>alert(1)</script>", "bad_host", "-hostname", "a" * 254):
            self.source([(MAC_A, "192.168.50.12", hostname)])
            result = self.service().poll()
            self.assertTrue(result["available"])
            self.assertEqual(result["devices"][0]["hostname"], "")
            self.assertEqual(result["devices"][0]["display_name"], "Unnamed device")
        self.source([(MAC_A, "192.168.50.12", "Laptop.Example.")])
        result = self.service().poll()["devices"][0]
        self.assertEqual(result["hostname"], "Laptop.Example")
        self.assertEqual(result["device_type"], "Unknown")

    def test_mapping_matches_mac_not_reassigned_ip(self):
        self.source()
        self.mapping.write_text(f"ip,mac,hostname,vendor,owner,role,trust_level,notes\n192.168.50.200,{MAC_A},Office computer,Example,Pat,Laptop,trusted,Curated\n192.168.50.12,{MAC_B},Unrelated tablet,Example,Sam,Tablet,trusted,Other MAC\n")
        result = self.service(mapping=True).poll()["devices"][0]
        self.assertEqual(result["display_name"], "Office computer")
        self.assertEqual(result["device_type"], "Laptop")
        self.assertEqual(result["hostname"], "work-laptop")
        self.assertEqual(result["ip"], "192.168.50.12")

    def test_missing_mapping_falls_back_with_notice(self):
        self.source()
        result = self.service(mapping=True).poll()
        self.assertTrue(result["available"])
        self.assertIn("labels are unavailable", result["notice"])
        self.assertEqual(result["devices"][0]["display_name"], "work-laptop")

    def test_malformed_source_does_not_create_partial_baseline(self):
        self.source()
        with self.leases.open("a") as source:
            source.write("partially-written-lease")
        result = self.service().poll()
        self.assertFalse(result["available"])
        self.assertFalse(result["baseline_established"])
        self.assertEqual(result["invalid_records"], 1)
        self.assertEqual(result["devices"], [])

    def test_duplicate_mac_is_one_identity(self):
        self.leases.write_text(f"253402300798 {MAC_A} 192.168.50.12 first-host *\n253402300799 {MAC_A.upper()} 192.168.50.13 second-host *\n")
        result = self.service().poll()
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(result["devices"][0]["hostname"], "second-host")
        self.assertTrue(result["devices"][0]["lease_active"])

    def test_expired_unknown_lease_does_not_notify_until_renewed(self):
        self.source([])
        service = self.service()
        service.poll()
        self.leases.write_text(f"100 {MAC_A} 192.168.50.12 old-host *\n")
        expired = service.poll()
        self.assertEqual(expired["devices"], [])
        self.assertEqual(expired["events"], [])
        self.source()
        self.assertEqual(service.poll()["unread_count"], 1)
        self.leases.write_text(f"100 {MAC_A} 192.168.50.12 old-host *\n")
        known = service.poll()
        self.assertEqual(known["unread_count"], 1)
        self.assertFalse(known["devices"][0]["lease_active"])

    def test_infinite_lease_takes_precedence_over_expired_duplicate(self):
        self.leases.write_text(f"0 {MAC_A} 192.168.50.12 current-host *\n200 {MAC_A} 192.168.50.13 old-host *\n")
        result = self.service().poll()
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(result["devices"][0]["hostname"], "current-host")
        self.assertTrue(result["devices"][0]["lease_active"])

    def test_rejects_non_unicast_identity_and_invalid_address(self):
        for mac, address in (("00:00:00:00:00:00", "192.168.50.1"), ("ff:ff:ff:ff:ff:ff", "192.168.50.1"), ("01:11:22:33:44:55", "192.168.50.1"), (MAC_A, "not-an-ip"), (MAC_A, "127.0.0.1")):
            self.source([(mac, address, "host")])
            self.assertFalse(self.service().poll()["available"])

    def test_lease_symlink_fifo_and_oversize_fail_without_hang(self):
        target = self.root / "target"
        target.write_text("")
        self.leases.symlink_to(target)
        self.assertFalse(self.service().poll()["available"])
        self.leases.unlink()
        os.mkfifo(self.leases)
        self.assertFalse(self.service().poll()["available"])
        self.leases.unlink()
        self.source()
        with patch.object(devices, "MAX_SOURCE_BYTES", 10):
            self.assertFalse(self.service().poll()["available"])

    def test_symlink_parent_is_rejected(self):
        self.source()
        parent = self.root / "alias"
        parent.symlink_to(self.root, target_is_directory=True)
        service = devices.DeviceDiscovery(parent / self.leases.name, self.state)
        self.assertFalse(service.poll()["available"])

    def test_corrupt_state_fails_closed_and_is_not_overwritten(self):
        self.source()
        for invalid in ("{broken", "[]", '{"version":1}', '{"version":true}'):
            self.state.write_text(invalid)
            self.state.chmod(0o600)
            service = self.service()
            result = service.poll()
            self.assertFalse(result["available"])
            self.assertEqual(result["events"], [])
            self.assertIn("stopped", result["notice"])
            self.assertEqual(self.state.read_text(), invalid)

    def test_unsafe_state_file_and_directory_are_rejected(self):
        self.source()
        baseline = self.service().poll()
        self.assertTrue(baseline["available"])
        before = self.state.read_bytes()
        self.state.chmod(0o644)
        self.assertFalse(self.service().poll()["available"])
        self.assertEqual(self.state.read_bytes(), before)
        self.state.chmod(0o600)
        self.root.chmod(0o755)
        self.assertFalse(self.service().poll()["available"])
        self.root.chmod(0o700)
        target = self.root / "state-target"
        self.state.rename(target)
        self.state.symlink_to(target)
        self.assertFalse(self.service().poll()["available"])
        self.assertEqual(target.read_bytes(), before)

    def test_save_failure_does_not_publish_new_events(self):
        self.source([])
        service = self.service()
        service.poll()
        self.source()
        with patch.object(service, "_save", side_effect=OSError("disk unavailable")):
            result = service.poll()
        self.assertFalse(result["available"])
        self.assertEqual(result["events"], [])
        self.assertEqual(result["devices"], [])
        self.assertFalse(service.poll()["available"])

    def test_acknowledgement_is_durable_and_unknown_id_is_rejected(self):
        self.source([])
        service = self.service()
        service.poll()
        self.source()
        result = service.poll()
        self.assertFalse(service.acknowledge("missing-event"))
        self.assertTrue(service.acknowledge(result["events"][0]["id"]))
        self.assertEqual(self.service().poll()["unread_count"], 0)
        self.assertTrue(service.acknowledge())

    def test_labels_persist_and_preserve_reported_hostname(self):
        self.source()
        service = self.service()
        service.poll()
        self.assertTrue(service.label(MAC_A, "  Pat's tablet  ", "Tablet"))
        current = self.service().poll()["devices"][0]
        self.assertEqual(current["display_name"], "Pat's tablet")
        self.assertEqual(current["device_type"], "Tablet")
        self.assertEqual(current["hostname"], "work-laptop")
        self.source([(MAC_A, "192.168.50.99", "new-dhcp-hostname")])
        current = self.service().poll()["devices"][0]
        self.assertEqual(current["display_name"], "Pat's tablet")
        self.assertEqual(current["hostname"], "new-dhcp-hostname")

    def test_invalid_labels_do_not_write(self):
        self.source()
        service = self.service()
        service.poll()
        for name, kind in (("", "Tablet"), ("a" * 81, "Tablet"), ("with\nnewline", "Tablet"), ("name", "Unrecognized"), ([], "Tablet")):
            with self.assertRaises(ValueError):
                service.label(MAC_A, name, kind)
        self.assertFalse(service.label(MAC_B, "Other", "Phone"))

    def test_capacity_retains_identity_instead_of_rediscovering(self):
        self.source()
        with patch.object(devices, "MAX_DEVICES", 1):
            service = self.service()
            service.poll()
            self.source([(MAC_B, "192.168.50.24", "new-tablet")])
            result = service.poll()
            self.assertEqual(result["events"], [])
            self.assertEqual(result["devices"][0]["id"], MAC_A)
            self.assertIn("history is full", result["notice"])
            self.source()
            self.assertEqual(service.poll()["events"], [])

    def test_event_capacity_is_bounded_and_does_not_repeat(self):
        self.source([])
        service = self.service()
        service.poll()
        with patch.object(devices, "MAX_EVENTS", 2):
            for index in range(3):
                self.source([(f"02:00:00:00:00:{index:02x}", f"192.168.50.{index + 2}", f"host-{index}")])
                service.poll()
            result = service.poll()
            self.assertEqual(len(result["events"]), 2)
            self.assertEqual(len(result["devices"]), 3)

    def test_snapshot_is_not_mutable_internal_state(self):
        self.source()
        service = self.service()
        snapshot = service.poll()
        snapshot["devices"][0]["display_name"] = "tampered"
        self.assertEqual(service.snapshot()["devices"][0]["display_name"], "work-laptop")

    def test_unconfigured_and_demo_are_explicit(self):
        self.assertFalse(devices.DeviceDiscovery().poll()["available"])
        demo = devices.DeviceDiscovery(demo=True)
        sample = demo.poll()
        self.assertTrue(sample["demo"])
        self.assertEqual(sample["source"], "sample_data")
        self.assertIn("Sample", sample["notice"])
        self.assertEqual(sample["unread_count"], 1)
        self.assertTrue({"Laptop", "Tablet"}.issubset({row["device_type"] for row in sample["devices"]}))
        self.assertTrue(demo.label(sample["devices"][0]["id"], "Sample rename", "Phone"))
        self.assertTrue(demo.acknowledge())
        self.assertEqual(demo.snapshot()["unread_count"], 0)
        self.assertFalse(self.state.exists())

    def database(self):
        path = self.root / "pihole-FTL.db"
        connection = sqlite3.connect(path)
        connection.executescript("CREATE TABLE network (id INTEGER PRIMARY KEY, hwaddr TEXT UNIQUE NOT NULL, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, macVendor TEXT); CREATE TABLE network_addresses (network_id INTEGER NOT NULL, ip TEXT UNIQUE NOT NULL, lastSeen INTEGER NOT NULL, name TEXT);")
        connection.close()
        return path

    def database_device(self, path, number=1, mac=MAC_A, address="192.168.50.12", hostname="pihole-host", age=0):
        epoch = int(time.time()) - age
        with sqlite3.connect(path) as connection:
            connection.execute("INSERT INTO network VALUES (?, ?, ?, ?, ?)", (number, mac, epoch - 100, epoch, "Example vendor"))
            connection.execute("INSERT INTO network_addresses VALUES (?, ?, ?, ?)", (number, address, epoch, hostname))

    def database_service(self, path):
        return devices.DeviceDiscovery(state_file=self.state, pihole_database=path)

    def test_authorized_scan_adds_confirmed_names_and_preserves_custom_labels(self):
        path=self.database()
        self.database_device(path,hostname='')
        scan=self.root/'scan.json'
        when=(devices.dt.datetime.now(devices.dt.timezone.utc)-devices.dt.timedelta(hours=1)).isoformat()
        scan.write_text(json.dumps({'collected_at':when,'devices':[
            {'mac':MAC_A,'ip':'192.168.50.12','hostname':'laptop','device_type':'Laptop','hostname_source':'local host identity'},
            {'mac':MAC_B,'ip':'192.168.50.39','hostname':'omega','device_type':'Appliance','hostname_source':'Pi hostname'}]}))
        service=devices.DeviceDiscovery(state_file=self.state,pihole_database=path,scan_file=scan)
        result=service.poll()
        self.assertEqual(len(result['devices']),2)
        self.assertEqual(result['unread_count'],0)
        pi=next(d for d in result['devices'] if d['mac']==MAC_B)
        self.assertEqual(pi['observation_source'],'network_scan')
        self.assertIsNone(pi['lease_active'])
        self.assertTrue(service.label(MAC_A,'My workstation','Desktop'))
        row=next(d for d in service.poll()['devices'] if d['mac']==MAC_A)
        self.assertEqual(row['hostname'],'laptop')
        self.assertEqual(row['display_name'],'My workstation')
        self.assertEqual(row['device_type'],'Desktop')

    def test_pihole_baseline_uses_source_hostname_and_observation_time(self):
        path = self.database()
        self.database_device(path, age=86400)
        before = path.read_bytes()
        result = self.database_service(path).poll()
        self.assertTrue(result["available"])
        self.assertEqual(result["source"], "pihole_network")
        device = result["devices"][0]
        self.assertEqual(device["hostname"], "pihole-host")
        self.assertEqual(device["vendor"], "Example vendor")
        self.assertEqual(device["device_type"], "Unknown")
        self.assertTrue(device["in_current_source"])
        self.assertFalse(device["observed_in_latest_lease"])
        self.assertIsNone(device["lease_active"])
        self.assertFalse(device["recently_observed"])
        self.assertNotEqual(device["last_seen"], result["updated"])
        self.assertEqual(result["events"], [])
        self.assertEqual(path.read_bytes(), before)

    def test_pihole_new_recent_mac_notifies_once_and_persists(self):
        path = self.database()
        service = self.database_service(path)
        self.assertTrue(service.poll()["baseline_established"])
        self.database_device(path)
        result = service.poll()
        self.assertEqual(result["unread_count"], 1)
        self.assertTrue(result["devices"][0]["recently_observed"])
        self.assertEqual(result["events"][0]["hostname"], "pihole-host")
        self.assertEqual(service.poll()["unread_count"], 1)
        restarted = self.database_service(path)
        self.assertEqual(restarted.poll()["events"], result["events"])
        self.assertTrue(restarted.acknowledge())
        self.assertEqual(self.database_service(path).poll()["unread_count"], 0)

    def test_pihole_late_old_records_are_not_arrival_notifications(self):
        path = self.database()
        service = self.database_service(path)
        service.poll()
        self.database_device(path, age=86400)
        result = service.poll()
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(result["events"], [])
        # Even recent observations from before the baseline are historical.
        self.database_device(path, 2, MAC_B, "192.168.50.24", age=30)
        self.assertEqual(service.poll()["events"], [])

    def test_pihole_ipv4_ipv6_addresses_share_mac_identity_and_labels(self):
        path = self.database()
        self.database_device(path, age=10)
        service = self.database_service(path)
        service.poll()
        self.assertTrue(service.label(MAC_A, "Family tablet", "Tablet"))
        with sqlite3.connect(path) as connection:
            connection.execute("INSERT INTO network_addresses VALUES (?, ?, ?, ?)", (1, "2001:db8::24", int(time.time()), "tablet-v6"))
        current = self.database_service(path).poll()
        self.assertEqual(len(current["devices"]), 1)
        self.assertEqual(current["devices"][0]["ip"], "2001:db8::24")
        self.assertEqual(current["devices"][0]["hostname"], "tablet-v6")
        self.assertEqual(current["devices"][0]["display_name"], "Family tablet")
        self.assertEqual(current["devices"][0]["device_type"], "Tablet")
        self.assertEqual(current["events"], [])

    def test_pihole_skips_mock_macs_and_bad_timestamps(self):
        path = self.database()
        self.database_device(path)
        self.database_device(path, 2, "ip-192.168.50.24", "192.168.50.24")
        self.database_device(path, 3, MAC_B, "192.168.50.25", age=-86400)
        current = self.database_service(path).poll()
        self.assertTrue(current["available"])
        self.assertEqual(len(current["devices"]), 1)
        self.assertEqual(current["skipped_records"], 2)
        self.assertEqual(current["events"], [])

    def test_pihole_only_unusable_rows_do_not_establish_baseline(self):
        path = self.database()
        self.database_device(path, mac="ip-192.168.50.12")
        current = self.database_service(path).poll()
        self.assertFalse(current["available"])
        self.assertFalse(current["baseline_established"])
        self.assertFalse(self.state.exists())

    def test_pihole_missing_schema_and_bounded_rows_fail_closed(self):
        missing = self.root / "missing.db"
        self.assertFalse(self.database_service(missing).poll()["available"])
        self.assertFalse(missing.exists())
        path = self.database()
        self.database_device(path)
        self.database_device(path, 2, MAC_B, "192.168.50.24")
        with patch.object(devices, "MAX_DATABASE_ROWS", 1):
            self.assertFalse(self.database_service(path).poll()["available"])
        with sqlite3.connect(path) as connection:
            connection.execute("ALTER TABLE network_addresses RENAME COLUMN name TO missing_name")
        self.assertFalse(self.database_service(path).poll()["available"])
        self.assertFalse(self.state.exists())

    def test_pihole_rejects_database_and_companion_symlinks_and_fifo(self):
        path = self.database()
        alias = self.root / "alias.db"
        alias.symlink_to(path)
        self.assertFalse(self.database_service(alias).poll()["available"])
        fifo = self.root / "fifo.db"
        os.mkfifo(fifo)
        self.assertFalse(self.database_service(fifo).poll()["available"])
        companion = self.root / "pihole-FTL.db-wal"
        companion.symlink_to(path)
        self.assertFalse(self.database_service(path).poll()["available"])

    def test_pihole_wal_reads_recent_commits_without_changing_database(self):
        path = self.database()
        writer = sqlite3.connect(path)
        try:
            self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            writer.execute("SELECT * FROM network").fetchall()
            service = self.database_service(path)
            service.poll()
            epoch = int(time.time())
            writer.execute("INSERT INTO network VALUES (?, ?, ?, ?, ?)", (1, MAC_A, epoch - 10, epoch, "Example"))
            writer.execute("INSERT INTO network_addresses VALUES (?, ?, ?, ?)", (1, "192.168.50.12", epoch, "wal-host"))
            writer.commit()
            database_before = path.read_bytes()
            wal = self.root / "pihole-FTL.db-wal"
            wal_before = wal.read_bytes()
            current = service.poll()
            self.assertTrue(current["available"])
            self.assertEqual(current["unread_count"], 1)
            self.assertEqual(current["devices"][0]["hostname"], "wal-host")
            self.assertEqual(path.read_bytes(), database_before)
            self.assertEqual(wal.read_bytes(), wal_before)
        finally:
            writer.close()

    def test_pihole_reader_does_not_create_missing_wal_companions(self):
        path = self.database()
        writer = sqlite3.connect(path)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.close()
        before = {entry.name for entry in self.root.iterdir()}
        current = self.database_service(path).poll()
        self.assertFalse(current["available"])
        self.assertEqual({entry.name for entry in self.root.iterdir()}, before)

    def test_pihole_locked_database_returns_unavailable_quickly(self):
        path = self.database()
        locker = sqlite3.connect(path)
        try:
            locker.execute("BEGIN EXCLUSIVE")
            started = time.monotonic()
            current = self.database_service(path).poll()
            self.assertFalse(current["available"])
            self.assertLess(time.monotonic() - started, 2)
        finally:
            locker.rollback()
            locker.close()

    def test_changing_to_pihole_source_establishes_silent_baseline(self):
        self.source()
        self.service().poll()
        path = self.database()
        self.database_device(path, mac=MAC_B)
        current = self.database_service(path).poll()
        self.assertTrue(current["available"])
        self.assertEqual(len(current["devices"]), 2)
        self.assertEqual(current["events"], [])
        previous = next(row for row in current["devices"] if row["id"] == MAC_A)
        self.assertFalse(previous["in_current_source"])

    def test_legacy_state_migrates_without_losing_identity_or_labels(self):
        self.source()
        service = self.service()
        service.poll()
        service.label(MAC_A, "Legacy label", "Laptop")
        state = json.loads(self.state.read_text())
        state["version"] = 1
        state.pop("source")
        state.pop("baseline_at")
        for device in state["devices"].values():
            device.pop("observation_source")
            device.pop("in_current_source")
        self.state.write_text(json.dumps(state))
        current = self.service().poll()
        self.assertTrue(current["available"])
        self.assertEqual(current["devices"][0]["display_name"], "Legacy label")
        self.assertEqual(current["events"], [])
        self.assertEqual(json.loads(self.state.read_text())["version"], 2)

    def test_sources_are_mutually_exclusive(self):
        with self.assertRaises(ValueError):
            devices.DeviceDiscovery(self.leases, self.state, pihole_database=self.root / "pihole-FTL.db")


if __name__ == "__main__":
    unittest.main()
