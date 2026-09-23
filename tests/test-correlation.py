#!/usr/bin/env python3
"""Evidence joins, complete export, and untrusted rendering regression tests."""
import csv
import datetime as dt
import io
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dashboard"))
from correlation import analyze_events, build_ai_evidence, format_ai_evidence, iter_csv_events, iter_html_report, iter_jsonl_events

BASE = dt.datetime(2026, 9, 11, 12, 0, tzinfo=dt.timezone.utc)


def event(number, source="suricata", seconds=0, ip="192.168.50.12", **fields):
    return {"id": f"event-{number}", "timestamp": (BASE + dt.timedelta(seconds=seconds)).isoformat(),
            "observed_at": BASE.isoformat(), "source": source, "stream": source,
            "event_type": "alert" if source != "pihole" else "dns", "severity": 2 if source != "pihole" else None,
            "title": f"Observed {source} event {number}", "source_ip": ip, "destination_ip": "8.8.8.8",
            "details": {}, **fields}


class CorrelationTests(unittest.TestCase):
    def test_relay_is_not_independent_evidence_or_sensor_traffic(self):
        original = event(1, details={"flow_id":123,"signature_id":456})
        relay = event(2,"wazuh",1,details={"origin":"suricata","agent_ip":"192.168.50.39","origin_timestamp":original["timestamp"],"flow_id":123,"signature_id":456})
        result = analyze_events([original,relay])
        self.assertEqual(result["correlations"],[])
        self.assertEqual(result["events_analyzed"],2)
        self.assertEqual(result["relayed_suricata_events"],1)
        sensor_dns = event(3,"pihole",2,ip="192.168.50.39")
        self.assertEqual(analyze_events([relay,sensor_dns])["correlations"],[])
        endpoint_dns = event(4,"pihole",2)
        self.assertTrue(analyze_events([original,relay,endpoint_dns])["correlations"])

    def test_all_records_counted_even_beyond_display_limits(self):
        rows = [event(i, ("suricata", "wazuh", "pihole")[i % 3], i) for i in range(2100)]
        result = analyze_events(iter(rows), max_candidates=3)
        self.assertEqual(result["events_analyzed"], 2100)
        self.assertEqual(result["source_counts"], {"pihole": 700, "suricata": 700, "wazuh": 700})
        self.assertEqual(result["event_types"], {"alert": 1400, "dns": 700})
        self.assertLessEqual(len(result["correlations"]), 3)
        self.assertGreater(result["candidate_windows"], 3)
        exported = list(iter_jsonl_events(iter(rows)))
        self.assertEqual(len(exported), 2100)
        self.assertEqual(json.loads(exported[-1])["id"], "event-2099")

    def test_cross_source_window_and_boundary_overlap(self):
        # A normal five-minute boundary splits these; the half-offset window joins them.
        rows = [event(1, "suricata", 299), event(2, "wazuh", 301), event(3, "pihole", 302)]
        result = analyze_events(rows)
        self.assertEqual(len(result["correlations"]), 1)
        group = result["correlations"][0]
        self.assertEqual(group["sources"], ["suricata", "wazuh", "pihole"])
        self.assertEqual(group["event_count"], 3)
        self.assertIn("not proof", group["summary"])
        self.assertEqual(set(group["event_ids"]), {"event-1", "event-2", "event-3"})
        self.assertEqual(group["id"], analyze_events(rows)["correlations"][0]["id"])

    def test_same_source_or_distant_time_is_not_cross_source(self):
        self.assertEqual(analyze_events([event(1), event(2, seconds=20)])["correlations"], [])
        self.assertEqual(analyze_events([event(1), event(2, "wazuh", 1000)])["correlations"], [])

    def test_shared_public_resolver_does_not_join_different_devices(self):
        rows = [event(1, ip="192.168.50.12"), event(2, "pihole", 1, ip="192.168.50.24")]
        self.assertEqual(analyze_events(rows)["correlations"], [])

    def test_endpoint_agent_ip_and_known_global_device_can_join(self):
        rows = [event(1, ip="192.168.50.12"), event(2, "wazuh", 1, ip="1.2.3.4", details={"agent_ip": "192.168.50.12"})]
        self.assertEqual(analyze_events(rows)["correlations"][0]["device"], "192.168.50.12")
        ip = "2001:4860:abcd::5"
        rows = [event(1, ip=ip), event(2, "pihole", 1, ip=ip)]
        self.assertEqual(analyze_events(rows)["correlations"], [])
        self.assertEqual(analyze_events(rows, known_ips=[ip])["correlations"][0]["device"], ip)

    def test_missing_naive_and_out_of_order_times_are_disclosed(self):
        rows = [event(1, timestamp=None), event(2, timestamp="2026-09-11T12:00:00"),
                event(3, seconds=30), event(4, "wazuh", 20)]
        result = analyze_events(rows)
        self.assertEqual(result["events_analyzed"], 4)
        self.assertEqual(result["without_timestamp"], 2)
        self.assertEqual(result["out_of_order"], 1)
        self.assertEqual(result["correlations"], [])
        self.assertTrue(any("out-of-order" in item for item in result["limitations"]))

    def test_candidate_pressure_preserves_all_aggregate_counts(self):
        rows = [event(1), event(2, "wazuh", 1, ip="192.168.50.24")]
        result = analyze_events(rows, max_active_windows=1)
        self.assertEqual(result["events_analyzed"], 2)
        self.assertGreater(result["window_associations_skipped"], 0)
        self.assertTrue(any("memory limit" in item for item in result["limitations"]))

    def test_ai_budget_covers_every_source_and_labels_excerpts(self):
        rows = [event(i, ("suricata", "wazuh", "pihole")[i % 3], i * 180, title="<untrusted event>" * 20) for i in range(300)]
        result = analyze_events(rows, sources=[{"name": "suricata", "available": True, "configured": True, "events": 100}, {"name": "wazuh", "available": False, "configured": True, "events": 100, "notice": "Source currently unreadable"}])
        original = json.dumps(result, sort_keys=True)
        evidence = build_ai_evidence(result, max_chars=5000)
        self.assertEqual(evidence["events_analyzed"], 300)
        self.assertEqual(sum(evidence["source_counts"].values()), 300)
        self.assertEqual({item["source"] for item in evidence["representative_events"]}, {"suricata", "wazuh", "pihole"})
        self.assertFalse(evidence["selection"]["raw_events_individually_analyzed"])
        self.assertLessEqual(len(json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))), 5000)
        self.assertIn("Source currently unreadable", json.dumps(evidence))
        self.assertEqual(json.dumps(result, sort_keys=True), original)

    def test_ai_candidate_selection_includes_available_third_source(self):
        rows = [event(1, seconds=0, severity=1), event(2, "wazuh", 1, severity=1),
                event(3, seconds=400, severity=1), event(4, "wazuh", 401, severity=1),
                event(5, seconds=800, ip="192.168.50.24"), event(6, "wazuh", 801, ip="192.168.50.24"),
                event(7, "pihole", 802, ip="192.168.50.24")]
        result = analyze_events(rows)
        ranked = result["correlations"]
        self.assertEqual([group["device"] for group in ranked[:3]], ["192.168.50.12", "192.168.50.12", "192.168.50.24"])
        self.assertNotIn("pihole", ranked[1]["source_counts"])
        original = json.dumps(result, sort_keys=True)
        evidence = build_ai_evidence(result, max_candidates=2)
        self.assertEqual([group["id"] for group in evidence["correlations"]], [ranked[0]["id"], ranked[2]["id"]])
        self.assertEqual(set(evidence["correlations"][1]["source_counts"]), {"suricata", "wazuh", "pihole"})
        for key in ("events_analyzed", "source_counts", "stream_counts", "event_types", "severity_counts"):
            self.assertEqual(evidence[key], result[key])
        self.assertEqual(evidence["selection"]["correlations_supplied"], 2)
        self.assertLessEqual(len(json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))), 3000)
        self.assertIn("not independent corroboration", evidence["limitations"][0])
        self.assertEqual(json.dumps(result, sort_keys=True), original)

    def test_ai_candidate_diversity_prefers_new_origins_then_devices_with_stable_ties(self):
        result = analyze_events([event(1), event(2, "wazuh", 1), event(3, "pihole", 2)])
        base = result["correlations"][0]
        first = {**base, "id": "first", "origin_counts": {"suricata": 2, "pihole": 1}}
        duplicate = {**first, "id": "duplicate"}
        other_device = {**first, "id": "other-device", "device": "192.168.50.24"}
        other_device_tie = {**first, "id": "other-device-tie", "device": "192.168.50.25"}
        new_origin = {**base, "id": "new-origin"}
        new_origin_tie = {**base, "id": "new-origin-tie"}
        result["correlations"] = [first, duplicate, other_device, other_device_tie, new_origin, new_origin_tie]
        evidence = build_ai_evidence(result)
        self.assertEqual([group["id"] for group in evidence["correlations"]], ["first", "new-origin"])
        result["correlations"] = result["correlations"][:4]
        evidence = build_ai_evidence(result)
        self.assertEqual([group["id"] for group in evidence["correlations"]], ["first", "other-device"])
        self.assertEqual(build_ai_evidence(result, max_candidates=1)["correlations"][0]["id"], "first")
        self.assertEqual(build_ai_evidence(result, max_candidates=0)["correlations"], [])

    def test_plain_model_evidence_separates_exclusions_and_candidate_counts(self):
        analysis = analyze_events([event(1), event(2, 'pihole', 1), event(3, seconds=2, ip='8.8.8.8')])
        evidence = build_ai_evidence(analysis)
        text = format_ai_evidence(evidence)
        self.assertIn('Normalized records: 3', text)
        self.assertIn('This window contains 2 observations', text)
        self.assertIn('1 records without a usable device address', text)
        self.assertIn('not candidate totals', text)
        self.assertIn('do not mean a selected candidate lacks its listed address', text)
        self.assertIn(analysis['correlations'][0]['id'], text)
        self.assertLessEqual(len(text), 4000)
        self.assertIn('may be outside the candidate windows', text)

    def test_report_escapes_ai_sensor_and_device_text(self):
        attack = '<script>alert("x")</script><img src=x onerror=alert(1)>'
        rows = [event(1, title=attack, hostname=attack, details={"input": attack})]
        result = analyze_events(rows, sources=[{"name": "suricata", "configured": True, "available": True, "notice": attack}])
        output = "".join(iter_html_report(rows, result, ai_analysis={"answer": attack, "model": attack}, devices=[{"display_name": attack}]))
        self.assertNotIn("<script>", output)
        self.assertNotIn("<img src=x", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertIn("Content-Security-Policy", output)
        self.assertIn("Normalized records exported: 1", output)

    def test_summary_only_does_not_consume_export_iterator(self):
        result = analyze_events([event(1)])
        def unread():
            self.fail("Summary-only rendering must not consume event iterator")
            yield
        output = "".join(iter_html_report(unread(), result, include_events=False))
        self.assertIn("companion events.jsonl", output)
        self.assertIn("AI analysis was not generated", output)
        self.assertNotIn("Normalized records exported", output)

    def test_export_mismatch_is_visible(self):
        result = analyze_events([event(1)])
        output = "".join(iter_html_report([event(1), event(2)], result))
        self.assertIn("differs from the analysis count", output)

    def test_csv_neutralizes_formula_and_jsonl_preserves_exact_data(self):
        row = event(1, title='=HYPERLINK("https://example.invalid")', hostname=" \t@SUM(A1)", details={"test": "line\ncomma,quote\""})
        exported = list(csv.DictReader(io.StringIO("".join(iter_csv_events([row])))))
        self.assertEqual(len(exported), 1)
        self.assertTrue(exported[0]["title"].startswith("'="))
        self.assertTrue(exported[0]["hostname"].startswith("'"))
        self.assertEqual(json.loads(exported[0]["details"]), row["details"])
        self.assertEqual(json.loads("".join(iter_jsonl_events([row]))), row)


if __name__ == "__main__":
    unittest.main()
