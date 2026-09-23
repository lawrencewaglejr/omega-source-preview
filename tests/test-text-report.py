import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'dashboard'))
from text_report import format_text_report


class TextReportTests(unittest.TestCase):
    def test_retained_totals_are_distinct_from_selection_and_rule_level(self):
        text = format_text_report({'coverage': {'stored_events': 620597, 'collection_mode': 'from_now', 'caught_up': False, 'limitations': ['Source missing']},
            'alert_count': 69160, 'alerts': [{'severity': 3, 'sensor': 'wazuh', 'rule_level': 2, 'rule_id': '1002', 'signature': 'Unknown problem'}] * 210})
        self.assertIn('Retained normalized events: 620597', text)
        self.assertIn('200 shown', text)
        self.assertEqual(text.count('original Wazuh level 2'), 200)
        self.assertIn('OMEGA priority Low', text)
        self.assertIn('Collector caught up: no', text)
        self.assertIn('Limit: Source missing', text)

    def test_missing_health_is_unknown_and_external_health_stays_qualified(self):
        text = format_text_report({'services': [{'label': 'Alert viewer', 'state': 'reachable', 'detail': 'Application health unverified'}]})
        self.assertIn('Telemetry available: unknown', text)
        self.assertIn('Alert viewer: reachable — Application health unverified', text)
        self.assertIn('completeness is unverified', text)
        self.assertNotIn('Retained normalized events:', text)

    def test_demo_stale_sources_and_untrusted_multiline_values(self):
        text = format_text_report({'demo': True, 'stale': True, 'truncated': True,
            'sources': [{'id': 'wazuh_archives', 'available': False, 'sync_current': False, 'updated': '2026-09-21T01:00:00Z', 'notice': 'sync failed\nforged heading'}]})
        self.assertIn('DEMO — simulated data', text)
        self.assertIn('Snapshot stale: yes', text)
        self.assertIn('sync current=no', text)
        self.assertIn('last event=2026-09-21T01:00:00Z', text)
        self.assertIn('sync failed forged heading', text)
        self.assertNotIn('\nforged heading', text)


if __name__ == '__main__':
    unittest.main()
