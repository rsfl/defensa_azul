import tempfile
import unittest

from defensa_azul.reporting import build_report, write_report


class ReportingTests(unittest.TestCase):
    def test_report_contains_required_sections_and_metrics(self):
        events = [
            {"run_id": "r1", "event_type": "defense.incident.opened", "event_id": "e1", "payload": {}},
            {"run_id": "r1", "event_type": "defense.action.result", "event_id": "e2", "payload": {"status": "succeeded"}},
            {"run_id": "r1", "event_type": "defense.knowledge.candidate", "event_id": "e3", "payload": {"lesson": "Example lesson"}},
            {"run_id": "r1", "event_type": "defense.evaluation.miss", "event_id": "e4", "payload": {"reason": "late detection"}},
            {"run_id": "r1", "event_type": "defense.attack.detected", "event_id": "e5", "target_id": "target-web-01", "time": "2026-09-17T00:00:00Z", "payload": {"attack_type": "post-exploitation-shell", "outcome": "observed", "instance_id": "target-web-01-1", "ttps": [{"id": "T1059.004", "name": "Unix Shell"}]}},
            {"run_id": "r1", "event_type": "defense.analysis.completed", "event_id": "e6", "payload": {"api_usage": {"input_tokens": 50, "output_tokens": 20, "total_tokens": 70}}},
        ]
        report = build_report(events, "r1")
        self.assertEqual(1.0, report["scores"]["derived"]["action_success_rate"])
        self.assertEqual(1, len(report["actions_taken"]))
        self.assertEqual(1, len(report["lessons_learned"]))
        self.assertEqual(1, len(report["misses"]))
        self.assertEqual(1, report["attacks"]["total"])
        self.assertEqual(1, report["attacks"]["by_type"]["post-exploitation-shell"])
        self.assertEqual(1, report["attacks"]["by_ttp"]["T1059.004"]["count"])
        self.assertEqual(1, report["instance_metrics"]["target-web-01-1"]["correlated_attacks"])
        self.assertEqual(70, report["openai_token_usage"]["total_tokens"])
        with tempfile.TemporaryDirectory() as directory:
            paths = write_report(report, directory)
            self.assertTrue(all(path.exists() for path in paths))


if __name__ == "__main__":
    unittest.main()
