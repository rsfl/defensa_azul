import unittest
import json
import tempfile
from pathlib import Path

from defensa_azul.worker import (
    _api_usage,
    _incident_event,
    _normalize_analysis,
    _recommendation_events,
    _token_health_events,
)


class WorkerTests(unittest.TestCase):
    def test_default_targets_start_in_observe_mode(self):
        config = json.loads(Path("policies/global.json").read_text(encoding="utf-8"))
        self.assertTrue(config["targets"])
        self.assertTrue(all(target["mode"] == "observe" for target in config["targets"].values()))

    def test_analysis_confidence_is_numeric_and_bounded(self):
        analysis = _normalize_analysis(
            {
                "summary": "test",
                "findings": "one finding",
                "gaps": [],
                "confidence": "1.5",
            }
        )
        self.assertEqual(1.0, analysis["confidence"])
        self.assertEqual(["one finding"], analysis["findings"])
        self.assertEqual("continue monitoring", analysis["recommended_next_step"])

    def test_invalid_confidence_uses_safe_default(self):
        analysis = _normalize_analysis({"confidence": "unknown"})
        self.assertEqual(0.5, analysis["confidence"])

    def test_api_usage_and_budget_warning(self):
        usage = _api_usage(
            {"usage": {"input_tokens": 50, "output_tokens": 30, "total_tokens": 80}},
            {"x-ratelimit-limit-tokens": "1000", "x-ratelimit-remaining-tokens": "50"},
        )
        source = {
            "event_id": "analysis-1",
            "event_type": "defense.analysis.completed",
            "run_id": "r1",
            "target_id": "target-web-01",
            "payload": {"api_usage": usage},
        }
        alerts = _token_health_events(
            [source], source, budget=100, warning_percent=80, rate_warning_percent=10
        )
        conditions = {item["payload"]["condition"] for item in alerts}
        self.assertEqual({"token_budget_warning", "token_rate_limit_low"}, conditions)

    def test_flag_access_never_enforces(self):
        attack = {
            "event_id": "evt-attack-1",
            "event_type": "defense.attack.detected",
            "run_id": "r1",
            "target_id": "target-web-01",
            "incident_id": "attack-1",
            "severity": "high",
            "confidence": 0.98,
            "payload": {
                "attack_type": "flag-access",
                "outcome": "successful",
                "instance_id": "target-web-01-1",
            },
        }
        first = _incident_event(attack)
        second = _incident_event(attack)
        self.assertEqual(first["event_id"], second["event_id"])
        proposal, decision = _recommendation_events(
            attack,
            ["evt-analysis-1"],
            Path("policies/global.json"),
        )
        self.assertEqual("response-planner", proposal["actor"]["id"])
        self.assertEqual("denied", decision["payload"]["status"])
        self.assertFalse(proposal["payload"]["intended_path_impacted"])

    def test_confirmed_shell_on_target_web_01_gets_bounded_allowed_proposal(self):
        attack = {
            "event_id": "evt-attack-shell",
            "event_type": "defense.attack.detected",
            "run_id": "r1",
            "target_id": "target-web-01",
            "incident_id": "attack-shell",
            "severity": "medium",
            "confidence": 0.98,
            "payload": {
                "attack_type": "post-exploitation-shell",
                "outcome": "observed",
                "instance_id": "target-stack-target-web-01-1",
                "process_context": {
                    "process": "bash",
                    "host_pid": 4242,
                    "container_pid": 7,
                    "container_name": "target-stack-target-web-01-1",
                    "container_id": "abc123def456",
                },
            },
        }
        config = json.loads(Path("policies/global.json").read_text(encoding="utf-8"))
        config["targets"]["target-web-01"]["mode"] = "enforce"
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps(config), encoding="utf-8")
            proposal, decision = _recommendation_events(attack, [], policy)
        self.assertEqual("suspend_process", proposal["payload"]["action_type"])
        self.assertEqual(15, proposal["payload"]["ttl_seconds"])
        self.assertEqual("allowed", decision["payload"]["status"])


if __name__ == "__main__":
    unittest.main()
