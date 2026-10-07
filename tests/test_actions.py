from __future__ import annotations

import unittest
from datetime import UTC, datetime

from defensa_azul.actions import pending_action_events


def proposal(proposal_id: str, action_type: str, *, created_at: str = "2026-09-29T23:21:00Z", ttl: int = 300):
    return {
        "event_type": "defense.proposal",
        "run_id": "run-test",
        "target_id": "win-dc01",
        "observed_time": created_at,
        "payload": {
            "proposal_id": proposal_id,
            "created_at": created_at,
            "action_type": action_type,
            "ttl_seconds": ttl,
        },
    }


def decision(proposal_id: str, status: str = "allowed"):
    return {
        "event_type": "defense.decision",
        "run_id": "run-test",
        "target_id": "win-dc01",
        "payload": {"proposal_id": proposal_id, "status": status},
    }


def action_result(proposal_id: str):
    return {
        "event_type": "defense.action.result",
        "run_id": "run-test",
        "target_id": "win-dc01",
        "payload": {"proposal_id": proposal_id, "status": "succeeded"},
    }


class PendingActionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 29, 23, 22, tzinfo=UTC)

    def test_returns_matching_allowed_unexecuted_proposal_and_decision(self):
        events = [proposal("prop-1", "windows_firewall_block"), decision("prop-1")]

        pending = pending_action_events(events, "windows_firewall_block", self.now)

        self.assertEqual(["defense.proposal", "defense.decision"], [event["event_type"] for event in pending])

    def test_filters_wrong_action_type(self):
        events = [proposal("prop-1", "increase_capture"), decision("prop-1")]

        pending = pending_action_events(events, "windows_firewall_block", self.now)

        self.assertEqual([], pending)

    def test_filters_executed_proposals(self):
        events = [
            proposal("prop-1", "windows_firewall_block"),
            decision("prop-1"),
            action_result("prop-1"),
        ]

        pending = pending_action_events(events, "windows_firewall_block", self.now)

        self.assertEqual([], pending)

    def test_filters_stale_proposals(self):
        events = [
            proposal("prop-1", "windows_firewall_block", created_at="2026-09-29T23:00:00Z", ttl=120),
            decision("prop-1"),
        ]

        pending = pending_action_events(events, "windows_firewall_block", self.now)

        self.assertEqual([], pending)

    def test_filters_denied_decisions(self):
        events = [proposal("prop-1", "windows_firewall_block"), decision("prop-1", "denied")]

        pending = pending_action_events(events, "windows_firewall_block", self.now)

        self.assertEqual([], pending)


if __name__ == "__main__":
    unittest.main()
