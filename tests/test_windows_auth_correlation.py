import json
import unittest
from unittest.mock import patch

from defensa_azul.attacks import correlate_windows_privileged_logon, correlate_windows_privileged_logon_bursts
from defensa_azul import worker
from defensa_azul.worker import _windows_firewall_block_action


FLOOR = "2026-11-15T13:00:00Z"


def windows_event(event_id, code, logon_id, *, source="192.168.225.1", observed="2026-11-15T13:18:24Z",
                  ingested="2026-11-15T13:18:27Z", user="Administrator"):
    data = ({"TargetUserName": user, "TargetLogonId": logon_id,
             "LogonType": "3", "IpAddress": source} if code == 4624 else
            {"SubjectUserName": user, "SubjectLogonId": logon_id})
    return {
        "event_id": event_id,
        "event_type": "defense.endpoint.windows_event",
        "run_id": "defended-live",
        "target_id": "win-dc01",
        "observed_time": observed,
        "time": ingested,
        "payload": {"channel": "Security", "event_id": code, "event_data": data},
    }


class WindowsAuthCorrelationTests(unittest.TestCase):
    def correlate(self, events):
        return correlate_windows_privileged_logon(
            events, "defended-live", allowed_sources={"192.168.225.1"}, not_before=FLOOR
        )

    def test_matched_admin_network_logon_produces_one_evidence_linked_attack(self):
        events = [windows_event("logon", 4624, "0xf02719"), windows_event("privilege", 4672, "0xf02719")]
        first = self.correlate(events)
        self.assertEqual(1, len(first))
        self.assertEqual("privileged_network_logon", first[0]["payload"]["attack_type"])
        self.assertEqual(["logon", "privilege"], first[0]["evidence_ids"])
        self.assertEqual(3, first[0]["payload"]["observation_delay_seconds"])
        self.assertEqual(first[0]["event_id"], self.correlate(events)[0]["event_id"])

    def test_single_logon_wrong_logon_id_and_unlisted_source_do_not_alert(self):
        logon = windows_event("logon", 4624, "0xf02719")
        self.assertEqual([], self.correlate([logon]))
        self.assertEqual([], self.correlate([logon, windows_event("privilege", 4672, "other")]))
        self.assertEqual([], self.correlate([
            windows_event("logon", 4624, "0xf02719", source="192.168.225.99"),
            windows_event("privilege", 4672, "0xf02719"),
        ]))

    def test_history_and_backlog_are_excluded_by_time_floor(self):
        old = "2026-11-15T12:59:00Z"
        events = [windows_event("logon", 4624, "x", observed=old),
                  windows_event("privilege", 4672, "x", observed=old)]
        self.assertEqual([], self.correlate(events))
        self.assertEqual([], correlate_windows_privileged_logon(
            [windows_event("logon", 4624, "x"), windows_event("privilege", 4672, "x")],
            "defended-live", allowed_sources=set(), not_before=FLOOR,
        ))

    def test_late_signal_can_alert_but_does_not_propose_block(self):
        events = [windows_event("logon", 4624, "x", ingested="2026-11-15T13:23:11Z"),
                  windows_event("privilege", 4672, "x", ingested="2026-11-15T13:23:11Z")]
        attack = self.correlate(events)[0]
        self.assertGreater(attack["payload"]["observation_delay_seconds"], 30)
        self.assertIsNone(_windows_firewall_block_action(attack, "win-dc01", "privileged_network_logon"))

    def test_fresh_bridge_alert_uses_ten_minute_rollback(self):
        events = [windows_event("logon", 4624, "x"), windows_event("privilege", 4672, "x")]
        attack = self.correlate(events)[0]
        with patch.object(worker, "LAB_BRIDGE_IP", "192.168.225.1"):
            action = _windows_firewall_block_action(attack, "win-dc01", "privileged_network_logon")
        self.assertIsNotNone(action)
        self.assertEqual(600, action[2])
        self.assertEqual(600, action[5]["rollback_deadline_seconds"])
        self.assertEqual("192.168.225.1", json.loads(action[1])["src_ip"])

    def test_three_matched_logons_in_thirty_seconds_alert_without_new_block(self):
        events = []
        for index, second in enumerate((24, 28, 36), 1):
            observed = f"2026-11-15T13:18:{second:02d}Z"
            events.extend([
                windows_event(f"logon-{index}", 4624, f"0x{index}", observed=observed),
                windows_event(f"privilege-{index}", 4672, f"0x{index}", observed=observed),
            ])
        attacks = correlate_windows_privileged_logon_bursts(
            events, "defended-live", allowed_sources={"192.168.225.1"}, not_before=FLOOR
        )
        self.assertEqual(1, len(attacks))
        self.assertEqual("privileged_network_logon_burst", attacks[0]["payload"]["attack_type"])
        self.assertEqual(3, attacks[0]["payload"]["successful_logons"])
        self.assertEqual(6, len(attacks[0]["evidence_ids"]))
        self.assertFalse(attacks[0]["payload"]["auto_block_eligible"])
        self.assertIsNone(_windows_firewall_block_action(attacks[0], "win-dc01", "privileged_network_logon_burst"))
        self.assertEqual(attacks[0]["event_id"], correlate_windows_privileged_logon_bursts(
            events, "defended-live", allowed_sources={"192.168.225.1"}, not_before=FLOOR
        )[0]["event_id"])

    def test_burst_requires_three_pairs_same_source_within_window(self):
        events = []
        for index, second in enumerate((0, 15, 45), 1):
            observed = f"2026-11-15T13:19:{second:02d}Z"
            events.extend([
                windows_event(f"logon-{index}", 4624, f"0x{index}", observed=observed),
                windows_event(f"privilege-{index}", 4672, f"0x{index}", observed=observed),
            ])
        correlate = lambda items: correlate_windows_privileged_logon_bursts(
            items, "defended-live", allowed_sources={"192.168.225.1"}, not_before=FLOOR
        )
        self.assertEqual([], correlate(events))
        events[4]["observed_time"] = "2026-11-15T13:19:25Z"
        events[5]["observed_time"] = "2026-11-15T13:19:25Z"
        self.assertEqual(1, len(correlate(events)))
        self.assertEqual([], correlate(events[:-1]))
        events[4]["payload"]["event_data"]["IpAddress"] = "192.168.225.99"
        self.assertEqual([], correlate(events))


if __name__ == "__main__":
    unittest.main()
