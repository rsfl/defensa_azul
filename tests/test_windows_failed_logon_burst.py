import unittest

from defensa_azul.attacks import correlate_windows_failed_logon_bursts
from defensa_azul.worker import _windows_firewall_block_action


def failure(index, *, source="192.168.225.1", target="win-dc01", minute="16:00",
            logon_type="3", observed_day="2026-11-16"):
    second = index % 60
    return {
        "event_id": f"failed-{target}-{index}",
        "event_type": "defense.endpoint.windows_event",
        "run_id": "defended-live",
        "target_id": target,
        "observed_time": f"{observed_day}T{minute}:{second:02d}Z",
        "time": f"{observed_day}T{minute}:{second:02d}Z",
        "payload": {"channel": "Security", "event_id": 4625,
                    "event_data": {"IpAddress": source, "LogonType": logon_type,
                                   "TargetUserName": "Administrator"}},
    }


class WindowsFailedLogonBurstTests(unittest.TestCase):
    def correlate(self, events):
        return correlate_windows_failed_logon_bursts(
            events, "defended-live", allowed_sources={"192.168.225.1"},
            not_before="2026-11-16T15:59:00Z",
        )

    def test_tenth_failure_creates_stable_alert_without_block(self):
        events = [failure(i) for i in range(10)]
        self.assertEqual([], self.correlate(events[:9]))
        alerts = self.correlate(events)
        self.assertEqual(1, len(alerts))
        alert = alerts[0]
        self.assertEqual("windows_failed_logon_burst", alert["payload"]["attack_type"])
        self.assertEqual("2026-11-16T16:00:09Z", alert["payload"]["threshold_reached_at"])
        self.assertEqual(10, len(alert["evidence_ids"]))
        self.assertFalse(alert["payload"]["auto_block_eligible"])
        self.assertIsNone(_windows_firewall_block_action(alert, "win-dc01", "windows_failed_logon_burst"))
        self.assertEqual(alert["event_id"], self.correlate(events + [failure(10)])[0]["event_id"])

    def test_deduplicates_and_rejects_wrong_source_type_or_history(self):
        events = [failure(i) for i in range(9)]
        events += [events[0].copy(), failure(9, source="192.168.225.99"),
                   failure(10, logon_type="2"), failure(11, observed_day="2026-11-15")]
        self.assertEqual([], self.correlate(events))

    def test_separates_hosts_and_minutes(self):
        events = [failure(i) for i in range(9)]
        events += [failure(9, minute="16:01"), failure(10, target="win-client01")]
        self.assertEqual([], self.correlate(events))
        events.append(failure(11))
        self.assertEqual(1, len(self.correlate(events)))


if __name__ == "__main__":
    unittest.main()
