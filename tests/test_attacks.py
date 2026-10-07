import unittest

from defensa_azul.attacks import correlate_runtime_attacks


def runtime_event(event_id, time, target, rule, **payload):
    return {
        "event_id": event_id,
        "event_type": "defense.observation.runtime",
        "run_id": "r1",
        "target_id": target,
        "time": time,
        "payload": {"rule": rule, **payload},
    }


class AttackCorrelationTests(unittest.TestCase):
    def test_repeated_signals_in_window_count_as_one_attack(self):
        events = [
            runtime_event("e1", "2026-09-17T00:00:01Z", "target-web-01", "Shell spawned in CTF target container"),
            runtime_event("e2", "2026-09-17T00:00:20Z", "target-web-01", "Shell spawned in CTF target container"),
            runtime_event("e3", "2026-09-17T00:00:30Z", "target-web-01", "Flag file read in CTF target container"),
        ]
        attacks = correlate_runtime_attacks(events, "r1")
        self.assertEqual(2, len(attacks))
        by_type = {event["payload"]["attack_type"]: event for event in attacks}
        self.assertEqual(2, by_type["post-exploitation-shell"]["payload"]["signal_count"])
        self.assertEqual("successful", by_type["flag-access"]["payload"]["outcome"])
        self.assertEqual("T1005", by_type["flag-access"]["payload"]["ttps"][0]["id"])
        self.assertEqual("T1059.004", by_type["post-exploitation-shell"]["payload"]["ttps"][0]["id"])

    def test_correlation_is_deterministic(self):
        events = [runtime_event("e1", "2026-09-17T00:00:01Z", "target-web-05", "Shell spawned in CTF target container")]
        first = correlate_runtime_attacks(events, "r1")
        second = correlate_runtime_attacks(events, "r1")
        self.assertEqual(first[0]["event_id"], second[0]["event_id"])

    def test_shell_process_context_is_propagated(self):
        events = [
            runtime_event(
                "e1",
                "2026-09-17T00:00:01Z",
                "target-web-01",
                "Shell spawned in CTF target container",
                process="bash",
                host_pid=4242,
                container_pid=7,
                container_name="target-stack-target-web-01-1",
                container_id="abc123",
            )
        ]
        attack = correlate_runtime_attacks(events, "r1")[0]
        self.assertEqual(4242, attack["payload"]["process_context"]["host_pid"])


if __name__ == "__main__":
    unittest.main()
