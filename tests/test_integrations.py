import unittest

from defensa_azul.integrations import to_discord_summary, to_splunk_hec


class IntegrationTests(unittest.TestCase):
    def test_sensitive_values_are_redacted(self):
        event = {
            "event_type": "defense.finding",
            "event_id": "e1",
            "time": "2026-09-17T00:00:00Z",
            "run_id": "r1",
            "payload": {"api_token": "sensitive"},
        }
        hec = to_splunk_hec(event, host="node")
        self.assertEqual("[REDACTED]", hec["event"]["payload"]["api_token"])
        discord = to_discord_summary(event)
        self.assertEqual({"parse": []}, discord["allowed_mentions"])


if __name__ == "__main__":
    unittest.main()
