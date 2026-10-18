import unittest

from defensa_azul.integrations import redact, to_discord_summary, to_splunk_hec


class IntegrationTests(unittest.TestCase):
    def test_nested_sensitive_fields_and_common_embedded_secrets(self):
        value = redact({"api_key": "example-secret", "nested": [{"client_secret": "example-secret"}],
                        "message": "Authorization: Bearer example-secret",
                        "url": "https://example.invalid/login?token=example-secret&user=alice"})
        self.assertEqual("[REDACTED]", value["api_key"])
        self.assertEqual("[REDACTED]", value["nested"][0]["client_secret"])
        self.assertNotIn("example-secret", str(value))
        self.assertNotIn("alice", value["url"])
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
