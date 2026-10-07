import unittest

from defensa_azul.sensors import normalize_falco, normalize_traefik


class SensorTests(unittest.TestCase):
    def test_traefik_target_mapping(self):
        event = normalize_traefik(
            {
                "RequestHost": "target-web-04.example.invalid",
                "RequestMethod": "GET",
                "RequestPath": "/api/secrets",
                "DownstreamStatus": 200,
                "StartUTC": "2026-09-17T00:00:00Z",
            },
            "run-1",
        )
        self.assertEqual("target-web-04", event["target_id"])
        self.assertEqual("defense.observation.http", event["event_type"])

    def test_falco_target_web_05_mapping_and_cmdline_hashing(self):
        event = normalize_falco(
            {
                "time": "2026-09-17T00:00:00Z",
                "rule": "Flag file read in CTF target container",
                "priority": "Notice",
                "source": "syscall",
                "tags": ["ctf", "flag"],
                "output_fields": {
                    "container.name": "target-stack-target-web-05-1",
                    "proc.cmdline": "cat /flag.txt",
                    "fd.name": "/flag.txt",
                },
            },
            "run-1",
        )
        self.assertEqual("target-web-05", event["target_id"])
        self.assertNotIn("cat /flag.txt", str(event["payload"]))
        self.assertEqual(13, event["payload"]["command_line"]["length"])

    def test_falco_preserves_exact_process_identity(self):
        event = normalize_falco(
            {
                "time": "2026-09-17T00:00:00Z",
                "rule": "Shell spawned in CTF target container",
                "priority": "Warning",
                "source": "syscall",
                "output_fields": {
                    "container.name": "target-stack-target-web-01-1",
                    "container.id": "abc123",
                    "proc.name": "bash",
                    "proc.pid": 4242,
                    "proc.vpid": 7,
                },
            },
            "run-1",
        )
        self.assertEqual(4242, event["payload"]["host_pid"])
        self.assertEqual(7, event["payload"]["container_pid"])


if __name__ == "__main__":
    unittest.main()
