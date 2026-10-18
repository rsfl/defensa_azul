import json
import unittest
from unittest.mock import patch

from defensa_azul.actuator import _call_target


class ActuatorSecurityTests(unittest.TestCase):
    def test_resource_cannot_override_policy_checked_fields(self):
        proposal = {"action_type": "suspend_process", "target_id": "safe-target", "ttl_seconds": 5,
                    "resource": json.dumps({"target_id": "other", "ttl_seconds": 100,
                                            "action_type": "other", "host_pid": 42})}
        with patch("defensa_azul.actuator.urllib.request.urlopen") as send:
            send.return_value.__enter__.return_value.read.return_value = b'{}'
            _call_target("http://example.invalid", "test-token", proposal)
            body = json.loads(send.call_args.args[0].data)
        self.assertEqual("safe-target", body["target_id"])
        self.assertEqual(5, body["ttl_seconds"])
        self.assertEqual("suspend_process", body["action_type"])
        self.assertEqual(42, body["host_pid"])
