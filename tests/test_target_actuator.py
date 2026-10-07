import os
import signal
import tempfile
import unittest
from pathlib import Path

from defensa_azul.target_actuator import ActionRejected, TargetActuator


CONTAINER_ID = "a" * 64


class TargetActuatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        proc = Path(self.temp.name) / "4242"
        proc.mkdir()
        (proc / "comm").write_text("bash\n", encoding="utf-8")
        (proc / "cgroup").write_text(f"0::/system.slice/docker-{CONTAINER_ID}.scope\n", encoding="utf-8")
        fields = ["4242", "(bash)", "S", *("0" for _ in range(19))]
        (proc / "stat").write_text(" ".join(fields), encoding="utf-8")
        self.signals = []
        self.watchdogs = []
        self.actuator = TargetActuator(
            proc_root=self.temp.name,
            inspect_container=lambda _: CONTAINER_ID,
            send_signal=lambda pid, sig: self.signals.append((pid, sig)),
            sleep=lambda _: None,
            schedule_resume=lambda pid, start, ttl: self.watchdogs.append((pid, start, ttl)),
            cooldown_seconds=60,
        )
        self.request = {
            "action_type": "suspend_process",
            "target_id": "target-web-01",
            "ttl_seconds": 15,
            "host_pid": 4242,
            "process": "bash",
            "container_name": "target-stack-target-web-01-1",
            "container_id": CONTAINER_ID,
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_process_is_stopped_then_resumed(self):
        result = self.actuator.execute(self.request)
        self.assertEqual("completed", result["rollback"])
        self.assertEqual([(4242, signal.SIGSTOP), (4242, signal.SIGCONT)], self.signals)
        self.assertEqual([(4242, "0", 15)], self.watchdogs)

    def test_wrong_container_is_rejected_without_signal(self):
        self.request["container_name"] = "target-stack-target-web-02-1"
        with self.assertRaises(ActionRejected):
            self.actuator.execute(self.request)
        self.assertEqual([], self.signals)

    def test_pid_one_and_long_ttl_are_rejected(self):
        for key, value in (("host_pid", 1), ("ttl_seconds", 16)):
            bad = dict(self.request)
            bad[key] = value
            with self.assertRaises(ActionRejected):
                self.actuator.execute(bad)

    def test_flag_action_is_never_accepted(self):
        self.request["action_type"] = "block_flag_access"
        with self.assertRaises(ActionRejected):
            self.actuator.execute(self.request)


if __name__ == "__main__":
    unittest.main()
