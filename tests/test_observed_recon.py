import unittest

from defensa_azul.attacks import correlate_observed_recon


def observation(kind: str, index: int, *, target: str = "nginx-server01", source: str = "172.19.0.5") -> dict:
    payload = {"source_ip": source}
    if kind == "http":
        payload["path"] = f"/path-{index}"
    elif kind == "network":
        payload["destination_port"] = index
    else:
        payload.update({"user": "root", "outcome": "accepted"})
    return {
        "event_id": f"e-{kind}-{index}",
        "event_type": f"defense.observation.{kind}",
        "run_id": "trial-1",
        "target_id": target,
        "time": "2026-11-14T00:58:10+00:00",
        "payload": payload,
    }


class ObservedReconTests(unittest.TestCase):
    def test_path_threshold_requires_distinct_paths(self):
        events = [observation("http", index) for index in range(14)]
        events.append({**events[0], "event_id": "duplicate-request"})
        self.assertEqual([], correlate_observed_recon(events, "trial-1"))
        events.append(observation("http", 14))
        attacks = correlate_observed_recon(events, "trial-1")
        self.assertEqual(1, len(attacks))
        self.assertEqual("web_path_enumeration", attacks[0]["payload"]["attack_type"])
        self.assertEqual(15, attacks[0]["payload"]["distinct_values"])

    def test_port_threshold_and_run_scope(self):
        events = [observation("network", index, target="linux-server01") for index in range(99)]
        self.assertEqual([], correlate_observed_recon(events, "trial-1"))
        events.append(observation("network", 99, target="linux-server01"))
        self.assertEqual(1, len(correlate_observed_recon(events, "trial-1")))
        self.assertEqual([], correlate_observed_recon(events, "other-trial"))

    def test_root_login_is_observed_without_claiming_exploitation(self):
        attack = correlate_observed_recon(
            [observation("authentication", 1, target="linux-server01")], "trial-1"
        )[0]
        self.assertEqual("privileged_remote_login", attack["payload"]["attack_type"])
        self.assertEqual("observed", attack["payload"]["outcome"])
        self.assertEqual("target-side-observations", attack["payload"]["classification_basis"])


if __name__ == "__main__":
    unittest.main()
