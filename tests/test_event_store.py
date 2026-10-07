import json
import tempfile
import unittest
from pathlib import Path

from defensa_azul.event_store import JsonlEventStore
from defensa_azul.models import AuditEvent


class EventStoreTests(unittest.TestCase):
    def test_append_and_verify_hash_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            store = JsonlEventStore(path)
            for index in range(2):
                event = AuditEvent(
                    event_type="defense.finding",
                    actor={"type": "agent", "id": "test"},
                    payload={"index": index},
                    run_id="run-test",
                )
                store.append(event.to_dict())
            self.assertEqual([], store.verify())
            events = list(store.read())
            self.assertEqual(1, events[0]["integrity"]["sequence"])
            self.assertEqual(events[0]["integrity"]["event_hash"], events[1]["integrity"]["previous_event_hash"])

    def test_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            store = JsonlEventStore(path)
            event = AuditEvent(
                event_type="defense.finding",
                actor={"type": "agent", "id": "test"},
                payload={"value": "original"},
                run_id="run-test",
            )
            store.append(event.to_dict())
            value = json.loads(path.read_text())
            value["payload"]["value"] = "changed"
            path.write_text(json.dumps(value) + "\n")
            self.assertTrue(store.verify())


if __name__ == "__main__":
    unittest.main()

