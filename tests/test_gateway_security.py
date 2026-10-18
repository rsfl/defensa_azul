import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from defensa_azul.event_store import JsonlEventStore
from defensa_azul.gateway import GatewayHandler


class GatewaySecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), GatewayHandler)
        self.server.event_store = JsonlEventStore(Path(self.directory.name) / "events.jsonl")
        self.server.policy_path = Path("policies/global.json")
        self.server.bearer_token = "operator-test-token"
        self.server.endpoint_token = "endpoint-test-token"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.directory.cleanup()

    def request(self, path, token, body=None):
        request = Request(f"http://127.0.0.1:{self.server.server_port}{path}",
                          data=json.dumps(body).encode() if body is not None else None,
                          headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_endpoint_cannot_forge_policy_events_or_submit_proposals(self):
        for event_type in ("defense.decision", "defense.proposal"):
            body = {"event_type": event_type, "actor": {"id": "forged"},
                    "payload": {"status": "allowed"}, "run_id": "run"}
            for token in ("endpoint-test-token", "operator-test-token"):
                self.assertEqual(403, self.request("/v1/events", token, body)[0])
        self.assertEqual(403, self.request("/v1/proposals", "endpoint-test-token", {})[0])
        self.assertEqual([], list(self.server.event_store.read()))

    def test_endpoint_permissions_and_ingestion_redaction(self):
        self.assertEqual(403, self.request("/v1/events", "endpoint-test-token")[0])
        self.assertEqual(401, self.request("/v1/events", "wrong-token")[0])
        self.assertEqual(200, self.request("/v1/actions?run_id=r&target_id=t", "endpoint-test-token")[0])
        body = {"event_type": "defense.endpoint.heartbeat", "actor": {"id": "host"},
                "payload": {"api_key": "example-secret"}, "run_id": "r"}
        status, event = self.request("/v1/events", "endpoint-test-token", body)
        self.assertEqual(201, status)
        self.assertEqual("[REDACTED]", event["payload"]["api_key"])

    def test_operator_proposal_still_runs_through_policy(self):
        proposal = json.loads(Path("examples/proposal.json").read_text(encoding="utf-8"))
        status, decision = self.request("/v1/proposals", "operator-test-token", proposal)
        self.assertEqual(201, status)
        self.assertEqual("denied", decision["payload"]["status"])
        self.assertEqual(["defense.proposal", "defense.decision"],
                         [event["event_type"] for event in self.server.event_store.read()])
