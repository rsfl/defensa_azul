from __future__ import annotations

import hmac
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .actions import pending_action_events
from .event_store import JsonlEventStore
from .integrations import redact
from .models import ActionProposal, AuditEvent
from .policy import SafetyGate
from .reporting import build_report
from .sensors import NORMALIZERS


MAX_BODY_BYTES = 1_048_576
ENDPOINT_EVENT_TYPES = frozenset({
    "defense.endpoint.heartbeat", "defense.endpoint.windows_event",
    "defense.action.result", "defense.rollback",
})


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "DefensaGateway/0.1"

    @property
    def event_store(self) -> JsonlEventStore:
        return self.server.event_store  # type: ignore[attr-defined]

    @property
    def policy_path(self) -> Path:
        return self.server.policy_path  # type: ignore[attr-defined]

    @property
    def bearer_token(self) -> str:
        return self.server.bearer_token  # type: ignore[attr-defined]

    def _reply(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _role(self) -> str | None:
        supplied = self.headers.get("Authorization", "")
        operator = self.bearer_token
        endpoint = self.server.endpoint_token  # type: ignore[attr-defined]
        if operator and hmac.compare_digest(supplied, f"Bearer {operator}"):
            return "operator"
        if endpoint and hmac.compare_digest(supplied, f"Bearer {endpoint}"):
            return "endpoint"
        return None

    def _require_role(self, *roles: str) -> bool:
        role = self._role()
        if role in roles:
            return True
        self._reply(HTTPStatus.FORBIDDEN if role else HTTPStatus.UNAUTHORIZED,
                    {"error": "forbidden" if role else "unauthorized"})
        return False

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("body must be between 1 byte and 1 MiB")
        try:
            value = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ValueError("body is not valid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("body must be a JSON object")
        return value

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._reply(HTTPStatus.OK, {"healthy": True, "service": "defensa-gateway"})
            return
        if not self._require_role("operator", "endpoint"):
            return
        if self._role() == "endpoint" and parsed.path != "/v1/actions":
            self._reply(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return
        if parsed.path == "/v1/report":
            run_id = parse_qs(parsed.query).get("run_id", [None])[0]
            if not run_id:
                self._reply(HTTPStatus.BAD_REQUEST, {"error": "run_id is required"})
                return
            self._reply(HTTPStatus.OK, build_report(self.event_store.read(), run_id))
            return
        if parsed.path == "/v1/events":
            run_id = parse_qs(parsed.query).get("run_id", [None])[0]
            events = list(self.event_store.read())
            if run_id:
                events = [event for event in events if event.get("run_id") == run_id]
            self._reply(HTTPStatus.OK, {"events": events})
            return
        if parsed.path == "/v1/actions":
            query = parse_qs(parsed.query)
            run_id = query.get("run_id", [None])[0]
            target_id = query.get("target_id", [None])[0]
            action_type = query.get("action_type", [None])[0]
            if not run_id or not target_id:
                self._reply(HTTPStatus.BAD_REQUEST, {"error": "run_id and target_id are required"})
                return
            events = [
                event
                for event in self.event_store.read()
                if event.get("run_id") == run_id and event.get("target_id") == target_id
            ]
            self._reply(HTTPStatus.OK, {"events": pending_action_events(events, action_type)})
            return
        self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._require_role("operator", "endpoint"):
            return
        try:
            body = self._body()
            parsed = urlparse(self.path)
            if parsed.path.startswith("/v1/sensors/"):
                sensor = parsed.path.rsplit("/", 1)[-1]
                run_id = parse_qs(parsed.query).get("run_id", [None])[0]
                if sensor not in NORMALIZERS or not run_id:
                    self._reply(HTTPStatus.BAD_REQUEST, {"error": "valid sensor and run_id are required"})
                    return
                event = redact(NORMALIZERS[sensor](body, run_id))
                if any(existing.get("event_id") == event["event_id"] for existing in self.event_store.read()):
                    self._reply(HTTPStatus.OK, {"status": "duplicate", "event_id": event["event_id"]})
                    return
                appended = self.event_store.append(event)
                self._reply(HTTPStatus.CREATED, appended)
                return
            if self.path == "/v1/events":
                if body.get("event_type") not in ENDPOINT_EVENT_TYPES:
                    self._reply(HTTPStatus.FORBIDDEN, {"error": "event type is reserved"})
                    return
                appended = self.event_store.append(redact(AuditEvent(**body).to_dict()))
                self._reply(HTTPStatus.CREATED, appended)
                return
            if self.path == "/v1/proposals":
                if not self._require_role("operator"):
                    return
                proposal = ActionProposal.from_dict(body)
                proposal_event = AuditEvent(
                    event_type="defense.proposal",
                    actor={"type": "agent", "id": "remote-planner"},
                    payload=proposal.to_dict(),
                    run_id=proposal.run_id,
                    target_id=proposal.target_id,
                    incident_id=proposal.incident_id,
                    evidence_ids=proposal.evidence_ids,
                    confidence=proposal.confidence,
                )
                self.event_store.append(proposal_event.to_dict())
                decision = SafetyGate.from_file(self.policy_path).evaluate(proposal)
                decision_event = AuditEvent(
                    event_type="defense.decision",
                    actor={"type": "policy-gate", "id": "safety-gate"},
                    payload={"proposal_id": proposal.proposal_id, **decision.to_dict()},
                    run_id=proposal.run_id,
                    target_id=proposal.target_id,
                    incident_id=proposal.incident_id,
                    evidence_ids=proposal.evidence_ids,
                )
                appended = self.event_store.append(decision_event.to_dict())
                self._reply(HTTPStatus.CREATED, appended)
                return
            self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except (TypeError, ValueError, KeyError) as exc:
            self._reply(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except OSError:
            self._reply(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "event store unavailable"})

    def log_message(self, format: str, *args: Any) -> None:
        # Avoid emitting bearer headers or bodies. Standard access line only.
        super().log_message(format, *args)


def main() -> None:
    host = os.environ.get("DEFENSA_GATEWAY_HOST", "127.0.0.1")
    port = int(os.environ.get("DEFENSA_GATEWAY_PORT", "8080"))
    token = os.environ.get("DEFENSA_GATEWAY_TOKEN", "")
    if not token:
        raise SystemExit("DEFENSA_GATEWAY_TOKEN is required")
    endpoint_token = os.environ.get("DEFENSA_ENDPOINT_TOKEN", "")
    if not endpoint_token or hmac.compare_digest(token, endpoint_token):
        raise SystemExit("DEFENSA_ENDPOINT_TOKEN must be set and differ from DEFENSA_GATEWAY_TOKEN")
    server = ThreadingHTTPServer((host, port), GatewayHandler)
    server.event_store = JsonlEventStore(os.environ.get("DEFENSA_EVENT_STORE", "data/events.jsonl"))
    server.policy_path = Path(os.environ.get("DEFENSA_POLICY", "policies/global.json"))
    server.bearer_token = token
    server.endpoint_token = endpoint_token
    server.serve_forever()


if __name__ == "__main__":
    main()
