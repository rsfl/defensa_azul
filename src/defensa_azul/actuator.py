from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from hashlib import sha256
from pathlib import Path
from typing import Any

from .event_store import JsonlEventStore
from .models import AuditEvent


def _stable_id(prefix: str, value: str) -> str:
    return f"{prefix}-{sha256(value.encode('utf-8')).hexdigest()[:24]}"


def _call_target(url: str, token: str, proposal: dict[str, Any]) -> dict[str, Any]:
    resource = json.loads(proposal["resource"])
    body = {
        "action_type": proposal["action_type"],
        "target_id": proposal["target_id"],
        "ttl_seconds": proposal["ttl_seconds"],
        **resource,
    }
    request = urllib.request.Request(
        f"{url.rstrip('/')}/v1/actions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=int(proposal["ttl_seconds"]) + 10) as response:
        return json.load(response)


def _result_event(
    decision: dict[str, Any], proposal: dict[str, Any], result: dict[str, Any]
) -> dict[str, Any]:
    proposal_id = str(proposal["proposal_id"])
    event = AuditEvent(
        event_type="defense.action.result",
        actor={"type": "agent", "id": "bounded-actuator"},
        payload={
            "proposal_id": proposal_id,
            "decision_event_id": decision["event_id"],
            "action_type": proposal["action_type"],
            "status": result.get("status", "failed"),
            "ttl_seconds": proposal["ttl_seconds"],
            "result": result,
        },
        run_id=str(decision["run_id"]),
        target_id=decision.get("target_id"),
        incident_id=decision.get("incident_id"),
        evidence_ids=[str(decision["event_id"]), *proposal.get("evidence_ids", [])],
        severity="high",
    ).to_dict()
    event["event_id"] = _stable_id("evt-action", proposal_id)
    return event


def _rollback_event(decision: dict[str, Any], proposal: dict[str, Any]) -> dict[str, Any]:
    proposal_id = str(proposal["proposal_id"])
    event = AuditEvent(
        event_type="defense.rollback",
        actor={"type": "agent", "id": "bounded-actuator"},
        payload={
            "proposal_id": proposal_id,
            "action_type": proposal["action_type"],
            "status": "completed",
            "rollback": proposal["rollback"],
        },
        run_id=str(decision["run_id"]),
        target_id=decision.get("target_id"),
        incident_id=decision.get("incident_id"),
        evidence_ids=[_stable_id("evt-action", proposal_id)],
        severity="info",
    ).to_dict()
    event["event_id"] = _stable_id("evt-rollback", proposal_id)
    return event


def main() -> None:
    token = os.environ.get("DEFENSA_ACTUATOR_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("DEFENSA_ACTUATOR_TOKEN must contain at least 32 characters")
    url = os.environ.get("DEFENSA_TARGET_ACTUATOR_URL", "http://127.0.0.1:9091")
    interval = float(os.environ.get("DEFENSA_ACTUATOR_POLL_SECONDS", "1"))
    store = JsonlEventStore(os.environ.get("DEFENSA_EVENT_STORE", "/data/events.jsonl"))
    checkpoint_path = Path(os.environ.get("DEFENSA_ACTUATOR_CHECKPOINT", "/data/actuator.checkpoint"))

    while True:
        checkpoint = int(checkpoint_path.read_text().strip() or "0") if checkpoint_path.exists() else 0
        events = list(store.read())
        proposals = {
            str(item.get("payload", {}).get("proposal_id")): item.get("payload", {})
            for item in events
            if item.get("event_type") == "defense.proposal"
        }
        for decision in events:
            sequence = int(decision.get("integrity", {}).get("sequence", 0))
            if sequence <= checkpoint:
                continue
            if (
                decision.get("event_type") == "defense.decision"
                and decision.get("payload", {}).get("status") == "allowed"
            ):
                proposal_id = str(decision.get("payload", {}).get("proposal_id", ""))
                proposal = proposals.get(proposal_id)
                if proposal and proposal.get("action_type") == "suspend_process":
                    try:
                        result = _call_target(url, token, proposal)
                    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
                        result = {"status": "failed", "error_type": type(exc).__name__}
                    existing = {item.get("event_id") for item in store.read()}
                    action = _result_event(decision, proposal, result)
                    if action["event_id"] not in existing:
                        store.append(action)
                    if result.get("rollback") == "completed":
                        rollback = _rollback_event(decision, proposal)
                        if rollback["event_id"] not in existing:
                            store.append(rollback)
            checkpoint_path.write_text(f"{sequence}\n", encoding="utf-8")
        time.sleep(interval)


if __name__ == "__main__":
    main()
