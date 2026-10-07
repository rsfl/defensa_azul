from __future__ import annotations

from datetime import datetime
from typing import Any


SENSITIVE_KEYS = {"flag", "flag_value", "password", "secret", "token", "authorization", "cookie"}


def _sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return (
        normalized in SENSITIVE_KEYS
        or normalized.endswith(("_password", "_secret", "_token", "_cookie"))
        or "authorization" in normalized
    )


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _sensitive_key(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def to_splunk_hec(event: dict[str, Any], *, host: str, index: str | None = None) -> dict[str, Any]:
    timestamp = event.get("time")
    epoch = None
    if isinstance(timestamp, str):
        epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    envelope: dict[str, Any] = {
        "host": host,
        "source": "defensa-azul",
        "sourcetype": "ctf:defense:json",
        "event": redact(event),
        "fields": {
            "run_id": event.get("run_id", "unknown"),
            "event_type": event.get("event_type", "unknown"),
            "target_id": event.get("target_id", "none"),
        },
    }
    if epoch is not None:
        envelope["time"] = epoch
    if index:
        envelope["index"] = index
    return envelope


def to_discord_summary(event: dict[str, Any]) -> dict[str, Any]:
    safe = redact(event)
    event_type = str(safe.get("event_type", "defense.event"))
    incident_id = safe.get("incident_id", "none")
    target_id = safe.get("target_id", "none")
    severity = safe.get("severity", "info")
    fields = [
        {"name": "Severity", "value": str(severity), "inline": True},
        {"name": "Event ID", "value": str(safe.get("event_id", "unknown")), "inline": True},
    ]
    payload = safe.get("payload", {})
    if event_type == "defense.attack.detected":
        fields.extend(
            [
                {"name": "Attack type", "value": str(payload.get("attack_type", "unknown")), "inline": True},
                {"name": "Outcome", "value": str(payload.get("outcome", "unknown")), "inline": True},
                {"name": "Signals", "value": str(payload.get("signal_count", 1)), "inline": True},
            ]
        )
    elif event_type in {"defense.decision", "defense.action.result", "defense.rollback"}:
        fields.append(
            {
                "name": "Status",
                "value": str(payload.get("status", payload.get("approval", "unknown"))),
                "inline": True,
            }
        )
    elif event_type == "defense.health.degraded":
        fields.extend(
            [
                {"name": "Component", "value": str(payload.get("component", "unknown")), "inline": True},
                {"name": "Condition", "value": str(payload.get("condition", "unknown")), "inline": True},
                {
                    "name": "Tokens remaining",
                    "value": str(payload.get("remaining_tokens", "not reported")),
                    "inline": True,
                },
            ]
        )
    return {
        "content": None,
        "embeds": [
            {
                "title": event_type,
                "description": f"Incident `{incident_id}` on target `{target_id}`",
                "fields": fields[:25],
            }
        ],
        "allowed_mentions": {"parse": []},
    }
