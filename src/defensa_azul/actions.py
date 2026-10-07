from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _proposal_created_at(proposal: dict[str, Any]) -> datetime | None:
    payload = proposal.get("payload", {})
    return (
        _parse_utc(payload.get("created_at"))
        or _parse_utc(proposal.get("observed_time"))
        or _parse_utc(proposal.get("time"))
    )


def _proposal_is_stale(proposal: dict[str, Any], now: datetime) -> bool:
    payload = proposal.get("payload", {})
    created_at = _proposal_created_at(proposal)
    if created_at is None:
        return True
    try:
        ttl_seconds = int(payload.get("ttl_seconds", 0))
    except (TypeError, ValueError):
        return True
    if ttl_seconds <= 0:
        return True
    return now.astimezone(UTC) > created_at + timedelta(seconds=ttl_seconds)


def pending_action_events(
    events: list[dict[str, Any]], action_type: str | None = None, now: datetime | None = None
) -> list[dict[str, Any]]:
    """Return proposal/decision pairs that are allowed, unexecuted, fresh, and type-matched."""
    now = now or datetime.now(UTC)
    proposals = {
        str(event.get("payload", {}).get("proposal_id")): event
        for event in events
        if event.get("event_type") == "defense.proposal"
    }
    executed = {
        str(event.get("payload", {}).get("proposal_id"))
        for event in events
        if event.get("event_type") == "defense.action.result"
    }
    pending: list[dict[str, Any]] = []
    for decision in events:
        if decision.get("event_type") != "defense.decision":
            continue
        if decision.get("payload", {}).get("status") != "allowed":
            continue
        proposal_id = str(decision.get("payload", {}).get("proposal_id", ""))
        if not proposal_id or proposal_id in executed:
            continue
        proposal = proposals.get(proposal_id)
        if not proposal:
            continue
        proposal_action_type = proposal.get("payload", {}).get("action_type")
        if action_type and proposal_action_type != action_type:
            continue
        if _proposal_is_stale(proposal, now):
            continue
        pending.extend([proposal, decision])
    return pending
