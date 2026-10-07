from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4


class Mode(StrEnum):
    OBSERVE = "observe"
    RECOMMEND = "recommend"
    ENFORCE = "enforce"


class DecisionStatus(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    RECOMMENDATION_ONLY = "recommendation_only"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4()}"


@dataclass(slots=True)
class AuditEvent:
    event_type: str
    actor: dict[str, Any]
    payload: dict[str, Any]
    run_id: str
    target_id: str | None = None
    incident_id: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    severity: str = "info"
    confidence: float | None = None
    event_id: str = field(default_factory=lambda: new_id("evt"))
    time: str = field(default_factory=utc_now)
    observed_time: str = field(default_factory=utc_now)
    schema_version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "time": self.time,
            "observed_time": self.observed_time,
            "run_id": self.run_id,
            "actor": self.actor,
            "severity": self.severity,
            "evidence_ids": self.evidence_ids,
            "payload": self.payload,
        }
        if self.target_id is not None:
            result["target_id"] = self.target_id
        if self.incident_id is not None:
            result["incident_id"] = self.incident_id
        if self.confidence is not None:
            if not 0 <= self.confidence <= 1:
                raise ValueError("confidence must be between 0 and 1")
            result["confidence"] = self.confidence
        return result


@dataclass(slots=True)
class ActionProposal:
    run_id: str
    target_id: str
    incident_id: str
    action_type: str
    resource: str
    evidence_ids: list[str]
    confidence: float
    ttl_seconds: int
    rollback: dict[str, Any]
    expected_effect: str
    intended_path_impacted: bool = False
    false_positive_strategy: dict[str, Any] = field(default_factory=dict)
    escalation: dict[str, Any] = field(default_factory=dict)
    proposal_id: str = field(default_factory=lambda: new_id("prop"))
    created_at: str = field(default_factory=utc_now)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ActionProposal":
        return cls(**value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "created_at": self.created_at,
            "run_id": self.run_id,
            "target_id": self.target_id,
            "incident_id": self.incident_id,
            "action_type": self.action_type,
            "resource": self.resource,
            "evidence_ids": self.evidence_ids,
            "confidence": self.confidence,
            "ttl_seconds": self.ttl_seconds,
            "rollback": self.rollback,
            "expected_effect": self.expected_effect,
            "intended_path_impacted": self.intended_path_impacted,
            "false_positive_strategy": self.false_positive_strategy,
            "escalation": self.escalation,
        }

