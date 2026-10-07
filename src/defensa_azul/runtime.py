from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import new_id, utc_now


@dataclass(frozen=True, slots=True)
class AgentRole:
    id: str
    skill: str
    purpose: str
    may_propose_actions: bool
    may_approve_actions: bool


@dataclass(frozen=True, slots=True)
class WorkItem:
    task_id: str
    role_id: str
    skill: str
    event_id: str
    run_id: str
    target_id: str | None
    incident_id: str | None
    created_at: str
    input_contract: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "role_id": self.role_id,
            "skill": self.skill,
            "event_id": self.event_id,
            "run_id": self.run_id,
            "target_id": self.target_id,
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "input_contract": self.input_contract,
        }


class AgentRegistry:
    def __init__(self, roles: dict[str, AgentRole], version: str):
        self.roles = roles
        self.version = version

    @classmethod
    def from_file(cls, path: str | Path) -> "AgentRegistry":
        with Path(path).open(encoding="utf-8") as handle:
            value = json.load(handle)
        roles = {
            item["id"]: AgentRole(
                id=item["id"],
                skill=item["skill"],
                purpose=item["purpose"],
                may_propose_actions=bool(item["may_propose_actions"]),
                may_approve_actions=bool(item["may_approve_actions"]),
            )
            for item in value["roles"]
        }
        return cls(roles, str(value["version"]))

    def dispatch(self, event: dict[str, Any]) -> list[WorkItem]:
        event_type = event.get("event_type")
        routing = {
            "defense.incident.opened": ["behavior-analyst", "exploit-analyst", "integrity-analyst"],
            "defense.analysis.completed": ["response-planner"],
            "defense.proposal": ["safety-arbiter"],
            "defense.incident.closed": ["knowledge-curator"],
            "defense.run.completed": ["knowledge-curator"],
        }
        role_ids = routing.get(str(event_type), [])
        return [
            WorkItem(
                task_id=new_id("task"),
                role_id=role_id,
                skill=self.roles[role_id].skill,
                event_id=str(event["event_id"]),
                run_id=str(event["run_id"]),
                target_id=event.get("target_id"),
                incident_id=event.get("incident_id"),
                created_at=utc_now(),
                input_contract="sanitized_event_ids_only",
            )
            for role_id in role_ids
        ]

