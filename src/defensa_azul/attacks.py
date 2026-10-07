from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Any, Iterable

from .models import AuditEvent


TARGET_CVES = {
    "target-web-01": [],
    "target-web-02": [],
    "target-web-03": [],
    "target-web-04": [],
    "target-web-05": [],
}

ATTACK_TTPS = {
    "flag-access": [{"id": "T1005", "name": "Data from Local System"}],
    "post-exploitation-shell": [{"id": "T1059.004", "name": "Unix Shell"}],
}


def _epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _classification(event: dict[str, Any]) -> tuple[str, str] | None:
    rule = str(event.get("payload", {}).get("rule", "")).lower()
    if "flag file read" in rule:
        return "flag-access", "successful"
    if "shell spawned" in rule:
        return "post-exploitation-shell", "observed"
    return None


def correlate_runtime_attacks(
    events: Iterable[dict[str, Any]], run_id: str, *, window_seconds: int = 300
) -> list[dict[str, Any]]:
    """Turn repeated runtime signals into stable attack events.

    Correlation uses target, attack type, and a fixed time window. It is an
    intentionally conservative baseline until HTTP/session-aware agents add a
    stronger incident key.
    """

    groups: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("run_id") != run_id or event.get("event_type") != "defense.observation.runtime":
            continue
        target_id = event.get("target_id")
        classified = _classification(event)
        if not target_id or classified is None:
            continue
        attack_type, _ = classified
        bucket = int(_epoch(str(event["time"])) // window_seconds)
        groups[(str(target_id), attack_type, bucket)].append(event)

    attacks: list[dict[str, Any]] = []
    for (target_id, attack_type, bucket), evidence in sorted(groups.items()):
        evidence.sort(key=lambda item: str(item["time"]))
        outcome = _classification(evidence[-1])[1]  # type: ignore[index]
        attack_key = f"{run_id}:{target_id}:{attack_type}:{bucket}"
        attack_id = "attack-" + hashlib.sha256(attack_key.encode("utf-8")).hexdigest()[:24]
        event = AuditEvent(
            event_type="defense.attack.detected",
            actor={"type": "agent", "id": "triage-coordinator"},
            payload={
                "attack_id": attack_id,
                "attack_type": attack_type,
                "outcome": outcome,
                "signal_count": len(evidence),
                "first_seen": evidence[0]["time"],
                "last_seen": evidence[-1]["time"],
                "correlation_window_seconds": window_seconds,
                "cves": TARGET_CVES.get(target_id, []),
                "ttps": ATTACK_TTPS.get(attack_type, []),
                "instance_id": evidence[-1].get("payload", {}).get("container_name") or target_id,
                "source_identity": "unavailable",
                "classification_basis": "falco-runtime-rule",
                "process_context": {
                    key: evidence[-1].get("payload", {}).get(key)
                    for key in (
                        "container_name",
                        "container_id",
                        "process",
                        "host_pid",
                        "container_pid",
                    )
                    if evidence[-1].get("payload", {}).get(key) is not None
                },
            },
            run_id=run_id,
            target_id=target_id,
            incident_id=attack_id,
            evidence_ids=[str(item["event_id"]) for item in evidence],
            severity="high" if outcome == "successful" else "medium",
            confidence=0.98,
            time=str(evidence[0]["time"]),
        ).to_dict()
        event["event_id"] = f"evt-{attack_id}"
        attacks.append(event)
    return attacks
