from __future__ import annotations

import fcntl
import hashlib
import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _content_for_hash(event: dict[str, Any]) -> dict[str, Any]:
    value = deepcopy(event)
    integrity = value.setdefault("integrity", {})
    integrity.pop("event_hash", None)
    return value


class JsonlEventStore:
    """Append-only, hash-chained JSONL event store.

    The chain detects accidental edits and basic tampering. For production, sign
    checkpoints and ship copies out of the target account as well.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        if "event_id" not in event or "event_type" not in event:
            raise ValueError("event_id and event_type are required")

        with self.path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                handle.seek(0)
                previous: dict[str, Any] | None = None
                sequence = 0
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        previous = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"invalid JSONL at line {line_number}") from exc
                    sequence += 1

                enriched = deepcopy(event)
                enriched["integrity"] = {
                    "sequence": sequence + 1,
                    "previous_event_hash": (
                        previous.get("integrity", {}).get("event_hash") if previous else None
                    ),
                }
                enriched["integrity"]["event_hash"] = hashlib.sha256(
                    _canonical(_content_for_hash(enriched))
                ).hexdigest()

                handle.seek(0, os.SEEK_END)
                handle.write(json.dumps(enriched, sort_keys=True, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
                return enriched
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def read(self) -> Iterable[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSONL at line {line_number}") from exc
        return events

    def verify(self) -> list[str]:
        issues: list[str] = []
        previous_hash: str | None = None
        expected_sequence = 1
        for event in self.read():
            integrity = event.get("integrity", {})
            actual_hash = integrity.get("event_hash")
            calculated_hash = hashlib.sha256(_canonical(_content_for_hash(event))).hexdigest()
            if integrity.get("sequence") != expected_sequence:
                issues.append(f"sequence {expected_sequence}: unexpected sequence number")
            if integrity.get("previous_event_hash") != previous_hash:
                issues.append(f"sequence {expected_sequence}: previous hash mismatch")
            if actual_hash != calculated_hash:
                issues.append(f"sequence {expected_sequence}: event hash mismatch")
            previous_hash = actual_hash
            expected_sequence += 1
        return issues

