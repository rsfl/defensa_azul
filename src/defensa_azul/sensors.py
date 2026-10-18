from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, Callable, Iterable

from .models import AuditEvent


HOST_PREFIX_TARGETS = {
    "target-web-01.": "target-web-01",
    "target-web-02.": "target-web-02",
    "target-web-03.": "target-web-03",
    "target-web-04.": "target-web-04",
    "target-web-05.": "target-web-05",
}

CONTAINER_TARGETS = {
    "target-stack-target-web-01-1": "target-web-01",
    "target-stack-target-web-02-1": "target-web-02",
    "target-stack-target-web-03-1": "target-web-03",
    "target-stack-target-web-04-1": "target-web-04",
    "target-stack-target-web-05-1": "target-web-05",
}

TARGET_INSTANCES = {target_id: container_name for container_name, target_id in CONTAINER_TARGETS.items()}


def _source_id(sensor: str, record: dict[str, Any]) -> str:
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"src-{sensor}-{digest}"


def _target_from_host(host: str) -> str | None:
    lowered = host.lower()
    for prefix, target_id in HOST_PREFIX_TARGETS.items():
        if lowered.startswith(prefix):
            return target_id
    return None


def normalize_traefik(record: dict[str, Any], run_id: str) -> dict[str, Any]:
    target_id = _target_from_host(str(record.get("RequestHost", "")))
    status = int(record.get("DownstreamStatus", 0) or 0)
    severity = "medium" if status >= 500 else "info"
    event = AuditEvent(
        event_type="defense.observation.http",
        actor={"type": "sensor", "id": "traefik-access"},
        payload={
            "instance_id": TARGET_INSTANCES.get(target_id) if target_id else None,
            "client_host": record.get("ClientHost"),
            "request_host": record.get("RequestHost"),
            "method": record.get("RequestMethod"),
            "path": urlsplit(str(record.get("RequestPath", ""))[:2048]).path,
            "status": status,
            "router": record.get("RouterName"),
            "service": record.get("ServiceName"),
            "duration_ns": record.get("Duration"),
        },
        run_id=run_id,
        target_id=target_id,
        evidence_ids=[_source_id("traefik", record)],
        severity=severity,
        time=str(record.get("StartUTC") or record.get("time")),
    ).to_dict()
    event["event_id"] = event["evidence_ids"][0]
    return event


def normalize_falco(record: dict[str, Any], run_id: str) -> dict[str, Any]:
    fields = record.get("output_fields", {}) if isinstance(record.get("output_fields"), dict) else {}
    container_name = str(fields.get("container.name", ""))
    target_id = CONTAINER_TARGETS.get(container_name)
    priority = str(record.get("priority", "info")).lower()
    proc_cmdline = str(fields.get("proc.cmdline", ""))
    event = AuditEvent(
        event_type="defense.observation.runtime",
        actor={"type": "sensor", "id": "falco"},
        payload={
            "rule": record.get("rule"),
            "priority": priority,
            "source": record.get("source"),
            "tags": record.get("tags", []),
            "container_name": container_name,
            "container_id": fields.get("container.id"),
            "process": fields.get("proc.name"),
            "host_pid": fields.get("proc.pid"),
            "container_pid": fields.get("proc.vpid"),
            "parent_process": fields.get("proc.pname"),
            "user": fields.get("user.name"),
            "file_path": fields.get("fd.name"),
            "command_line": {
                "sha256": hashlib.sha256(proc_cmdline.encode("utf-8")).hexdigest(),
                "length": len(proc_cmdline),
            },
        },
        run_id=run_id,
        target_id=target_id,
        evidence_ids=[_source_id("falco", record)],
        severity=priority if priority in {"debug", "info", "low", "medium", "high", "critical"} else "medium",
        time=str(record.get("time")),
    ).to_dict()
    event["event_id"] = event["evidence_ids"][0]
    return event


def read_jsonl(path: str | Path) -> Iterable[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"record at {path}:{line_number} is not an object")
            yield value


NORMALIZERS: dict[str, Callable[[dict[str, Any], str], dict[str, Any]]] = {
    "traefik": normalize_traefik,
    "falco": normalize_falco,
}
