from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


def build_report(events: Iterable[dict[str, Any]], run_id: str) -> dict[str, Any]:
    selected = [event for event in events if event.get("run_id") == run_id]
    counts = Counter(str(event.get("event_type", "unknown")) for event in selected)
    actions = [event for event in selected if event.get("event_type") == "defense.action.result"]
    lessons = [event for event in selected if event.get("event_type") == "defense.knowledge.candidate"]
    misses = [
        event
        for event in selected
        if event.get("event_type") == "defense.evaluation.miss"
        or event.get("payload", {}).get("disposition") == "miss"
    ]
    explicit_scores = [
        event.get("payload", {}) for event in selected if event.get("event_type") == "defense.evaluation.score"
    ]
    api_usage = [
        event.get("payload", {}).get("api_usage", {})
        for event in selected
        if event.get("event_type") == "defense.analysis.completed"
    ]
    succeeded = sum(1 for event in actions if event.get("payload", {}).get("status") == "succeeded")
    failed = sum(1 for event in actions if event.get("payload", {}).get("status") == "failed")
    decisions = [event for event in selected if event.get("event_type") == "defense.decision"]
    rejected = sum(1 for event in decisions if event.get("payload", {}).get("status") == "denied")
    attack_events = [event for event in selected if event.get("event_type") == "defense.attack.detected"]
    attacks_by_type = Counter(str(event.get("payload", {}).get("attack_type", "unknown")) for event in attack_events)
    attacks_by_target = Counter(str(event.get("target_id", "unknown")) for event in attack_events)
    attacks_by_outcome = Counter(str(event.get("payload", {}).get("outcome", "unknown")) for event in attack_events)
    attacks_by_instance = Counter(
        str(event.get("payload", {}).get("instance_id") or event.get("target_id", "unknown"))
        for event in attack_events
    )
    attacks_by_ttp: Counter[str] = Counter()
    ttp_names: dict[str, str] = {}
    for event in attack_events:
        for ttp in event.get("payload", {}).get("ttps", []):
            if isinstance(ttp, dict) and ttp.get("id"):
                ttp_id = str(ttp["id"])
                attacks_by_ttp[ttp_id] += 1
                ttp_names[ttp_id] = str(ttp.get("name", "unknown"))

    instance_metrics: dict[str, dict[str, Any]] = {}
    for event in selected:
        target_id = event.get("target_id")
        if not target_id:
            continue
        payload = event.get("payload", {})
        instance_id = str(payload.get("instance_id") or payload.get("container_name") or target_id)
        metrics = instance_metrics.setdefault(
            instance_id,
            {
                "target_id": target_id,
                "events": 0,
                "http_signals": 0,
                "runtime_signals": 0,
                "correlated_attacks": 0,
                "successful_attacks": 0,
                "actions": 0,
                "misses": 0,
                "first_seen": None,
                "last_seen": None,
            },
        )
        metrics["events"] += 1
        event_type = event.get("event_type")
        if event_type == "defense.observation.http":
            metrics["http_signals"] += 1
        elif event_type == "defense.observation.runtime":
            metrics["runtime_signals"] += 1
        elif event_type == "defense.attack.detected":
            metrics["correlated_attacks"] += 1
            if payload.get("outcome") == "successful":
                metrics["successful_attacks"] += 1
        elif event_type == "defense.action.result":
            metrics["actions"] += 1
        if event_type == "defense.evaluation.miss" or payload.get("disposition") == "miss":
            metrics["misses"] += 1
        event_time = event.get("time")
        if event_time:
            metrics["first_seen"] = min(filter(None, [metrics["first_seen"], event_time]))
            metrics["last_seen"] = max(filter(None, [metrics["last_seen"], event_time]))

    return {
        "report_version": "1.0.0",
        "run_id": run_id,
        "summary": {
            "total_events": len(selected),
            "incidents": counts["defense.incident.opened"],
            "findings": counts["defense.finding"],
            "proposals": counts["defense.proposal"],
            "actions_attempted": len(actions),
        },
        "actions_taken": [
            {
                "event_id": event.get("event_id"),
                "incident_id": event.get("incident_id"),
                "target_id": event.get("target_id"),
                **event.get("payload", {}),
            }
            for event in actions
        ],
        "openai_token_usage": {
            "input_tokens": sum(_safe_int(item.get("input_tokens")) for item in api_usage),
            "output_tokens": sum(_safe_int(item.get("output_tokens")) for item in api_usage),
            "total_tokens": sum(_safe_int(item.get("total_tokens")) for item in api_usage),
            "responses_counted": sum(1 for item in api_usage if item),
        },
        "attacks": {
            "total": len(attack_events),
            "by_type": dict(sorted(attacks_by_type.items())),
            "by_target": dict(sorted(attacks_by_target.items())),
            "by_outcome": dict(sorted(attacks_by_outcome.items())),
            "by_instance": dict(sorted(attacks_by_instance.items())),
            "by_ttp": {
                ttp_id: {"name": ttp_names.get(ttp_id, "unknown"), "count": count}
                for ttp_id, count in sorted(attacks_by_ttp.items())
            },
            "records": [
                {
                    "event_id": event.get("event_id"),
                    "target_id": event.get("target_id"),
                    "incident_id": event.get("incident_id"),
                    **event.get("payload", {}),
                }
                for event in attack_events
            ],
        },
        "instance_metrics": dict(sorted(instance_metrics.items())),
        "lessons_learned": [event.get("payload", {}) for event in lessons],
        "scores": {
            "derived": {
                "action_success_rate": succeeded / len(actions) if actions else None,
                "successful_actions": succeeded,
                "failed_actions": failed,
                "unsafe_or_invalid_proposals_rejected": rejected,
                "recorded_misses": len(misses),
            },
            "evaluation_events": explicit_scores,
        },
        "misses": [
            {
                "event_id": event.get("event_id"),
                "incident_id": event.get("incident_id"),
                "target_id": event.get("target_id"),
                **event.get("payload", {}),
            }
            for event in misses
        ],
        "event_counts": dict(sorted(counts.items())),
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def to_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    derived = report["scores"]["derived"]
    lines = [
        f"# Defensive Run Report: {report['run_id']}",
        "",
        "## Executive summary",
        "",
        f"- Total audited events: {summary['total_events']}",
        f"- Incidents: {summary['incidents']}",
        f"- Findings: {summary['findings']}",
        f"- Proposals: {summary['proposals']}",
        f"- Actions attempted: {summary['actions_attempted']}",
        f"- OpenAI tokens recorded: {report['openai_token_usage']['total_tokens']}",
        "",
        "## Attack counts",
        "",
    ]
    lines.append(f"- Correlated attacks: {report['attacks']['total']}")
    for attack_type, count in report["attacks"]["by_type"].items():
        lines.append(f"- `{attack_type}`: {count}")
    lines.extend(["", "### By target", ""])
    for target_id, count in report["attacks"]["by_target"].items():
        lines.append(f"- `{target_id}`: {count}")
    lines.extend(["", "### TTPs", ""])
    if report["attacks"]["by_ttp"]:
        for ttp_id, value in report["attacks"]["by_ttp"].items():
            lines.append(f"- `{ttp_id}` {value['name']}: {value['count']}")
    else:
        lines.append("No evidence-backed TTP mappings were recorded.")
    lines.extend(["", "## Per-instance metrics", ""])
    if report["instance_metrics"]:
        for instance_id, metrics in report["instance_metrics"].items():
            lines.append(
                f"- `{instance_id}`: events={metrics['events']}, http={metrics['http_signals']}, "
                f"runtime={metrics['runtime_signals']}, attacks={metrics['correlated_attacks']}, "
                f"successful={metrics['successful_attacks']}, actions={metrics['actions']}, misses={metrics['misses']}"
            )
    else:
        lines.append("No per-instance events were recorded.")
    lines.extend(["", "## Actions taken", ""])
    if report["actions_taken"]:
        for action in report["actions_taken"]:
            lines.append(f"- `{action.get('event_id')}`: {json.dumps(action, sort_keys=True)}")
    else:
        lines.append("No enforcement actions were recorded.")
    lines.extend(["", "## Lessons learned", ""])
    if report["lessons_learned"]:
        for lesson in report["lessons_learned"]:
            lines.append(f"- {lesson.get('lesson', json.dumps(lesson, sort_keys=True))}")
    else:
        lines.append("No reviewed lessons were recorded.")
    lines.extend(
        [
            "",
            "## Scores",
            "",
            f"- Action success rate: {derived['action_success_rate']}",
            f"- Successful actions: {derived['successful_actions']}",
            f"- Failed actions: {derived['failed_actions']}",
            f"- Unsafe or invalid proposals rejected: {derived['unsafe_or_invalid_proposals_rejected']}",
            f"- Recorded misses: {derived['recorded_misses']}",
            "",
            "## Misses",
            "",
        ]
    )
    if report["misses"]:
        for miss in report["misses"]:
            lines.append(f"- `{miss.get('event_id')}`: {json.dumps(miss, sort_keys=True)}")
    else:
        lines.append("No misses were recorded. This means no miss events were supplied, not that recall was perfect.")
    lines.extend(["", "## Event counts", ""])
    for event_type, count in report["event_counts"].items():
        lines.append(f"- `{event_type}`: {count}")
    return "\n".join(lines) + "\n"


def write_report(report: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"{report['run_id']}.json"
    markdown_path = directory / f"{report['run_id']}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(to_markdown(report), encoding="utf-8")
    return json_path, markdown_path
