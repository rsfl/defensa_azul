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


def correlate_observed_recon(
    events: Iterable[dict[str, Any]], run_id: str, *, window_seconds: int = 300
) -> list[dict[str, Any]]:
    """Correlate target-side web, network, and SSH observations for one run."""

    groups: dict[tuple[str, str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("run_id") != run_id:
            continue
        kind = event.get("event_type")
        payload = event.get("payload", {})
        source = str(payload.get("source_ip") or "")
        target = str(event.get("target_id") or "")
        if not source or not target or not event.get("time"):
            continue
        if kind == "defense.observation.http" and payload.get("path"):
            attack_type = "web_path_enumeration"
        elif kind == "defense.observation.network" and payload.get("destination_port") is not None:
            attack_type = "port_enumeration"
        elif kind == "defense.observation.authentication" and payload.get("outcome") == "accepted" and payload.get("user") == "root":
            attack_type = "privileged_remote_login"
        else:
            continue
        bucket = int(_epoch(str(event["time"])) // window_seconds)
        groups[(target, source, attack_type, bucket)].append(event)

    attacks: list[dict[str, Any]] = []
    for (target, source, attack_type, bucket), evidence in sorted(groups.items()):
        if attack_type == "web_path_enumeration":
            distinct = len({str(item["payload"]["path"]) for item in evidence})
            threshold = 15
        elif attack_type == "port_enumeration":
            distinct = len({int(item["payload"]["destination_port"]) for item in evidence})
            threshold = 100
        else:
            distinct = len(evidence)
            threshold = 1
        if distinct < threshold:
            continue
        evidence.sort(key=lambda item: str(item["time"]))
        attack_key = f"{run_id}:{target}:{source}:{attack_type}:{bucket}"
        attack_id = "attack-" + hashlib.sha256(attack_key.encode("utf-8")).hexdigest()[:24]
        event = AuditEvent(
            event_type="defense.attack.detected",
            actor={"type": "agent", "id": "triage-coordinator"},
            payload={
                "attack_id": attack_id,
                "attack_type": attack_type,
                "outcome": "observed",
                "signal_count": len(evidence),
                "distinct_values": distinct,
                "threshold": threshold,
                "source_ip": source,
                "first_seen": evidence[0]["time"],
                "last_seen": evidence[-1]["time"],
                "correlation_window_seconds": window_seconds,
                "classification_basis": "target-side-observations",
                "ttps": [],
            },
            run_id=run_id,
            target_id=target,
            incident_id=attack_id,
            evidence_ids=[str(item["event_id"]) for item in evidence],
            severity="high" if attack_type == "privileged_remote_login" else "medium",
            confidence=0.95 if attack_type == "privileged_remote_login" else 0.9,
            time=str(evidence[0]["time"]),
        ).to_dict()
        event["event_id"] = f"evt-{attack_id}"
        attacks.append(event)
    return attacks


def correlate_windows_privileged_logon(
    events: Iterable[dict[str, Any]],
    run_id: str,
    *,
    allowed_sources: set[str],
    not_before: str | None = None,
    window_seconds: int = 300,
) -> list[dict[str, Any]]:
    """Correlate a DC network logon with the matching privileged-logon event.

    The source allowlist and time floor are mandatory for the lab rule. A 4624
    alone is an authentication observation, not proof of privilege or intent.
    """
    if not allowed_sources or not not_before:
        return []
    floor = _epoch(not_before)
    logons: list[dict[str, Any]] = []
    privileges: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        if event.get("run_id") != run_id or event.get("event_type") != "defense.endpoint.windows_event":
            continue
        if event.get("target_id") != "win-dc01":
            continue
        payload = event.get("payload", {})
        if payload.get("channel") != "Security" or not isinstance(payload.get("event_data"), dict):
            continue
        data = payload["event_data"]
        observed = str(event.get("observed_time") or "")
        ingested = str(event.get("time") or "")
        if not observed or not ingested or _epoch(observed) < floor or _epoch(ingested) < floor:
            continue
        try:
            event_code = int(payload.get("event_id", 0))
        except (TypeError, ValueError):
            continue
        if event_code == 4624:
            if (str(data.get("LogonType")) != "3"
                    or str(data.get("TargetUserName", "")).casefold() != "administrator"
                    or str(data.get("IpAddress", "")) not in allowed_sources):
                continue
            logon_id = str(data.get("TargetLogonId", ""))
            if logon_id:
                logons.append(event)
        elif event_code == 4672 and str(data.get("SubjectUserName", "")).casefold() == "administrator":
            logon_id = str(data.get("SubjectLogonId", ""))
            if logon_id:
                privileges[(str(event["target_id"]), logon_id)] = event

    groups: dict[tuple[str, str, int], list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for logon in logons:
        data = logon["payload"]["event_data"]
        privilege = privileges.get((str(logon["target_id"]), str(data["TargetLogonId"])))
        if privilege is None:
            continue
        observed = str(logon["observed_time"])
        if abs(_epoch(str(privilege["observed_time"])) - _epoch(observed)) > 60:
            continue
        source = str(data["IpAddress"])
        bucket = int(_epoch(observed) // window_seconds)
        groups[(str(logon["target_id"]), source, bucket)].append((logon, privilege))

    attacks: list[dict[str, Any]] = []
    for (target, source, bucket), pairs in sorted(groups.items()):
        pairs.sort(key=lambda pair: str(pair[0]["observed_time"]))
        logon, privilege = pairs[0]
        attack_key = f"{run_id}:{target}:{source}:privileged-network-logon:{bucket}"
        attack_id = "attack-" + hashlib.sha256(attack_key.encode("utf-8")).hexdigest()[:24]
        observed = str(logon["observed_time"])
        first_ingested = max(_epoch(str(logon["time"])), _epoch(str(privilege["time"])))
        event = AuditEvent(
            event_type="defense.attack.detected",
            actor={"type": "agent", "id": "windows-auth-correlator"},
            payload={
                "attack_id": attack_id,
                "attack_type": "privileged_network_logon",
                "outcome": "observed",
                "source_ip": source,
                "account": "Administrator",
                "logon_type": 3,
                "logon_id": str(logon["payload"]["event_data"]["TargetLogonId"]),
                "first_seen": observed,
                "signal_count": 2,
                "observation_delay_seconds": round(first_ingested - _epoch(observed), 3),
                "classification_basis": "windows-security-4624-4672-matched-logon-id",
                "ttps": [],
            },
            run_id=run_id,
            target_id=target,
            incident_id=attack_id,
            evidence_ids=[str(logon["event_id"]), str(privilege["event_id"])],
            severity="high",
            confidence=0.98,
            observed_time=observed,
        ).to_dict()
        event["event_id"] = f"evt-{attack_id}"
        attacks.append(event)
    return attacks


def correlate_windows_privileged_logon_bursts(
    events: Iterable[dict[str, Any]],
    run_id: str,
    *,
    allowed_sources: set[str],
    not_before: str | None = None,
    window_seconds: int = 30,
    minimum_logons: int = 3,
) -> list[dict[str, Any]]:
    """Alert on repeated *paired* DC admin network logons from one source.

    This is a generic automation signal, not an ARTEX fingerprint. It is
    deliberately monitoring-only; the first paired logon already drives the
    lab's narrowly scoped SMB response.
    """
    if not allowed_sources or not not_before or window_seconds <= 0 or minimum_logons < 2:
        return []
    floor = _epoch(not_before)
    logons: dict[tuple[str, str], dict[str, Any]] = {}
    privileges: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        if (event.get("run_id") != run_id
                or event.get("event_type") != "defense.endpoint.windows_event"
                or event.get("target_id") != "win-dc01"):
            continue
        payload = event.get("payload", {})
        if payload.get("channel") != "Security" or not isinstance(payload.get("event_data"), dict):
            continue
        observed = str(event.get("observed_time") or "")
        ingested = str(event.get("time") or "")
        if not observed or not ingested or _epoch(observed) < floor or _epoch(ingested) < floor:
            continue
        data = payload["event_data"]
        try:
            code = int(payload.get("event_id", 0))
        except (TypeError, ValueError):
            continue
        if code == 4624:
            if (str(data.get("LogonType")) != "3"
                    or str(data.get("TargetUserName", "")).casefold() != "administrator"
                    or str(data.get("IpAddress", "")) not in allowed_sources):
                continue
            logon_id = str(data.get("TargetLogonId", ""))
            if logon_id:
                logons[("win-dc01", logon_id)] = event
        elif code == 4672 and str(data.get("SubjectUserName", "")).casefold() == "administrator":
            logon_id = str(data.get("SubjectLogonId", ""))
            if logon_id:
                privileges[("win-dc01", logon_id)] = event

    grouped: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for key, logon in logons.items():
        privilege = privileges.get(key)
        if privilege is None:
            continue
        if abs(_epoch(str(privilege["observed_time"])) - _epoch(str(logon["observed_time"]))) > 60:
            continue
        source = str(logon["payload"]["event_data"]["IpAddress"])
        grouped[source].append((logon, privilege))

    attacks: list[dict[str, Any]] = []
    for source, pairs in sorted(grouped.items()):
        pairs.sort(key=lambda pair: str(pair[0]["observed_time"]))
        index = 0
        while index + minimum_logons <= len(pairs):
            first = pairs[index]
            last = pairs[index + minimum_logons - 1]
            span = _epoch(str(last[0]["observed_time"])) - _epoch(str(first[0]["observed_time"]))
            if span > window_seconds:
                index += 1
                continue
            cluster = pairs[index:index + minimum_logons]
            first_time = str(first[0]["observed_time"])
            first_logon_id = str(first[0]["payload"]["event_data"]["TargetLogonId"])
            attack_key = f"{run_id}:win-dc01:{source}:privileged-logon-burst:{first_logon_id}"
            attack_id = "attack-" + hashlib.sha256(attack_key.encode("utf-8")).hexdigest()[:24]
            evidence_ids = [str(item["event_id"]) for pair in cluster for item in pair]
            event = AuditEvent(
                event_type="defense.attack.detected",
                actor={"type": "agent", "id": "windows-auth-correlator"},
                payload={
                    "attack_id": attack_id,
                    "attack_type": "privileged_network_logon_burst",
                    "outcome": "observed",
                    "source_ip": source,
                    "account": "Administrator",
                    "successful_logons": len(cluster),
                    "first_seen": first_time,
                    "last_seen": str(last[0]["observed_time"]),
                    "span_seconds": round(span, 3),
                    "correlation_window_seconds": window_seconds,
                    "classification_basis": "windows-security-4624-4672-matched-logon-id-burst",
                    "framework_attribution": "unknown",
                    "auto_block_eligible": False,
                    "ttps": [{"id": "T1078.002", "name": "Domain Accounts"}],
                },
                run_id=run_id,
                target_id="win-dc01",
                incident_id=attack_id,
                evidence_ids=evidence_ids,
                severity="high",
                confidence=0.9,
                observed_time=first_time,
            ).to_dict()
            event["event_id"] = f"evt-{attack_id}"
            attacks.append(event)
            index += len(cluster)
            while index < len(pairs) and _epoch(str(pairs[index][0]["observed_time"])) - _epoch(first_time) <= window_seconds:
                index += 1
    return attacks


def correlate_windows_failed_logon_bursts(
    events: Iterable[dict[str, Any]],
    run_id: str,
    *,
    allowed_sources: set[str],
    not_before: str | None = None,
    window_seconds: int = 60,
    minimum_failures: int = 10,
) -> list[dict[str, Any]]:
    """Emit an alert-only signal for repeated target-observed network failures.

    A separate activation floor prevents historical event-store replay from
    appearing as a live alert after this rule is deployed.
    """
    if not allowed_sources or not not_before or window_seconds <= 0 or minimum_failures < 2:
        return []
    floor = _epoch(not_before)
    groups: dict[tuple[str, str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
    for event in events:
        if event.get("run_id") != run_id or event.get("event_type") != "defense.endpoint.windows_event":
            continue
        target = str(event.get("target_id") or "")
        if target not in {"win-dc01", "win-client01"}:
            continue
        payload = event.get("payload", {})
        if payload.get("channel") != "Security" or str(payload.get("event_id")) != "4625":
            continue
        data = payload.get("event_data")
        if not isinstance(data, dict) or str(data.get("LogonType")) != "3":
            continue
        source = str(data.get("IpAddress") or "")
        if source not in allowed_sources:
            continue
        observed = str(event.get("observed_time") or "")
        ingested = str(event.get("time") or "")
        if not observed or not ingested or _epoch(observed) < floor or _epoch(ingested) < floor:
            continue
        bucket = int(_epoch(observed) // window_seconds)
        event_id = str(event.get("event_id") or "")
        if event_id:
            groups[(target, source, bucket)][event_id] = event

    attacks: list[dict[str, Any]] = []
    for (target, source, bucket), by_id in sorted(groups.items()):
        evidence = sorted(by_id.values(), key=lambda item: (str(item["observed_time"]), str(item["event_id"])))
        if len(evidence) < minimum_failures:
            continue
        first = evidence[:minimum_failures]
        first_seen = str(first[0]["observed_time"])
        crossed_at = str(first[-1]["observed_time"])
        accounts = {name for item in first
                    if (name := str(item["payload"]["event_data"].get("TargetUserName") or ""))}
        attack_key = f"{run_id}:{target}:{source}:failed-logon-burst:{bucket}"
        attack_id = "attack-" + hashlib.sha256(attack_key.encode("utf-8")).hexdigest()[:24]
        event = AuditEvent(
            event_type="defense.attack.detected",
            actor={"type": "agent", "id": "windows-auth-correlator"},
            payload={
                "attack_id": attack_id,
                "attack_type": "windows_failed_logon_burst",
                "outcome": "observed",
                "source_ip": source,
                "failed_logons": minimum_failures,
                "distinct_accounts_at_threshold": len(accounts),
                "first_seen": first_seen,
                "threshold_reached_at": crossed_at,
                "correlation_window_seconds": window_seconds,
                "classification_basis": "windows-security-4625-network-logon-burst",
                "framework_attribution": "unknown",
                "auto_block_eligible": False,
                "ttps": [{"id": "T1110", "name": "Brute Force"}],
            },
            run_id=run_id,
            target_id=target,
            incident_id=attack_id,
            evidence_ids=[str(item["event_id"]) for item in first],
            severity="medium",
            confidence=0.88,
            observed_time=crossed_at,
        ).to_dict()
        event["event_id"] = f"evt-{attack_id}"
        attacks.append(event)
    return attacks
