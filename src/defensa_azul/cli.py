from __future__ import annotations

import argparse
import json
from pathlib import Path

from .attacks import correlate_runtime_attacks
from .event_store import JsonlEventStore
from .models import ActionProposal, AuditEvent
from .policy import SafetyGate
from .reporting import build_report, write_report
from .sensors import NORMALIZERS, read_jsonl


def _json_file(path: str) -> dict:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> None:
    parser = argparse.ArgumentParser(prog="defensa-azul")
    parser.add_argument("--event-store", default="data/events.jsonl")
    commands = parser.add_subparsers(dest="command", required=True)

    append = commands.add_parser("append", help="Append a typed event from JSON")
    append.add_argument("event")

    verify = commands.add_parser("verify", help="Verify the JSONL hash chain")
    verify.set_defaults(command="verify")

    evaluate = commands.add_parser("evaluate", help="Evaluate and audit an action proposal")
    evaluate.add_argument("proposal")
    evaluate.add_argument("--policy", default="policies/global.json")

    report = commands.add_parser("report", help="Generate JSON and Markdown run reports")
    report.add_argument("run_id")
    report.add_argument("--output-dir", default="reports")

    ingest = commands.add_parser("ingest", help="Normalize a sensor JSONL file into the audit store")
    ingest.add_argument("--sensor", choices=sorted(NORMALIZERS), required=True)
    ingest.add_argument("--input", required=True)
    ingest.add_argument("--run-id", required=True)

    correlate = commands.add_parser("correlate-attacks", help="Create deduplicated attack records")
    correlate.add_argument("run_id")
    correlate.add_argument("--window-seconds", type=int, default=300)

    args = parser.parse_args()
    store = JsonlEventStore(args.event_store)

    if args.command == "append":
        raw = _json_file(args.event)
        event = AuditEvent(**raw).to_dict()
        print(json.dumps(store.append(event), indent=2, sort_keys=True))
        return
    if args.command == "verify":
        issues = store.verify()
        print(json.dumps({"valid": not issues, "issues": issues}, indent=2))
        raise SystemExit(1 if issues else 0)
    if args.command == "evaluate":
        proposal = ActionProposal.from_dict(_json_file(args.proposal))
        proposal_event = AuditEvent(
            event_type="defense.proposal",
            actor={"type": "agent", "id": "response-planner"},
            payload=proposal.to_dict(),
            run_id=proposal.run_id,
            target_id=proposal.target_id,
            incident_id=proposal.incident_id,
            evidence_ids=proposal.evidence_ids,
            confidence=proposal.confidence,
        )
        store.append(proposal_event.to_dict())
        decision = SafetyGate.from_file(args.policy).evaluate(proposal)
        decision_event = AuditEvent(
            event_type="defense.decision",
            actor={"type": "policy-gate", "id": "safety-gate"},
            payload={"proposal_id": proposal.proposal_id, **decision.to_dict()},
            run_id=proposal.run_id,
            target_id=proposal.target_id,
            incident_id=proposal.incident_id,
            evidence_ids=proposal.evidence_ids,
        )
        appended = store.append(decision_event.to_dict())
        print(json.dumps(appended, indent=2, sort_keys=True))
        return
    if args.command == "report":
        generated = build_report(store.read(), args.run_id)
        paths = write_report(generated, args.output_dir)
        print(json.dumps({"json": str(paths[0]), "markdown": str(paths[1])}, indent=2))
        return
    if args.command == "ingest":
        normalizer = NORMALIZERS[args.sensor]
        existing_ids = {event.get("event_id") for event in store.read()}
        appended = 0
        skipped = 0
        for record in read_jsonl(args.input):
            event = normalizer(record, args.run_id)
            if event["event_id"] in existing_ids:
                skipped += 1
                continue
            store.append(event)
            existing_ids.add(event["event_id"])
            appended += 1
        print(json.dumps({"appended": appended, "skipped_duplicates": skipped}, indent=2))
        return
    if args.command == "correlate-attacks":
        existing_ids = {event.get("event_id") for event in store.read()}
        attacks = correlate_runtime_attacks(store.read(), args.run_id, window_seconds=args.window_seconds)
        appended = 0
        skipped = 0
        for event in attacks:
            if event["event_id"] in existing_ids:
                skipped += 1
                continue
            store.append(event)
            existing_ids.add(event["event_id"])
            appended += 1
        print(json.dumps({"attacks_appended": appended, "skipped_duplicates": skipped}, indent=2))


if __name__ == "__main__":
    main()
