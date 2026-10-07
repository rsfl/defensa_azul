from __future__ import annotations

import json
import os
import sys

from forwarder import SOURCES, send_record


def record_time(sensor: str, value: dict) -> str:
    if sensor == "traefik":
        return str(value.get("StartUTC") or value.get("time") or "")
    return str(value.get("time") or "")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: replay_since.py ISO8601_CUTOFF")
    cutoff = sys.argv[1]
    base_url = os.environ["DEFENSA_GATEWAY_URL"].rstrip("/")
    token = os.environ["DEFENSA_GATEWAY_TOKEN"]
    run_id = os.environ.get("DEFENSA_RUN_ID", "live")
    counts: dict[str, int] = {}
    for sensor, source in SOURCES.items():
        sent = 0
        with source.open(encoding="utf-8") as handle:
            for line in handle:
                value = json.loads(line)
                if isinstance(value, dict) and record_time(sensor, value) >= cutoff:
                    send_record(base_url, token, run_id, sensor, value)
                    sent += 1
        counts[sensor] = sent
    print(json.dumps({"cutoff": cutoff, "records_replayed": counts}, sort_keys=True))


if __name__ == "__main__":
    main()
