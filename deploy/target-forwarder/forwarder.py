from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


SOURCES = {
    "traefik": Path("/opt/ctf-stack/logs/traefik/access.jsonl"),
    "falco": Path("/opt/ctf-stack/logs/falco/events.jsonl"),
}


def load_checkpoints(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    return {str(key): int(offset) for key, offset in value.items()}


def save_checkpoints(path: Path, checkpoints: dict[str, int]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(checkpoints, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def send_record(base_url: str, token: str, run_id: str, sensor: str, record: dict[str, Any]) -> None:
    query = urllib.parse.urlencode({"run_id": run_id})
    request = urllib.request.Request(
        f"{base_url}/v1/sensors/{sensor}?{query}",
        data=json.dumps(record).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status not in {200, 201}:
            raise RuntimeError(f"gateway returned {response.status}")


def main() -> None:
    base_url = os.environ.get("DEFENSA_GATEWAY_URL", "http://127.0.0.1:8080").rstrip("/")
    token = os.environ.get("DEFENSA_GATEWAY_TOKEN", "")
    run_id = os.environ.get("DEFENSA_RUN_ID", "live")
    checkpoint_path = Path(os.environ.get("DEFENSA_FORWARDER_CHECKPOINT", "/var/lib/defensa-forwarder/checkpoints.json"))
    poll_seconds = float(os.environ.get("DEFENSA_FORWARDER_POLL_SECONDS", "1"))
    from_end = os.environ.get("DEFENSA_FORWARD_FROM_END", "true").lower() == "true"
    if not token:
        raise SystemExit("DEFENSA_GATEWAY_TOKEN is required")
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoints = load_checkpoints(checkpoint_path)

    for sensor, source in SOURCES.items():
        if sensor not in checkpoints and source.exists():
            checkpoints[sensor] = source.stat().st_size if from_end else 0
    save_checkpoints(checkpoint_path, checkpoints)

    while True:
        for sensor, source in SOURCES.items():
            if not source.exists():
                continue
            offset = checkpoints.get(sensor, 0)
            if source.stat().st_size < offset:
                offset = 0
            with source.open(encoding="utf-8") as handle:
                handle.seek(offset)
                while True:
                    record_start = handle.tell()
                    line = handle.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        handle.seek(record_start)
                        break
                    try:
                        value = json.loads(line)
                        if not isinstance(value, dict):
                            raise ValueError("record is not an object")
                        send_record(base_url, token, run_id, sensor, value)
                    except (json.JSONDecodeError, ValueError) as exc:
                        print(f"invalid {sensor} record at byte {record_start}: {type(exc).__name__}", flush=True)
                    except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
                        print(f"forwarding {sensor} failed: {type(exc).__name__}", flush=True)
                        handle.seek(record_start)
                        break
                    checkpoints[sensor] = handle.tell()
                    save_checkpoints(checkpoint_path, checkpoints)
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()

