from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import ssl
from pathlib import Path

from .event_store import JsonlEventStore
from .integrations import to_splunk_hec


def collector_url(base_url: str) -> str:
    value = base_url.rstrip("/")
    if value.endswith("/services/collector/event"):
        return value
    return f"{value}/services/collector/event"


def _verify_tls() -> bool:
    return os.environ.get("SPLUNK_HEC_VERIFY_TLS", "true").lower() not in {"0", "false", "no"}


def send_hec(event: dict, *, url: str, token: str, host: str, index: str | None) -> None:
    request = urllib.request.Request(
        collector_url(url),
        data=json.dumps(to_splunk_hec(event, host=host, index=index)).encode("utf-8"),
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
            "User-Agent": "DefensaAzul/0.1",
        },
        method="POST",
    )
    context = None if _verify_tls() else ssl._create_unverified_context()
    with urllib.request.urlopen(request, timeout=15, context=context) as response:
        if response.status not in {200, 201}:
            raise RuntimeError(f"Splunk HEC returned status {response.status}")


def main() -> None:
    url = os.environ.get("SPLUNK_HEC_URL", "")
    token = os.environ.get("SPLUNK_HEC_TOKEN", "")
    if not url or not token:
        raise SystemExit("SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN are required")
    host = os.environ.get("SPLUNK_HEC_HOST", "defense-agent-host")
    index = os.environ.get("SPLUNK_HEC_INDEX") or None
    store = JsonlEventStore(os.environ.get("DEFENSA_EVENT_STORE", "/data/events.jsonl"))
    checkpoint_path = Path(os.environ.get("DEFENSA_SPLUNK_CHECKPOINT", "/data/splunk.checkpoint"))
    interval = float(os.environ.get("DEFENSA_SPLUNK_POLL_SECONDS", "2"))

    while True:
        checkpoint = int(checkpoint_path.read_text().strip() or "0") if checkpoint_path.exists() else 0
        for event in store.read():
            sequence = int(event.get("integrity", {}).get("sequence", 0))
            if sequence <= checkpoint:
                continue
            try:
                send_hec(event, url=url, token=token, host=host, index=index)
            except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
                print(f"Splunk export failed at sequence {sequence}: {type(exc).__name__}", flush=True)
                time.sleep(min(interval * 2, 30))
                break
            checkpoint_path.write_text(f"{sequence}\n", encoding="utf-8")
        time.sleep(interval)


if __name__ == "__main__":
    main()
