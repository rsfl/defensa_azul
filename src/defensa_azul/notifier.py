from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from .event_store import JsonlEventStore
from .integrations import to_discord_summary


NOTIFY_TYPES = {
    "defense.deployment.ready",
    "defense.attack.detected",
    "defense.incident.opened",
    "defense.proposal",
    "defense.decision",
    "defense.action.result",
    "defense.rollback",
    "defense.health.degraded",
    "defense.evaluation.miss",
}


def send_discord(event: dict, bot_token: str, channel_id: str) -> None:
    url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
    request = urllib.request.Request(
        url,
        data=json.dumps(to_discord_summary(event)).encode("utf-8"),
        headers={
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json",
            "User-Agent": "DefensaAzul/0.1",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status not in {200, 201, 204}:
            raise RuntimeError(f"Discord returned status {response.status}")


def main() -> None:
    bot_token = os.environ.get("DISCORD_BOT_TOKEN", "")
    channel_id = os.environ.get("DISCORD_CHANNEL_ID", "")
    if not bot_token or not channel_id:
        raise SystemExit("DISCORD_BOT_TOKEN and DISCORD_CHANNEL_ID are required")
    store = JsonlEventStore(os.environ.get("DEFENSA_EVENT_STORE", "/data/events.jsonl"))
    checkpoint_path = Path(os.environ.get("DEFENSA_DISCORD_CHECKPOINT", "/data/discord.checkpoint"))
    interval = float(os.environ.get("DEFENSA_NOTIFY_POLL_SECONDS", "2"))

    while True:
        checkpoint = int(checkpoint_path.read_text().strip() or "0") if checkpoint_path.exists() else 0
        for event in store.read():
            sequence = int(event.get("integrity", {}).get("sequence", 0))
            if sequence <= checkpoint:
                continue
            if event.get("event_type") in NOTIFY_TYPES:
                try:
                    send_discord(event, bot_token, channel_id)
                except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
                    print(f"Discord notification failed at sequence {sequence}: {type(exc).__name__}", flush=True)
                    time.sleep(min(interval * 2, 30))
                    break
            checkpoint_path.write_text(f"{sequence}\n", encoding="utf-8")
        time.sleep(interval)


if __name__ == "__main__":
    main()
