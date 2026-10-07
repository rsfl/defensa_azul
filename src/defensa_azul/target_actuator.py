from __future__ import annotations

import hmac
import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


TARGET_CONTAINERS = {
    "target-web-01": "target-stack-target-web-01-1",
    "target-web-05": "target-stack-target-web-05-1",
}
ALLOWED_PROCESSES = {"sh", "bash", "dash"}
MAX_TTL_SECONDS = 15


class ActionRejected(ValueError):
    pass


class TargetActuator:
    def __init__(
        self,
        *,
        proc_root: str | Path = "/proc",
        inspect_container: Callable[[str], str] | None = None,
        send_signal: Callable[[int, int], None] = os.kill,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        schedule_resume: Callable[[int, str, int], None] | None = None,
        cooldown_seconds: int = 60,
    ):
        self.proc_root = Path(proc_root)
        self.inspect_container = inspect_container or self._docker_container_id
        self.send_signal = send_signal
        self.sleep = sleep
        self.monotonic = monotonic
        self.schedule_resume = schedule_resume or self._schedule_resume_watchdog
        self.cooldown_seconds = cooldown_seconds
        self._lock = threading.Lock()
        self._last_action: dict[str, float] = {}

    def _schedule_resume_watchdog(self, host_pid: int, start_time: str, ttl: int) -> None:
        subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--resume-watchdog",
                str(host_pid),
                start_time,
                str(ttl),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )

    @staticmethod
    def _docker_container_id(container_name: str) -> str:
        result = subprocess.run(
            ["docker", "inspect", "--format={{.Id}}", container_name],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip()

    def _read_process(self, host_pid: int) -> tuple[str, str, str]:
        process_dir = self.proc_root / str(host_pid)
        try:
            comm = (process_dir / "comm").read_text(encoding="utf-8").strip()
            cgroup = (process_dir / "cgroup").read_text(encoding="utf-8")
            stat = (process_dir / "stat").read_text(encoding="utf-8")
        except (FileNotFoundError, PermissionError) as exc:
            raise ActionRejected("process is no longer available") from exc
        fields = stat.split()
        if len(fields) < 22:
            raise ActionRejected("process identity cannot be verified")
        return comm, cgroup, fields[21]

    def _validate(self, request: dict[str, Any]) -> tuple[str, int, int, str, str]:
        if request.get("action_type") != "suspend_process":
            raise ActionRejected("action type is not allowlisted")
        target_id = str(request.get("target_id", ""))
        expected_name = TARGET_CONTAINERS.get(target_id)
        if expected_name is None:
            raise ActionRejected("target is not enforce-enabled")
        try:
            ttl = int(request.get("ttl_seconds", 0))
            host_pid = int(request.get("host_pid", 0))
        except (TypeError, ValueError) as exc:
            raise ActionRejected("TTL and host PID must be integers") from exc
        if not 1 <= ttl <= MAX_TTL_SECONDS:
            raise ActionRejected("TTL is outside the allowed range")
        if host_pid <= 1:
            raise ActionRejected("host PID must be greater than one")
        if request.get("process") not in ALLOWED_PROCESSES:
            raise ActionRejected("process is not an allowlisted shell")
        if request.get("container_name") != expected_name:
            raise ActionRejected("container name does not match target")

        live_container_id = self.inspect_container(expected_name)
        observed_container_id = str(request.get("container_id", ""))
        if len(observed_container_id) < 12 or not live_container_id.startswith(observed_container_id):
            raise ActionRejected("container identity is stale or mismatched")
        comm, cgroup, start_time = self._read_process(host_pid)
        if comm not in ALLOWED_PROCESSES or comm != request.get("process"):
            raise ActionRejected("live process name does not match evidence")
        if live_container_id not in cgroup and live_container_id[:12] not in cgroup:
            raise ActionRejected("PID is not in the allowlisted container")
        return target_id, host_pid, ttl, live_container_id, start_time

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        target_id, host_pid, ttl, container_id, start_time = self._validate(request)
        if not self._lock.acquire(blocking=False):
            raise ActionRejected("another defensive action is active")
        stopped = False
        try:
            now = self.monotonic()
            if now - self._last_action.get(target_id, float("-inf")) < self.cooldown_seconds:
                raise ActionRejected("target action cooldown is active")
            _, _, current_start_time = self._read_process(host_pid)
            if current_start_time != start_time:
                raise ActionRejected("PID was reused before action")
            self.schedule_resume(host_pid, start_time, ttl)
            self.send_signal(host_pid, signal.SIGSTOP)
            stopped = True
            self._last_action[target_id] = now
            self.sleep(ttl)
            return {
                "status": "executed",
                "target_id": target_id,
                "host_pid": host_pid,
                "container_id": container_id[:12],
                "ttl_seconds": ttl,
                "rollback": "completed",
            }
        finally:
            if stopped:
                try:
                    self.send_signal(host_pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass
            self._lock.release()


class ActuatorHandler(BaseHTTPRequestHandler):
    server_version = "DefensaAzulTargetActuator/0.1"

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"status": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/actions":
            self._json(404, {"status": "not_found"})
            return
        expected = f"Bearer {self.server.token}"  # type: ignore[attr-defined]
        if not hmac.compare_digest(self.headers.get("Authorization", ""), expected):
            self._json(401, {"status": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 8192:
                raise ActionRejected("request size is invalid")
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise ActionRejected("request must be a JSON object")
            result = self.server.actuator.execute(value)  # type: ignore[attr-defined]
            self._json(200, result)
        except ActionRejected as exc:
            self._json(409, {"status": "rejected", "reason": str(exc)})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"status": "invalid_json"})
        except (OSError, subprocess.SubprocessError) as exc:
            self._json(503, {"status": "failed", "error_type": type(exc).__name__})

    def log_message(self, message: str, *args: Any) -> None:
        print(f"target-actuator {self.address_string()} {message % args}", flush=True)


def main() -> None:
    token = os.environ.get("DEFENSA_ACTUATOR_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("DEFENSA_ACTUATOR_TOKEN must contain at least 32 characters")
    host = os.environ.get("DEFENSA_ACTUATOR_HOST", "127.0.0.1")
    port = int(os.environ.get("DEFENSA_ACTUATOR_PORT", "9091"))
    server = ThreadingHTTPServer((host, port), ActuatorHandler)
    server.token = token  # type: ignore[attr-defined]
    server.actuator = TargetActuator()  # type: ignore[attr-defined]
    server.serve_forever()


def resume_watchdog(host_pid: int, start_time: str, ttl: int) -> None:
    time.sleep(ttl + 0.25)
    try:
        fields = (Path("/proc") / str(host_pid) / "stat").read_text(encoding="utf-8").split()
        if len(fields) >= 22 and fields[21] == start_time:
            os.kill(host_pid, signal.SIGCONT)
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--resume-watchdog":
        resume_watchdog(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    else:
        main()
