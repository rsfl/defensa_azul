#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
export_dir="${1:-$project_dir/exports}"
run_id="${DEFENSA_RUN_ID:-live-20260917}"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
key="${DEFENSA_SSH_KEY:?set DEFENSA_SSH_KEY}"
host="${DEFENSA_AGENT_SSH_HOST:?set DEFENSA_AGENT_SSH_HOST, for example root@xxx.xxx.xxx.xxx}"
gateway_host="${DEFENSA_REMOTE_GATEWAY_HOST:-127.0.0.1}"
gateway_port="${DEFENSA_REMOTE_GATEWAY_PORT:-8080}"
known_hosts=/tmp/defensa-azul-agent-known-hosts

mkdir -p "$export_dir"

events_path="$export_dir/${run_id}-${stamp}.jsonl"
report_path="$export_dir/${run_id}-${stamp}-report.json"

scp -q \
  -F /dev/null \
  -i "$key" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile="$known_hosts" \
  "$host:/var/lib/docker/volumes/defensa-azul_defensa-data/_data/events.jsonl" \
  "$events_path"

ssh \
  -F /dev/null \
  -i "$key" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile="$known_hosts" \
  "$host" \
  "set -a; . /etc/defensa-azul/defensa.env; set +a; curl -fsS -H \"Authorization: Bearer \$DEFENSA_GATEWAY_TOKEN\" \"http://$gateway_host:$gateway_port/v1/report?run_id=$run_id\"" \
  >"$report_path"

chmod 600 "$events_path" "$report_path"
printf 'events=%s\nreport=%s\n' "$events_path" "$report_path"
