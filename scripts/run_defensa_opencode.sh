#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

set -a
. "$project_dir/.env"
set +a

if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo "OPENAI_API_KEY is required" >&2
  exit 1
fi

gateway_secret="$project_dir/.secrets/defensa_gateway_token"
if [ ! -s "$gateway_secret" ]; then
  echo "Gateway token is not deployed yet: $gateway_secret" >&2
  exit 1
fi

export DEFENSA_GATEWAY_TOKEN
DEFENSA_GATEWAY_TOKEN=$(<"$gateway_secret")
export DEFENSA_GATEWAY_URL="http://127.0.0.1:18080"

ssh_key="${DEFENSA_SSH_KEY:?set DEFENSA_SSH_KEY}"
agent_ssh_host="${DEFENSA_AGENT_SSH_HOST:?set DEFENSA_AGENT_SSH_HOST, for example root@xxx.xxx.xxx.xxx}"
remote_gateway_host="${DEFENSA_REMOTE_GATEWAY_HOST:-127.0.0.1}"
remote_gateway_port="${DEFENSA_REMOTE_GATEWAY_PORT:-8080}"

ssh -F /dev/null \
  -i "$ssh_key" \
  -o BatchMode=yes \
  -o ExitOnForwardFailure=yes \
  -o StrictHostKeyChecking=accept-new \
  -o ServerAliveInterval=30 \
  -o UserKnownHostsFile=/tmp/defensa-azul-agent-known-hosts \
  -N -L "18080:$remote_gateway_host:$remote_gateway_port" "$agent_ssh_host" &
tunnel_pid=$!
trap 'kill "$tunnel_pid" 2>/dev/null || true' EXIT INT TERM

sleep 1
cd "$project_dir"
exec opencode . --agent defensa_azul_agent
