#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
key="${DEFENSA_SSH_KEY:?set DEFENSA_SSH_KEY}"
agent="${DEFENSA_AGENT_SSH_HOST:?set DEFENSA_AGENT_SSH_HOST, for example root@xxx.xxx.xxx.xxx}"
target="${DEFENSA_TARGET_SSH_HOST:?set DEFENSA_TARGET_SSH_HOST, for example root@xxx.xxx.xxx.xxx}"
target_firewall_id="${DEFENSA_TARGET_FIREWALL_ID:?set DEFENSA_TARGET_FIREWALL_ID}"
agent_firewall_id="${DEFENSA_AGENT_FIREWALL_ID:?set DEFENSA_AGENT_FIREWALL_ID}"
agent_droplet_id="${DEFENSA_AGENT_DROPLET_ID:?set DEFENSA_AGENT_DROPLET_ID}"
target_droplet_id="${DEFENSA_TARGET_DROPLET_ID:?set DEFENSA_TARGET_DROPLET_ID}"
agent_private_cidr="${DEFENSA_AGENT_PRIVATE_CIDR:?set DEFENSA_AGENT_PRIVATE_CIDR, for example xxx.xxx.xxx.xxx/32}"
target_private_cidr="${DEFENSA_TARGET_PRIVATE_CIDR:?set DEFENSA_TARGET_PRIVATE_CIDR, for example xxx.xxx.xxx.xxx/32}"
target_actuator_host="${DEFENSA_TARGET_ACTUATOR_HOST:?set DEFENSA_TARGET_ACTUATOR_HOST, for example xxx.xxx.xxx.xxx}"
ssh_options=(-F /dev/null -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
secret_file=$(mktemp /tmp/defensa-actuator-token.XXXXXX)

cleanup() {
  shred -u "$secret_file" 2>/dev/null || true
}
trap cleanup EXIT

openssl rand -hex -out "$secret_file" 32
chmod 600 "$secret_file"

scp -q "${ssh_options[@]}" \
  "$project_dir/src/defensa_azul/target_actuator.py" \
  "$target:/tmp/target_actuator.py"
scp -q "${ssh_options[@]}" \
  "$project_dir/deploy/target-actuator/defensa-target-actuator.service" \
  "$target:/tmp/defensa-target-actuator.service"
scp -q "${ssh_options[@]}" "$secret_file" "$target:/tmp/defensa-actuator-token"

ssh "${ssh_options[@]}" "$target" \
  "install -d -m 0755 /opt/defensa-target-actuator; install -m 0644 /tmp/target_actuator.py /opt/defensa-target-actuator/target_actuator.py; install -m 0644 /tmp/defensa-target-actuator.service /etc/systemd/system/defensa-target-actuator.service; DEFENSA_TARGET_ACTUATOR_HOST='$target_actuator_host' python3 -c 'import os; from pathlib import Path; token=Path(\"/tmp/defensa-actuator-token\").read_text().strip(); host=os.environ[\"DEFENSA_TARGET_ACTUATOR_HOST\"]; p=Path(\"/etc/defensa-target-actuator.env\"); p.write_text(\"DEFENSA_ACTUATOR_TOKEN=\"+token+\"\\nDEFENSA_ACTUATOR_HOST=\"+host+\"\\nDEFENSA_ACTUATOR_PORT=9091\\n\", encoding=\"utf-8\"); p.chmod(0o600); Path(\"/tmp/defensa-actuator-token\").unlink()'; systemctl daemon-reload; systemctl enable --now defensa-target-actuator.service"

scp -q "${ssh_options[@]}" "$secret_file" "$agent:/tmp/defensa-actuator-token"
scp -q "${ssh_options[@]}" \
  "$project_dir/compose.yaml" "$project_dir/Dockerfile" "$project_dir/pyproject.toml" \
  "$project_dir/README.md" "$agent:/opt/defensa-azul/"
scp -q -r "${ssh_options[@]}" "$project_dir/src" "$agent:/opt/defensa-azul/"
scp -q "${ssh_options[@]}" "$project_dir/policies/global.json" "$agent:/opt/defensa-azul/policies/global.json"

ssh "${ssh_options[@]}" "$agent" \
  "DEFENSA_TARGET_ACTUATOR_HOST='$target_actuator_host' python3 -c 'import os; from pathlib import Path; token=Path(\"/tmp/defensa-actuator-token\").read_text().strip(); host=os.environ[\"DEFENSA_TARGET_ACTUATOR_HOST\"]; p=Path(\"/etc/defensa-azul/defensa.env\"); lines=[line for line in p.read_text(encoding=\"utf-8\").splitlines() if not line.startswith((\"DEFENSA_ACTUATOR_TOKEN=\", \"DEFENSA_TARGET_ACTUATOR_URL=\"))]; p.write_text(\"\\n\".join(lines+[\"DEFENSA_ACTUATOR_TOKEN=\"+token, \"DEFENSA_TARGET_ACTUATOR_URL=http://\"+host+\":9091\"])+\"\\n\", encoding=\"utf-8\"); p.chmod(0o600); Path(\"/tmp/defensa-actuator-token\").unlink()'"

set -a
# shellcheck disable=SC1091
. "$project_dir/.env"
set +a
firewall_json=$(curl -fsS \
  --connect-timeout 5 --max-time 15 \
  -H "Authorization: Bearer $DIGITALOCEAN_ACCESS_TOKEN" \
  "https://api.digitalocean.com/v2/firewalls/$target_firewall_id")
if ! jq -e --argjson droplet "$agent_droplet_id" \
  '.firewall.inbound_rules[] | select(.protocol == "tcp" and .ports == "9091" and (.sources.droplet_ids // [] | index($droplet)))' \
  >/dev/null <<<"$firewall_json"; then
  response_code=$(curl -sS -o /tmp/defensa-firewall-response.json -w '%{http_code}' \
    --connect-timeout 5 --max-time 15 \
    -X POST \
    -H "Authorization: Bearer $DIGITALOCEAN_ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"inbound_rules\":[{\"protocol\":\"tcp\",\"ports\":\"9091\",\"action\":\"allow\",\"sources\":{\"droplet_ids\":[$agent_droplet_id]}}]}" \
    "https://api.digitalocean.com/v2/firewalls/$target_firewall_id/rules")
  if [[ "$response_code" != "204" ]]; then
    printf 'Firewall update failed with HTTP %s\n' "$response_code" >&2
    exit 1
  fi
fi
if ! jq -e \
  --arg cidr "$agent_private_cidr" \
  '.firewall.inbound_rules[] | select(.protocol == "tcp" and .ports == "9091" and (.sources.addresses // [] | index($cidr)))' \
  >/dev/null <<<"$firewall_json"; then
  response_code=$(curl -sS -o /tmp/defensa-firewall-private-response.json -w '%{http_code}' \
    --connect-timeout 5 --max-time 15 \
    -X POST \
    -H "Authorization: Bearer $DIGITALOCEAN_ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"inbound_rules\":[{\"protocol\":\"tcp\",\"ports\":\"9091\",\"action\":\"allow\",\"sources\":{\"addresses\":[\"$agent_private_cidr\"]}}]}" \
    "https://api.digitalocean.com/v2/firewalls/$target_firewall_id/rules")
  test "$response_code" = "204"
fi
agent_firewall_json=$(curl -fsS \
  --connect-timeout 5 --max-time 15 \
  -H "Authorization: Bearer $DIGITALOCEAN_ACCESS_TOKEN" \
  "https://api.digitalocean.com/v2/firewalls/$agent_firewall_id")
if ! jq -e --argjson droplet "$target_droplet_id" \
  '.firewall.outbound_rules[] | select(.protocol == "tcp" and .ports == "9091" and (.destinations.droplet_ids // [] | index($droplet)))' \
  >/dev/null <<<"$agent_firewall_json"; then
  response_code=$(curl -sS -o /tmp/defensa-agent-firewall-response.json -w '%{http_code}' \
    --connect-timeout 5 --max-time 15 \
    -X POST \
    -H "Authorization: Bearer $DIGITALOCEAN_ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"outbound_rules\":[{\"protocol\":\"tcp\",\"ports\":\"9091\",\"action\":\"allow\",\"destinations\":{\"droplet_ids\":[$target_droplet_id],\"addresses\":[\"$target_private_cidr\"]}}]}" \
    "https://api.digitalocean.com/v2/firewalls/$agent_firewall_id/rules")
  test "$response_code" = "204"
fi
unset DIGITALOCEAN_ACCESS_TOKEN

scp -q "${ssh_options[@]}" \
  "$project_dir/sensors/falco/falco_rules.local.yaml" \
  "$target:/tmp/defensa-falco-rules.yaml"
ssh "${ssh_options[@]}" "$target" \
  'container=target-stack-falco-1; before=$(docker inspect -f "{{.Id}}" "$container"); install -m 0644 /opt/ctf-stack/falco/falco_rules.local.yaml "/opt/ctf-stack/falco/falco_rules.local.yaml.pre-active-defense"; install -m 0644 /tmp/defensa-falco-rules.yaml /opt/ctf-stack/falco/falco_rules.local.yaml; docker kill --signal HUP "$container" >/dev/null; sleep 3; after=$(docker inspect -f "{{.Id}}" "$container"); test "$before" = "$after"; test "$(docker inspect -f "{{.State.Running}}" "$container")" = true'

ssh "${ssh_options[@]}" "$agent" \
  'cd /opt/defensa-azul; set -a; . /etc/defensa-azul/defensa.env; set +a; docker compose up -d --build gateway worker actuator'

printf 'Active defense deployed for configured enforcement targets; no challenge container was restarted.\n'
