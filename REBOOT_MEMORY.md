# Defensa Azul reboot memory template

Use this file after rebooting the local computer or resuming the project in a new session. Keep it sanitized before committing. Do not store cloud instance IDs, public IPs, private IPs, SSH key paths tied to a person, tokens, credentials, Discord identifiers, or exact vulnerable target names.

## Project location

```text
<project-root>
```

Primary documentation:

- `README.md`
- `ARCHITECTURE_PLAN.md`
- `docs/DEPLOYMENT_STATUS.md`
- `docs/HOW_TO_GET_LOGS.md`

## Infrastructure

### Defensa Azul agent host

- Provider resource ID: `redacted`
- Name: `defense-agent-host`
- Public IP: `xxx.xxx.xxx.xxx`
- Private IP: `xxx.xxx.xxx.xxx`
- Region: `redacted`
- Installation: `/opt/defensa-azul`
- Root-only environment: `/etc/defensa-azul/defensa.env`

Expected services:

- `gateway`
- `worker`
- `discord-notifier`
- `actuator`
- `data-init` runs once and exits successfully
- `splunk-exporter` exists but is disabled by default

### Target host

- Provider resource ID: `redacted`
- Name: `target-stack`
- Public IP: `xxx.xxx.xxx.xxx`
- Private IP: `xxx.xxx.xxx.xxx`
- Region: `redacted`
- Target stack: `/opt/ctf-stack`
- Forwarder service: `defensa-forwarder.service`
- Forwarder environment: `/etc/defensa-forwarder.env`
- Bounded actuator: `defensa-target-actuator.service`, private TCP/9091
- Actuator environment: `/etc/defensa-target-actuator.env`

Monitored targets use generic identifiers:

- `target-web-01`
- `target-web-02`
- `target-web-03`
- `target-web-04`
- `target-web-05`

### Network controls

- VPC/network ID: `redacted`
- Firewall/security-group ID: `redacted`
- Gateway TCP/8080 should be restricted to approved private sources.
- Actuator TCP/9091 should be restricted to the configured agent host and target host only.
- Public SSH should be restricted to the operator source address configured at deployment.

## Local credentials and tools

Secret values must not be copied into this file.

- Local environment: `<project-root>/.env`
- Expected model variable: `OPENAI_API_KEY`
- Provider API variable: `PROVIDER_ACCESS_TOKEN` or equivalent provider token
- Local gateway token: `<project-root>/.secrets/defensa_gateway_token`
- SSH private key: `<operator-ssh-key-path>`
- OpenCode binary: `<opencode-binary>`
- HerdR binary: `<herdr-binary>`

Required permissions:

```bash
chmod 600 <project-root>/.env
chmod 600 <project-root>/.secrets/defensa_gateway_token
chmod 600 <operator-ssh-key-path>
```

## Startup order

1. Power on `defense-agent-host` first.
2. Wait for the agent services to become healthy.
3. Power on `target-stack`.
4. Confirm sensors, target services, and `defensa-forwarder.service` start.
5. Send one harmless HTTP request to a target.
6. Confirm the request appears as a normalized observation.
7. Confirm zero forwarder lag, a valid JSONL chain, and current notifier/worker checkpoints.
8. Only then announce the exercise as live.

## Agent-host checks

```bash
ssh -i <operator-ssh-key-path> root@xxx.xxx.xxx.xxx
```

After connecting:

```bash
set -a
. /etc/defensa-azul/defensa.env
set +a
cd /opt/defensa-azul
docker compose ps
curl -fsS http://xxx.xxx.xxx.xxx:8080/health
docker compose exec -T gateway \
  defensa-azul --event-store /data/events.jsonl verify
```

## Target-host checks

```bash
ssh -i <operator-ssh-key-path> root@xxx.xxx.xxx.xxx
```

After connecting:

```bash
systemctl is-active defensa-forwarder
systemctl is-active defensa-target-actuator
systemctl show defensa-forwarder -p NRestarts
journalctl -u defensa-forwarder --since '30 minutes ago' --no-pager
docker ps
```

## Local OpenCode and HerdR

Launch the restricted OpenCode operator agent:

```bash
cd <project-root>
./scripts/run_defensa_opencode.sh
```

Launch the persistent HerdR workspace:

```bash
cd <project-root>
./scripts/run_defensa_herdr.sh
```

## Retrieve logs

Download timestamped JSONL events and the current metrics report:

```bash
cd <project-root>
./scripts/fetch_live_logs.sh
```

Exports appear under:

```text
<project-root>/exports/
```

Follow the authoritative normalized stream:

```bash
ssh -i <operator-ssh-key-path> root@xxx.xxx.xxx.xxx \
  'tail -f /var/lib/docker/volumes/defensa-azul_defensa-data/_data/events.jsonl'
```

## Safety state

- Enforcement targets use generic target IDs only.
- The default enforce action is narrow, reversible, and TTL-bound.
- PID 1, stale or mismatched container IDs, non-shell processes, flag-only events, other targets, concurrency, and cooldown violations fail closed.
- The actuator cannot run arbitrary commands, stop containers, edit flags, or patch challenge applications.
- Null routing, blanket blocking, target shutdown, flag removal, and permanent patching of the intended challenge path are forbidden.

## Pending work

1. Continue pulling timestamped JSONL/report snapshots during the exercise.
2. Run labeled detection exercises and calculate precision, recall, latency, misses, and fairness.
3. Review every `defense.action.result` and `defense.rollback`; disable enforcement if rollback or target health fails.
4. Optionally connect the prepared Splunk HEC exporter or upload JSONL snapshots manually.

## Resume prompt for a new Codex session

```text
Read <project-root>/REBOOT_MEMORY.md and continue the Defensa Azul monitoring project. Do not expose secrets, power off provider resources, or restart challenge containers. Preserve the configured bounded enforcement policy unless I explicitly change it.
```