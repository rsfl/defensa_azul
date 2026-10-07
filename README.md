# Defensa Azul

Defensa Azul is an auditable defensive-agent control plane for authorized attack/defense CTF research. The framework records hash-chained JSONL events, evaluates typed response proposals against a fail-closed policy, exposes a restricted gateway, produces Splunk and Discord payloads, and generates complete JSON and Markdown run reports.

The live pilot policy supports bounded active defense for two classes of actions:

- `suspend_process` for declared generic CTF targets. This pauses an exactly evidenced shell process for at most 15 seconds and automatically resumes it.
- `windows_firewall_block` for declared Windows lab targets. This creates a short-lived, source-scoped Windows Firewall rule and automatically removes the exact rule at rollback time.
- `linux_nftables_block` for declared Linux targets. This validates a source-scoped nftables block against the target policy and requires an exact rollback contract.

Active response is intentionally narrow. Defensa Azul does not expose a generic shell, does not execute arbitrary model output, and does not permanently modify targets by default.

## Run locally

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m defensa_azul.cli append examples/event.json
PYTHONPATH=src python3 -m defensa_azul.cli verify
PYTHONPATH=src python3 -m defensa_azul.cli evaluate examples/proposal.json
PYTHONPATH=src python3 -m defensa_azul.cli report run-demo
```

The proposal evaluation command is expected to deny the example because `target-demo` is not declared.

Useful focused checks during development:

```bash
PYTHONPATH=src python3 -m unittest tests.test_policy -v
PYTHONPATH=src python3 -m py_compile src/defensa_azul/gateway.py src/defensa_azul/models.py src/defensa_azul/policy.py src/defensa_azul/splunk_exporter.py src/defensa_azul/worker.py
```

The full test suite currently expects a Linux-like runtime for modules that use `fcntl` and POSIX process signals.

## Gateway

Set a long random token through the environment and bind to loopback by default:

```bash
export DEFENSA_GATEWAY_TOKEN='replace-through-a-secret-manager'
PYTHONPATH=src python3 -m defensa_azul.gateway
```

Endpoints:

- `GET /health` — unauthenticated liveness only.
- `GET /v1/events?run_id=...` — authenticated audit events.
- `GET /v1/actions?run_id=...&target_id=...&action_type=...` — authenticated pending action queue for endpoint agents.
- `GET /v1/report?run_id=...` — authenticated generated report.
- `POST /v1/events` — authenticated typed event ingestion.
- `POST /v1/proposals` — authenticated proposal creation and policy evaluation; never executes an action.

OpenCode uses `.opencode/tools/defensa.ts` and the skills under `.opencode/skills/`. Set `DEFENSA_GATEWAY_URL` and `DEFENSA_GATEWAY_TOKEN` in the local OpenCode environment. Do not make the gateway public; use WireGuard/Tailscale or an SSH tunnel to the cloud provider and keep it bound to a private interface.

The skill set covers target onboarding, detection triage, evidence and exploit analysis, response planning, fairness review, incident reporting, and reviewed knowledge curation. Third-party provenance is recorded in `THIRD_PARTY_NOTICES.md`.

The local launcher creates that tunnel and selects the restricted agent:

```bash
./scripts/run_defensa_opencode.sh
```

For a persistent local terminal workspace, launch the named HerdR session and run the OpenCode launcher in one of its panes:

```bash
./scripts/run_defensa_herdr.sh
```

## Windows endpoint agent

The Windows endpoint agent lives in `deploy/windows-agent/`.

Observe mode is the default. Active firewall blocking is opt-in at install time:

```powershell
.\install-defensa-windows-agent.ps1 `
  -GatewayUrl "http://<gateway-host>:18080" `
  -Token "<gateway-token>" `
  -RunId "defended-live" `
  -TargetId "win-dc01" `
  -PollSeconds 10 `
  -AllowedBlockSources "xxx.xxx.xxx.xxx" `
  -ProtectedSources "127.0.0.1","xxx.xxx.xxx.xxx" `
  -BridgeSource "xxx.xxx.xxx.xxx" `
  -EnableBlocking
```

When `-EnableBlocking` is present, the agent polls `/v1/actions` for allowed `windows_firewall_block` proposals addressed to its own `target_id`. It validates the typed resource locally, applies a scoped `New-NetFirewallRule`, emits `defense.action.result`, and removes the exact rule after the TTL by emitting `defense.rollback`.

The lab policy permits only narrow Windows firewall blocks configured by the operator:

- Source `xxx.xxx.xxx.xxx` values listed in the target policy or installer arguments.
- Optional bridge-source handling only for the configured target and inbound TCP/445.
- Destination ports `445`, `3389`, and `5985`.
- Rule names beginning with `DefensaAzul block `.
- Rollback type `remove_windows_firewall_rule`.

Use `examples/windows-firewall-block-proposal.json` as the action-contract reference.

## Linux defensive actions

Linux defense is policy-driven rather than tied to named CTF containers. A Linux target declares its allowed nftables envelope in `policies/global.json`:

```json
{
  "linux-server01": {
    "mode": "enforce",
    "allowed_actions": ["increase_capture", "linux_nftables_block"],
    "minimum_confidence": 0.70,
    "maximum_ttl_seconds": 300,
    "linux_nftables": {
      "allowed_sources": ["xxx.xxx.xxx.xxx"],
      "protected_sources": ["127.0.0.1", "xxx.xxx.xxx.xxx"],
      "allowed_ports": [22, 80, 443],
      "allowed_chains": ["defensa_azul_input"],
      "rule_comment_prefix": "defensa-azul "
    }
  }
}
```

The policy gate rejects Linux blocks unless the proposal is narrow:

- `action_type` is `linux_nftables_block`.
- Source IP is private lab address space.
- Source IP is allowed by target policy when `allowed_sources` is present.
- Source IP is not in `protected_sources`.
- Protocol is `tcp` or `udp`.
- Destination port is listed in `allowed_ports`.
- Chain is listed in `allowed_chains`; use an owned chain such as `defensa_azul_input`.
- Rule comment starts with the configured `rule_comment_prefix`.
- Rollback type is `remove_nftables_rule`.
- Rollback chain and comment exactly match the proposed rule.

Use `examples/linux-nftables-block-proposal.json` as the action-contract reference.

## Security boundaries

- Agent output is a proposal, not authorization.
- The policy gate defaults to denial; endpoint agents accept only typed action contracts and independently revalidate them on the target host.
- The gateway exposes no generic shell, Docker, Kubernetes, or arbitrary HTTP tool.
- Attacker-controlled evidence is data, never an instruction.
- Flags, credentials, tokens, cookies, and authorization values are redacted from integration payloads.
- The JSONL hash chain detects modification but does not replace remote replication or signed checkpoints.

See [ARCHITECTURE_PLAN.md](ARCHITECTURE_PLAN.md) for the deployment and evaluation design.

See [docs/HOW_TO_GET_LOGS.md](docs/HOW_TO_GET_LOGS.md) for the operator guide to downloading, following, and querying live monitoring logs.

See [REBOOT_MEMORY.md](REBOOT_MEMORY.md) for the reboot-safe operational handoff, infrastructure identifiers, startup order, and resume prompt.
