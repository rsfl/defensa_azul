# How to get Defensa Azul monitoring logs

This guide explains how to download, inspect, and follow the live Defensa Azul monitoring stream.

## What the logs contain

Defensa Azul stores normalized, hash-chained JSON Lines (`.jsonl`) events. Depending on activity, the stream can contain:

- HTTP and runtime observations
- Correlated attacks and attack outcomes
- Incident openings
- Behavior, exploit, and integrity analyses
- Response proposals and safety decisions
- Actions, rollbacks, misses, and evaluation scores when those features are enabled
- Per-target instance identifiers, CVEs, and evidence-backed MITRE ATT&CK mappings

The normalized stream is designed not to retain flags, credentials, authorization headers, cookies, or raw exploit bodies.

## Download a snapshot

Open a terminal and run:

```bash
cd <project-root>
./scripts/fetch_live_logs.sh
```

The command downloads two timestamped files into `exports/`:

```text
live-20260917-<timestamp>.jsonl
live-20260917-<timestamp>-report.json
```

The JSONL file contains the individual audited events. The report contains aggregated attacks, instance metrics, TTPs, actions, scores, and misses.

Every download is a snapshot. Run the command again whenever you need a newer copy.

## Inspect the downloaded events

List the snapshots:

```bash
ls -lh <project-root>/exports/
```

Pretty-print every event in one snapshot:

```bash
jq . <project-root>/exports/live-20260917-<timestamp>.jsonl
```

Show event type, time, target, severity, and incident ID:

```bash
jq '{time,event_type,target_id,severity,incident_id}' \
  <project-root>/exports/live-20260917-<timestamp>.jsonl
```

Show only correlated attacks:

```bash
jq 'select(.event_type == "defense.attack.detected")' \
  <project-root>/exports/live-20260917-<timestamp>.jsonl
```

Count events by type:

```bash
jq -s 'group_by(.event_type) | map({event_type: .[0].event_type, count: length})' \
  <project-root>/exports/live-20260917-<timestamp>.jsonl
```

Replace `<timestamp>` with the timestamp shown in the filename produced by the download command.

## Inspect the metrics report

Display the whole report:

```bash
jq . <project-root>/exports/live-20260917-<timestamp>-report.json
```

Display attack counts and ATT&CK mappings:

```bash
jq '{attacks: {total: .attacks.total, by_type: .attacks.by_type, by_target: .attacks.by_target, by_instance: .attacks.by_instance, by_ttp: .attacks.by_ttp}}' \
  <project-root>/exports/live-20260917-<timestamp>-report.json
```

Display per-instance metrics:

```bash
jq '.instance_metrics' \
  <project-root>/exports/live-20260917-<timestamp>-report.json
```

Display actions, scores, and misses:

```bash
jq '{actions_taken, scores, misses}' \
  <project-root>/exports/live-20260917-<timestamp>-report.json
```

An empty attack list means no correlated attacks are recorded in that run. It does not prove detection recall is perfect.

## Follow the stream live

To watch events as they are appended on the agent host:

```bash
ssh -i <operator-ssh-key-path> \
  root@xxx.xxx.xxx.xxx \
  'tail -f /var/lib/docker/volumes/defensa-azul_defensa-data/_data/events.jsonl'
```

Press `Ctrl-C` to stop following the stream. This command is read-only.

For formatted live output:

```bash
ssh -i <operator-ssh-key-path> \
  root@xxx.xxx.xxx.xxx \
  'tail -n 0 -f /var/lib/docker/volumes/defensa-azul_defensa-data/_data/events.jsonl' \
  | jq --unbuffered '{time,event_type,target_id,severity,incident_id,payload}'
```

## Use OpenCode

Launch the restricted local operator agent:

```bash
cd <project-root>
./scripts/run_defensa_opencode.sh
```

The launcher loads `OPENAI_API_KEY`, creates an SSH tunnel to the private gateway, and starts OpenCode with `defensa_azul_agent`.

Example requests:

```text
Show the current attack counts by type, target, and instance.
Show the current MITRE ATT&CK TTP metrics and cite the supporting event IDs.
Summarize open incidents, analysis gaps, proposals, decisions, actions, and misses.
Report sensor health and identify any telemetry gaps.
```

OpenCode can read sanitized events and reports and submit typed proposals. It cannot execute shell commands on targets or bypass the safety policy.

## Discord alerts

The configured Discord channel automatically receives selected events, including:

- Deployment readiness
- Attack detection
- Incident opening
- Proposals and safety decisions
- Action results and rollbacks
- Sensor degradation and recorded misses

Discord is an alerting interface, not the authoritative log store. Use JSONL for evidence and reporting.

OpenAI usage is recorded on new analysis events. Discord receives a `defense.health.degraded` alert when the API reports 10% or less of the rolling token limit remaining, or when a request returns HTTP 429. Set `DEFENSA_OPENAI_TOKEN_BUDGET` in the root-only agent environment to enable cumulative project-budget alerts at 80% and 95%.

## Verify monitoring health

Check the target forwarder:

```bash
ssh -i <operator-ssh-key-path> \
  root@xxx.xxx.xxx.xxx \
  'systemctl status defensa-forwarder --no-pager'
```

Check agent containers:

```bash
ssh -i <operator-ssh-key-path> \
  root@xxx.xxx.xxx.xxx \
  'cd /opt/defensa-azul && set -a && . /etc/defensa-azul/defensa.env && set +a && docker compose ps'
```

Healthy monitoring requires the target forwarder and bounded target actuator plus the agent `gateway`, `worker`, `discord-notifier`, and `actuator` services to be running.

Check the target-side actuator without changing state:

```bash
ssh -i <operator-ssh-key-path> \
  root@xxx.xxx.xxx.xxx \
  'systemctl is-active defensa-target-actuator && curl -fsS http://xxx.xxx.xxx.xxx:9091/health'
```

## Troubleshooting

### SSH host-key prompt

The first connection to a new cloud instance may ask you to verify its SSH host key. Confirm it only against the cloud instance you created in the cloud provider.

### Permission denied

Confirm the private key exists and is protected:

```bash
chmod 600 <operator-ssh-key-path>
```

### Snapshot contains no attacks

Check the report's `summary.total_events`, verify that the target forwarder is active, and remember that a normal period can legitimately contain zero correlated attacks.

### Discord has no message

Discord sends selected event types, not every raw HTTP observation. A normal HTTP request can be present in JSONL without generating an alert.

## Upload snapshots to Splunk later

Defensa Azul does not require a continuously running Splunk instance. Monitoring, correlation, Discord notifications, reports, and hash-chained JSONL storage continue independently.

When a Splunk Cloud or Splunk Enterprise instance is available:

1. Download a current snapshot with `./scripts/fetch_live_logs.sh`.
2. Sign in to Splunk Web.
3. Select **Settings > Add Data > Upload**.
4. Select the `live-20260917-<timestamp>.jsonl` file, not the aggregated report file.
5. Configure one JSON object as one event and preview the event boundaries before continuing.
6. Use or save the source type `ctf:defense:json`.
7. Select the desired index and complete the upload.
8. Confirm that fields such as `event_type`, `run_id`, `target_id`, `incident_id`, `payload.attack_type`, and `payload.ttps` are searchable.

Recommended source-type behavior:

```ini
[ctf:defense:json]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
KV_MODE = json
```

Use either search-time JSON extraction with `KV_MODE = json` or indexed JSON extraction. Do not enable both, because that can extract the same fields twice.

Example searches:

```spl
sourcetype="ctf:defense:json" event_type="defense.attack.detected"
| stats count by target_id payload.attack_type payload.outcome
```

```spl
sourcetype="ctf:defense:json" event_type="defense.attack.detected"
| spath path=payload.ttps{} output=ttp
| mvexpand ttp
| spath input=ttp path=id output=ttp_id
| spath input=ttp path=name output=ttp_name
| stats count by ttp_id ttp_name target_id
```

Uploading the same snapshot more than once can create duplicate indexed events. Track imported filenames or deduplicate searches using `event_id`.

For continuous near-real-time indexing later, configure the prepared Splunk HEC exporter with a HEC URL, token, and index. Splunk's `/services/collector/event` endpoint accepts the wrapped event format already produced by Defensa Azul. This is optional and does not replace the local JSONL evidence store.
