# Deployment status

Updated: 2026-09-19

## Live topology

- Agent cloud instance `redacted` (`defense-agent-host`) is active in `nyc3` with 2 vCPU, 4 GB RAM, and 80 GB disk.
- Target cloud instance `redacted` (`target-stack`) remains active in the same VPC.
- The retired relay cloud instance `redacted` (`retired-relay-host`) is powered off.
- The cloud provider firewall `redacted` limits public SSH to the operator IP and gateway TCP/8080 to the target cloud instance. Required outbound HTTPS, DNS, and target SSH are permitted.
- The gateway is bound only to the agent cloud instance's private address. Local OpenCode reaches it through an SSH tunnel.

## Running components

The agent host runs four long-lived containers plus a one-shot volume initializer:

- `gateway`: authenticated sensor/event ingestion, hash-chained JSONL storage, reporting, and proposal policy decisions.
- `worker`: deterministic attack correlation and incident creation, three bounded OpenAI analyst roles, response planning, and deterministic safety decisions.
- `discord-notifier`: redacted alert delivery to the existing CTF Discord channel.
- `actuator`: consumes allowed decisions and calls only the private bounded target actuator.
- `data-init`: one-shot ownership correction for the non-root shared data volume.

The target host runs `defensa-forwarder.service`, which tails the authoritative Traefik and Falco JSONL logs from its installation-time end offsets. A harmless HTTP request was observed end to end as `defense.observation.http`, mapped to the Target Web 01 container instance. The service is active with zero restarts.

The first `defense.deployment.ready` audit event was accepted and the Discord checkpoint advanced through it. A non-persisted model smoke test successfully returned the expected analysis fields. OpenCode 1.18.30 resolves `defensa_azul_agent` with the intended restricted permissions and model configuration.

OpenCode discovers eight validated CTF skills, including an adapted `ctf-detection-triage` skill informed by the Apache-2.0 Detection Skills library. Its upstream source commit, authorship, license, and CTF-specific modifications are recorded in `THIRD_PARTY_NOTICES.md`.

## Sensor correction

The Falco flag-access rule now includes Target Web 05's `/flag.txt` path in addition to the `.flag` suffix used by the other targets. The prior rule was backed up on the target, the corrected rule passed Falco schema validation, and only Falco was restarted; challenge application containers were not restarted.

## Historical baseline

The copied pre-deployment logs were re-normalized into `data/live-baseline-v2.jsonl` under run ID `baseline-live-20260917-v2`. This is historical verification traffic, not a claim about player activity.

| Instance | HTTP | Runtime | Correlated attacks | Successful flag access |
|---|---:|---:|---:|---:|
| Target Web 01 | 43 | 5 | 3 | 1 |
| Target Web 02 | 22 | 9 | 4 | 2 |
| Target Web 03 | 86 | 0 | 0 | 0 |
| Target Web 04 | 15 | 8 | 5 | 1 |
| Target Web 05 | 55 | 1 | 1 | 0 |
| **Total** | **221** | **23** | **13** | **4** |

Attack types were 4 `flag-access` and 9 `post-exploitation-shell`. Evidence-backed ATT&CK mappings were 4 occurrences of T1005 (Data from Local System) and 9 of T1059.004 (Unix Shell). The 257-event JSONL hash chain passed verification. Reports are generated as `reports/baseline-live-20260917-v2.json` and `reports/baseline-live-20260917-v2.md`.

## Current safety state

- Target Web 01 and Target Web 05 are enforcement-enabled for one action: pause an exactly evidenced shell PID for at most 15 seconds and automatically resume it.
- Target Web 02, Target Web 03, and Target Web 04 remain observe-only.
- The target actuator revalidates the live PID name, Docker container ID, cgroup membership, PID age, target allowlist, TTL, cooldown, and concurrency before signaling.
- Flag access alone cannot trigger mitigation, and no challenge path or flag is modified.
- No live mitigation action has yet been attempted; a forbidden-target/PID 1 request was rejected with HTTP 409 during validation.
- Null routing, blanket blocking, target shutdown, and changes that remove the intended challenge path are outside the allowed design.
- Two enforcement targets and per-target reversible action allowlists still require explicit selection before mitigation can be enabled.

## Next phase

1. Continue live collection and review action/rollback events immediately.
2. Conduct labeled attack exercises to measure detection latency, precision/recall, misses, proposal quality, rollback success, and challenge solvability.
3. Upload JSONL snapshots to Splunk or enable the optional HEC profile when desired.
