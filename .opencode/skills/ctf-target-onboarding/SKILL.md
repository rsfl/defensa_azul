---
name: ctf-target-onboarding
description: Onboard an authorized vulnerable CTF target into Defensa Azul. Use when adding a target profile, sensor mapping, flag contract, or observe/recommend/enforce policy without weakening the intended challenge.
---

# CTF target onboarding

Create a versioned target profile from operator-supplied infrastructure and challenge facts. Record target and instance IDs, immutable image identity when available, exposed service, intended CVE/advisory, flag path or retrieval contract, expected processes, health probe, lab boundary, and initial mode.

Start every target in `observe`. Do not infer enforcement permission from access to the target. Enabling `enforce` requires explicit selection of that target and an exact reversible action allowlist with confidence threshold, TTL cap, rollback, service probe, and flag-path probe.

Map hostnames and container identifiers in the sensor normalizer and add a harmless observation test. Never copy flag values, credentials, environment secrets, exploit payloads, or player identifiers into profiles, prompts, or fixtures.

Return the changed profile, sensor mapping, policy state, validation evidence, and any missing onboarding inputs. Do not deploy or restart the challenge unless the operator separately authorizes it.
