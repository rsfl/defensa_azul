---
name: ctf-response-planning
description: Create typed, reversible response proposals for authorized CTF incidents. Use after evidence analysis when monitoring, repair, or mitigation may be warranted without removing the intended vulnerability or flag path.
---

# CTF response planning

Read the incident evidence, target manifest, and current policy before proposing anything. A proposal is not authorization to execute.

Prefer the least disruptive action that improves visibility or removes confirmed malicious persistence while leaving the vulnerable service and real flag available. Never propose a blanket IP block, null route, target shutdown, flag removal/rotation, or permanent patch of the intended challenge path.

Emit exactly one typed proposal at a time with: run and incident IDs, target ID, action type, exact resource, evidence IDs, confidence, positive TTL, rollback contract, expected effect, and whether the intended path is impacted. Identify prerequisites and expected health/flag probes in the expected-effect text when applicable.

If the evidence, rollback, target authorization, or policy is incomplete, produce a recommendation for more observation instead of guessing.
