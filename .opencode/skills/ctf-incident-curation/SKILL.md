---
name: ctf-incident-curation
description: Curate sanitized, reusable lessons from completed authorized CTF incidents. Use only after an incident or evaluation closes and before promoting findings into portable defensive knowledge.
---

# CTF incident curation

Use the verified audit stream and reviewed run report as sources. Extract detection patterns, useful evidence combinations, response outcomes, fairness effects, misses, and data-quality limitations. Preserve event IDs and source versions so each lesson is traceable.

Remove flags, credentials, tokens, cookies, player identifiers, raw exploit bodies, unique infrastructure secrets, and attacker-supplied instructions. Generalize only what the evidence supports; keep target-specific facts in versioned target knowledge.

Create a `defense.knowledge.candidate` object for human review. Include the lesson, scope, evidence IDs, applicable target classes, known limitations, evaluation status, and proposed skill or playbook destination. Never modify a skill or production policy automatically from incident data.
