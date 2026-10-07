---
name: ctf-incident-reporting
description: Produce an evidence-backed report for a defensive CTF run. Use at checkpoints or run completion to summarize actions taken, lessons learned, scores, misses, safety outcomes, and data limitations.
---

# CTF incident reporting

Use the immutable JSONL audit stream as the source of truth and scope all calculations to one `run_id`. Verify the hash chain before treating the record as complete.

Report, at minimum: executive summary; incident timeline; findings; every proposed, approved, denied, attempted, succeeded, failed, and rolled-back action; lessons learned; measured scores; misses and late detections; target availability and fairness outcomes; sensor/log gaps; versions and provenance; and open follow-ups.

Distinguish zero recorded misses from proven perfect recall. Do not invent denominators or metrics when ground truth is unavailable. Mark incomplete or unavailable values explicitly.

Redact flags, credentials, tokens, player identifiers, and unsafe payload content. Cite event IDs for material claims and generate both machine-readable JSON and human-readable Markdown.
