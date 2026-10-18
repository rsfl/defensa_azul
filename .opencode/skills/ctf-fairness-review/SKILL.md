---
name: ctf-fairness-review
description: Review proposed defensive actions for authorization, evidence, reversibility, and operational impact.
---

# Defensive workflow

Fail closed. Confirm that the target is declared, enforcement is authorized, and the exact action is allowlisted. Reject missing evidence, insufficient confidence, excessive TTL, an unworkable rollback, prohibited actions, or unacceptable service impact. Verify health checks and recovery requirements. Return a decision with reasons, policy version, proposal ID, and evidence; do not execute the action.
