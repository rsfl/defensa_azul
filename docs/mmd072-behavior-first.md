# Behavior-first ARTEX monitoring and bounded Windows response

This update applies the evidence and tiering principles in [MalwareMustDie MMD-072-2026](https://blog.malwaremustdie.org/2026/11/mmd-072-2026-artex-detection-signature.html) and its [detection pack](https://github.com/unixfreaxjp/malwaremustdie/blob/master/etc/artex-stix-osquery-sigma-kql-snort-suricata-yara/README.md). It does not copy the pack's signatures or claim that a generic logon burst identifies ARTEX. The pack treats behavior as more durable than changeable strings and warns that generic indicators and historical IPs need corroboration before containment.

## New monitoring signal

`privileged_network_logon_burst` requires **three distinct DC Administrator type-3 4624 logons**, each paired by logon ID with a 4672 privilege event, from the same allowlisted source within **30 seconds**. The correlator requires `DEFENSA_WINDOWS_ALERT_SOURCES` and `DEFENSA_WINDOWS_RULE_NOT_BEFORE`, deduplicates by logon ID, and preserves six target event IDs per alert. It emits one stable alert per qualifying cluster. The payload says `framework_attribution=unknown` and `auto_block_eligible=false`.

The burst alert opens an analyst incident but skips model analysis and response proposals. A separate first paired logon detector remains the only source of the lab's automatic DC SMB proposal. This separation prevents a generic burst from creating a second block. Repeated logons can be legitimate administration, and the same source can carry several processes.

## Block result semantics

The Windows agent still requires an allowlisted private source, a bounded destination port and TTL, an enabled active firewall profile, and an independent scheduled rollback. After installing a rule, it now reads the rule and its port/address filters back. It reports `rule_state_verified=true` only when the rule is enabled, inbound, blocking the requested TCP port and source, and an active profile remains enabled. A failed postcondition removes the rule and rollback task before returning a failed action result. A successful result also says `traffic_blocked=unverified_until_connectivity_check`: rule state alone is not proof that traffic or a framework step stopped.

## Lab evidence and deployment limits

In the six saved Windows exercise windows, a Splunk search for the burst returned one hit in the ARTEX block run and zero in the other five. Replaying the indexed Defensa endpoint events through the new correlator produced the same one-to-zero pattern. A subsequent bounded block validation produced an indexed `rule_state_verified=true` result; the framework's later SMB connection timed out, and an independent check found SMB 445 blocked while LDAP 389 remained reachable. The initial privileged logon succeeded before the block.

The Splunk searches and detailed run evidence live in the separate research lab, not in this repository. Default policy should remain in `observe` with no allowed block sources. Operators must explicitly configure sources, a time floor, target policy, endpoint allowlists, and a rollback watchdog for an isolated deployment. Do not use an ARTEX string, generic user-agent, or published IP by itself to trigger a block.
