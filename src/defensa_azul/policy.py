from __future__ import annotations

import json
from ipaddress import ip_address
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import ActionProposal, DecisionStatus


ALWAYS_FORBIDDEN = {
    "blanket_ip_block",
    "null_route",
    "remove_flag",
    "rotate_flag",
    "stop_target",
    "permanently_patch_intended_vulnerability",
}

SUSPEND_CONTAINERS = {
    "target-web-01": "target-stack-target-web-01-1",
    "target-web-05": "target-stack-target-web-05-1",
}

WINDOWS_FIREWALL_ALLOWED_PORTS = {445, 3389, 5985}
LINUX_BLOCK_DEFAULT_COMMENT_PREFIX = "defensa-azul "


@dataclass(slots=True)
class PolicyDecision:
    status: DecisionStatus
    reasons: list[str]
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reasons": self.reasons,
            "policy_version": self.policy_version,
        }


class SafetyGate:
    def __init__(self, config: dict[str, Any]):
        self.config = config

    @classmethod
    def from_file(cls, path: str | Path) -> "SafetyGate":
        with Path(path).open(encoding="utf-8") as handle:
            return cls(json.load(handle))

    def evaluate(self, proposal: ActionProposal) -> PolicyDecision:
        reasons: list[str] = []
        policy_version = str(self.config.get("policy_version", "unknown"))
        targets = self.config.get("targets", {})
        target = targets.get(proposal.target_id)

        if target is None:
            return PolicyDecision(DecisionStatus.DENIED, ["target is not declared"], policy_version)

        mode = target.get("mode", "observe")
        if proposal.action_type in ALWAYS_FORBIDDEN:
            reasons.append("action is globally forbidden")
        if proposal.action_type not in set(target.get("allowed_actions", [])):
            reasons.append("action is not allowlisted for target")
        if not proposal.evidence_ids:
            reasons.append("proposal has no evidence")
        if not 0 <= proposal.confidence <= 1:
            reasons.append("confidence is outside 0..1")
        if proposal.confidence < float(target.get("minimum_confidence", 1.0)):
            reasons.append("confidence is below target threshold")
        if proposal.ttl_seconds <= 0:
            reasons.append("TTL must be positive")
        if proposal.ttl_seconds > int(target.get("maximum_ttl_seconds", 0)):
            reasons.append("TTL exceeds target maximum")
        if not proposal.rollback:
            reasons.append("rollback contract is missing")
        if proposal.intended_path_impacted:
            reasons.append("proposal impacts the intended challenge path")
        if proposal.action_type == "suspend_process":
            try:
                resource = json.loads(proposal.resource)
            except (json.JSONDecodeError, TypeError):
                resource = None
            if not isinstance(resource, dict):
                reasons.append("suspend_process resource is not structured JSON")
            else:
                if resource.get("container_name") != SUSPEND_CONTAINERS.get(proposal.target_id):
                    reasons.append("container does not match the target allowlist")
                if resource.get("process") not in {"sh", "bash", "dash"}:
                    reasons.append("process is not an allowlisted shell")
                try:
                    host_pid = int(resource.get("host_pid", 0))
                except (TypeError, ValueError):
                    host_pid = 0
                if host_pid <= 1:
                    reasons.append("host PID must be greater than one")
                if not str(resource.get("container_id", "")):
                    reasons.append("container identity is missing")
        if proposal.action_type == "windows_firewall_block":
            try:
                resource = json.loads(proposal.resource)
            except (json.JSONDecodeError, TypeError):
                resource = None
            windows_policy = target.get("windows_firewall", {})
            if not isinstance(resource, dict):
                reasons.append("windows_firewall_block resource is not structured JSON")
            elif not isinstance(windows_policy, dict):
                reasons.append("windows firewall policy must be structured")
            else:
                src_ip = str(resource.get("src_ip", ""))
                try:
                    parsed_src = ip_address(src_ip)
                except ValueError:
                    parsed_src = None
                allowed_sources = set(windows_policy.get("allowed_sources", []))
                protected_sources = set(windows_policy.get("protected_sources", ["127.0.0.1"]))
                bridge_source = str(windows_policy.get("bridge_source", ""))
                bridge_target = str(windows_policy.get("bridge_target", "win-dc01"))
                bridge_ports = {int(port) for port in windows_policy.get("bridge_ports", [445])}
                if not allowed_sources:
                    reasons.append("Windows firewall policy must declare allowed_sources")
                elif src_ip not in allowed_sources:
                    reasons.append("source IP is not allowlisted for lab blocking")
                if src_ip in protected_sources:
                    reasons.append("source IP is protected infrastructure")
                if parsed_src is None or not parsed_src.is_private:
                    reasons.append("source IP must be private lab address space")
                if str(resource.get("protocol", "")).lower() != "tcp":
                    reasons.append("windows firewall block only permits tcp")
                if str(resource.get("direction", "")).lower() != "inbound":
                    reasons.append("windows firewall block only permits inbound rules")
                try:
                    dst_port = int(resource.get("dst_port", 0))
                except (TypeError, ValueError):
                    dst_port = 0
                if dst_port not in WINDOWS_FIREWALL_ALLOWED_PORTS:
                    reasons.append("destination port is not allowlisted for Windows blocking")
                if bridge_source and src_ip == bridge_source and (
                    proposal.target_id != bridge_target or dst_port not in bridge_ports
                ):
                    reasons.append("bridge source can only be blocked for the configured bridge target and ports")
                if not str(resource.get("rule_name", "")).startswith("DefensaAzul block "):
                    reasons.append("firewall rule name must use the DefensaAzul prefix")
                if proposal.rollback.get("type") != "remove_windows_firewall_rule":
                    reasons.append("windows firewall block requires a firewall-rule rollback")
        if proposal.action_type == "linux_nftables_block":
            try:
                resource = json.loads(proposal.resource)
            except (json.JSONDecodeError, TypeError):
                resource = None
            linux_policy = target.get("linux_nftables", {})
            if not isinstance(resource, dict):
                reasons.append("linux_nftables_block resource is not structured JSON")
            elif not isinstance(linux_policy, dict):
                reasons.append("linux nftables policy must be structured")
            else:
                src_ip = str(resource.get("src_ip", ""))
                try:
                    parsed_src = ip_address(src_ip)
                except ValueError:
                    parsed_src = None
                allowed_sources = set(linux_policy.get("allowed_sources", []))
                protected_sources = set(linux_policy.get("protected_sources", []))
                if allowed_sources and src_ip not in allowed_sources:
                    reasons.append("source IP is not allowlisted for Linux blocking")
                if src_ip in protected_sources:
                    reasons.append("source IP is protected infrastructure")
                if parsed_src is None or not parsed_src.is_private:
                    reasons.append("source IP must be private lab address space")
                protocol = str(resource.get("protocol", "")).lower()
                if protocol not in {"tcp", "udp"}:
                    reasons.append("linux nftables block only permits tcp or udp")
                try:
                    dst_port = int(resource.get("dst_port", 0))
                except (TypeError, ValueError):
                    dst_port = 0
                allowed_ports = {int(port) for port in linux_policy.get("allowed_ports", [])}
                if not allowed_ports:
                    reasons.append("Linux nftables policy must declare allowed_ports")
                elif dst_port not in allowed_ports:
                    reasons.append("destination port is not allowlisted for Linux blocking")
                chain = str(resource.get("chain", ""))
                allowed_chains = set(linux_policy.get("allowed_chains", ["defensa_azul_input"]))
                if chain not in allowed_chains:
                    reasons.append("nftables chain is not allowlisted")
                rule_comment = str(resource.get("rule_comment", ""))
                comment_prefix = str(linux_policy.get("rule_comment_prefix", LINUX_BLOCK_DEFAULT_COMMENT_PREFIX))
                if not rule_comment.startswith(comment_prefix):
                    reasons.append("nftables rule comment must use the Defensa Azul prefix")
                if proposal.rollback.get("type") != "remove_nftables_rule":
                    reasons.append("linux nftables block requires an nftables rollback")
                if str(proposal.rollback.get("chain", "")) != chain:
                    reasons.append("linux nftables rollback chain must match the action chain")
                if str(proposal.rollback.get("rule_comment", "")) != rule_comment:
                    reasons.append("linux nftables rollback comment must match the action comment")

        if reasons:
            return PolicyDecision(DecisionStatus.DENIED, reasons, policy_version)
        if mode != "enforce":
            return PolicyDecision(
                DecisionStatus.RECOMMENDATION_ONLY,
                [f"target mode is {mode}; execution is disabled"],
                policy_version,
            )
        return PolicyDecision(DecisionStatus.ALLOWED, ["all safety checks passed"], policy_version)
