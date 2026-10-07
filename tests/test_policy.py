import unittest

from defensa_azul.models import ActionProposal, DecisionStatus
from defensa_azul.policy import SafetyGate


def proposal(**overrides):
    value = {
        "run_id": "run-test",
        "target_id": "target-a",
        "incident_id": "inc-test",
        "action_type": "increase_capture",
        "resource": "pid:10",
        "evidence_ids": ["evt-1"],
        "confidence": 0.99,
        "ttl_seconds": 60,
        "rollback": {"type": "expire"},
        "expected_effect": "capture more metadata",
    }
    value.update(overrides)
    return ActionProposal(**value)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "policy_version": "test",
            "targets": {
                "target-a": {
                    "mode": "enforce",
                    "allowed_actions": ["increase_capture"],
                    "minimum_confidence": 0.95,
                    "maximum_ttl_seconds": 120,
                }
            },
        }

    def test_valid_allowlisted_action_is_allowed(self):
        decision = SafetyGate(self.config).evaluate(proposal())
        self.assertEqual(DecisionStatus.ALLOWED, decision.status)

    def test_unknown_target_is_denied(self):
        decision = SafetyGate(self.config).evaluate(proposal(target_id="missing"))
        self.assertEqual(DecisionStatus.DENIED, decision.status)

    def test_flag_impact_is_denied(self):
        decision = SafetyGate(self.config).evaluate(proposal(intended_path_impacted=True))
        self.assertEqual(DecisionStatus.DENIED, decision.status)

    def test_observe_target_is_recommendation_only(self):
        self.config["targets"]["target-a"]["mode"] = "observe"
        decision = SafetyGate(self.config).evaluate(proposal())
        self.assertEqual(DecisionStatus.RECOMMENDATION_ONLY, decision.status)

    def test_lab_windows_firewall_block_is_allowed(self):
        self.config["targets"]["win-client01"] = {
            "mode": "enforce",
            "allowed_actions": ["windows_firewall_block"],
            "minimum_confidence": 0.70,
            "maximum_ttl_seconds": 300,
            "windows_firewall": {
                "allowed_sources": ["10.10.10.151", "10.10.10.67"],
                "protected_sources": ["10.10.10.67"],
                "bridge_source": "10.10.10.67",
                "bridge_target": "win-dc01",
                "bridge_ports": [445],
            },
        }
        decision = SafetyGate(self.config).evaluate(
            proposal(
                target_id="win-client01",
                action_type="windows_firewall_block",
                resource='{"src_ip":"10.10.10.151","protocol":"tcp","dst_port":445,"direction":"inbound","rule_name":"DefensaAzul block attacker SMB inc-test"}',
                confidence=0.97,
                ttl_seconds=300,
                rollback={"type": "remove_windows_firewall_rule", "rule_name": "DefensaAzul block attacker SMB inc-test"},
            )
        )
        self.assertEqual(DecisionStatus.ALLOWED, decision.status)

    def test_lab_windows_firewall_block_rejects_infrastructure_source(self):
        self.config["targets"]["win-client01"] = {
            "mode": "enforce",
            "allowed_actions": ["windows_firewall_block"],
            "minimum_confidence": 0.70,
            "maximum_ttl_seconds": 300,
            "windows_firewall": {
                "allowed_sources": ["10.10.10.151", "10.10.10.67"],
                "protected_sources": ["10.10.10.67"],
                "bridge_source": "10.10.10.67",
                "bridge_target": "win-dc01",
                "bridge_ports": [445],
            },
        }
        decision = SafetyGate(self.config).evaluate(
            proposal(
                target_id="win-client01",
                action_type="windows_firewall_block",
                resource='{"src_ip":"10.10.10.67","protocol":"tcp","dst_port":445,"direction":"inbound","rule_name":"DefensaAzul block attacker SMB inc-test"}',
                confidence=0.97,
                ttl_seconds=300,
                rollback={"type": "remove_windows_firewall_rule", "rule_name": "DefensaAzul block attacker SMB inc-test"},
            )
        )
        self.assertEqual(DecisionStatus.DENIED, decision.status)

    def test_lab_windows_firewall_block_allows_dc_bridge_smb(self):
        self.config["targets"]["win-dc01"] = {
            "mode": "enforce",
            "allowed_actions": ["windows_firewall_block"],
            "minimum_confidence": 0.70,
            "maximum_ttl_seconds": 300,
            "windows_firewall": {
                "allowed_sources": ["10.10.10.151", "10.10.10.67"],
                "protected_sources": [],
                "bridge_source": "10.10.10.67",
                "bridge_target": "win-dc01",
                "bridge_ports": [445],
            },
        }
        decision = SafetyGate(self.config).evaluate(
            proposal(
                target_id="win-dc01",
                action_type="windows_firewall_block",
                resource='{"src_ip":"10.10.10.67","protocol":"tcp","dst_port":445,"direction":"inbound","rule_name":"DefensaAzul block bridge SMB inc-test"}',
                confidence=0.97,
                ttl_seconds=120,
                rollback={"type": "remove_windows_firewall_rule", "rule_name": "DefensaAzul block bridge SMB inc-test"},
            )
        )
        self.assertEqual(DecisionStatus.ALLOWED, decision.status)

    def test_lab_windows_firewall_block_rejects_bridge_non_smb(self):
        self.config["targets"]["win-dc01"] = {
            "mode": "enforce",
            "allowed_actions": ["windows_firewall_block"],
            "minimum_confidence": 0.70,
            "maximum_ttl_seconds": 300,
            "windows_firewall": {
                "allowed_sources": ["10.10.10.151", "10.10.10.67"],
                "protected_sources": [],
                "bridge_source": "10.10.10.67",
                "bridge_target": "win-dc01",
                "bridge_ports": [445],
            },
        }
        decision = SafetyGate(self.config).evaluate(
            proposal(
                target_id="win-dc01",
                action_type="windows_firewall_block",
                resource='{"src_ip":"10.10.10.67","protocol":"tcp","dst_port":5985,"direction":"inbound","rule_name":"DefensaAzul block bridge WinRM inc-test"}',
                confidence=0.97,
                ttl_seconds=120,
                rollback={"type": "remove_windows_firewall_rule", "rule_name": "DefensaAzul block bridge WinRM inc-test"},
            )
        )
        self.assertEqual(DecisionStatus.DENIED, decision.status)

    def test_lab_linux_nftables_block_is_allowed(self):
        self.config["targets"]["linux-server01"] = {
            "mode": "enforce",
            "allowed_actions": ["linux_nftables_block"],
            "minimum_confidence": 0.70,
            "maximum_ttl_seconds": 300,
            "linux_nftables": {
                "allowed_sources": ["10.10.10.151"],
                "protected_sources": ["10.10.10.67"],
                "allowed_ports": [22, 80, 443],
                "allowed_chains": ["defensa_azul_input"],
                "rule_comment_prefix": "defensa-azul ",
            },
        }
        decision = SafetyGate(self.config).evaluate(
            proposal(
                target_id="linux-server01",
                action_type="linux_nftables_block",
                resource='{"src_ip":"10.10.10.151","protocol":"tcp","dst_port":22,"chain":"defensa_azul_input","rule_comment":"defensa-azul inc-test"}',
                confidence=0.96,
                ttl_seconds=300,
                rollback={
                    "type": "remove_nftables_rule",
                    "chain": "defensa_azul_input",
                    "rule_comment": "defensa-azul inc-test",
                },
            )
        )
        self.assertEqual(DecisionStatus.ALLOWED, decision.status)

    def test_lab_linux_nftables_block_rejects_public_source(self):
        self.config["targets"]["linux-server01"] = {
            "mode": "enforce",
            "allowed_actions": ["linux_nftables_block"],
            "minimum_confidence": 0.70,
            "maximum_ttl_seconds": 300,
            "linux_nftables": {
                "allowed_ports": [22],
                "allowed_chains": ["defensa_azul_input"],
                "rule_comment_prefix": "defensa-azul ",
            },
        }
        decision = SafetyGate(self.config).evaluate(
            proposal(
                target_id="linux-server01",
                action_type="linux_nftables_block",
                resource='{"src_ip":"8.8.8.8","protocol":"tcp","dst_port":22,"chain":"defensa_azul_input","rule_comment":"defensa-azul inc-test"}',
                confidence=0.96,
                ttl_seconds=300,
                rollback={
                    "type": "remove_nftables_rule",
                    "chain": "defensa_azul_input",
                    "rule_comment": "defensa-azul inc-test",
                },
            )
        )
        self.assertEqual(DecisionStatus.DENIED, decision.status)

    def test_lab_linux_nftables_block_rejects_unmanaged_chain(self):
        self.config["targets"]["linux-server01"] = {
            "mode": "enforce",
            "allowed_actions": ["linux_nftables_block"],
            "minimum_confidence": 0.70,
            "maximum_ttl_seconds": 300,
            "linux_nftables": {
                "allowed_sources": ["10.10.10.151"],
                "allowed_ports": [22],
                "allowed_chains": ["defensa_azul_input"],
                "rule_comment_prefix": "defensa-azul ",
            },
        }
        decision = SafetyGate(self.config).evaluate(
            proposal(
                target_id="linux-server01",
                action_type="linux_nftables_block",
                resource='{"src_ip":"10.10.10.151","protocol":"tcp","dst_port":22,"chain":"input","rule_comment":"defensa-azul inc-test"}',
                confidence=0.96,
                ttl_seconds=300,
                rollback={"type": "remove_nftables_rule", "chain": "input", "rule_comment": "defensa-azul inc-test"},
            )
        )
        self.assertEqual(DecisionStatus.DENIED, decision.status)

    def test_lab_linux_nftables_block_rejects_unapproved_port(self):
        self.config["targets"]["linux-server01"] = {
            "mode": "enforce",
            "allowed_actions": ["linux_nftables_block"],
            "minimum_confidence": 0.70,
            "maximum_ttl_seconds": 300,
            "linux_nftables": {
                "allowed_sources": ["10.10.10.151"],
                "allowed_ports": [22],
                "allowed_chains": ["defensa_azul_input"],
                "rule_comment_prefix": "defensa-azul ",
            },
        }
        decision = SafetyGate(self.config).evaluate(
            proposal(
                target_id="linux-server01",
                action_type="linux_nftables_block",
                resource='{"src_ip":"10.10.10.151","protocol":"tcp","dst_port":5432,"chain":"defensa_azul_input","rule_comment":"defensa-azul inc-test"}',
                confidence=0.96,
                ttl_seconds=300,
                rollback={
                    "type": "remove_nftables_rule",
                    "chain": "defensa_azul_input",
                    "rule_comment": "defensa-azul inc-test",
                },
            )
        )
        self.assertEqual(DecisionStatus.DENIED, decision.status)

    def test_lab_linux_nftables_block_rejects_rollback_mismatch(self):
        self.config["targets"]["linux-server01"] = {
            "mode": "enforce",
            "allowed_actions": ["linux_nftables_block"],
            "minimum_confidence": 0.70,
            "maximum_ttl_seconds": 300,
            "linux_nftables": {
                "allowed_sources": ["10.10.10.151"],
                "allowed_ports": [22],
                "allowed_chains": ["defensa_azul_input"],
                "rule_comment_prefix": "defensa-azul ",
            },
        }
        decision = SafetyGate(self.config).evaluate(
            proposal(
                target_id="linux-server01",
                action_type="linux_nftables_block",
                resource='{"src_ip":"10.10.10.151","protocol":"tcp","dst_port":22,"chain":"defensa_azul_input","rule_comment":"defensa-azul inc-test"}',
                confidence=0.96,
                ttl_seconds=300,
                rollback={
                    "type": "remove_nftables_rule",
                    "chain": "defensa_azul_input",
                    "rule_comment": "defensa-azul wrong-comment",
                },
            )
        )
        self.assertEqual(DecisionStatus.DENIED, decision.status)


if __name__ == "__main__":
    unittest.main()

