import unittest

from defensa_azul.runtime import AgentRegistry


class RuntimeTests(unittest.TestCase):
    def test_incident_dispatches_three_independent_analysts(self):
        registry = AgentRegistry.from_file("agents/roles.json")
        work = registry.dispatch(
            {
                "event_type": "defense.incident.opened",
                "event_id": "evt-1",
                "run_id": "run-1",
                "target_id": "target-1",
                "incident_id": "inc-1",
            }
        )
        self.assertEqual(
            {"behavior-analyst", "exploit-analyst", "integrity-analyst"},
            {item.role_id for item in work},
        )
        self.assertTrue(all(item.input_contract == "sanitized_event_ids_only" for item in work))

    def test_only_arbiter_may_approve(self):
        registry = AgentRegistry.from_file("agents/roles.json")
        approvers = [role.id for role in registry.roles.values() if role.may_approve_actions]
        self.assertEqual(["safety-arbiter"], approvers)


if __name__ == "__main__":
    unittest.main()

