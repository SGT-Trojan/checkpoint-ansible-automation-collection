from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
TASKS = (
    ROOT
    / "roles"
    / "checkpoint_deployment_agent_observation"
    / "tasks"
    / "main.yml"
)
EXECUTOR = ROOT / "playbooks" / "live_readonly_deployment_agent.yml"
GUIDE = ROOT / "docs" / "DEPLOYMENT_AGENT.md"
INVENTORY = ROOT / "examples" / "deployment_agent_inventory.yml"
PREFLIGHT = (
    "sgt_trojan.checkpoint_automation."
    "cp_automation_deployment_agent_live_preflight"
)


class DeploymentAgentLiveOrchestrationTests(unittest.TestCase):
    def test_every_network_request_is_immediately_preflighted(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        requests = (
            "check_point.gaia.cp_gaia_features_facts",
            (
                "sgt_trojan.checkpoint_automation."
                "cp_automation_deployment_agent_acquire"
            ),
        )
        for request in requests:
            index = next(
                index for index, task in enumerate(tasks) if request in task
            )
            gate = tasks[index - 1]
            self.assertIn(PREFLIGHT, gate)
            self.assertTrue(gate["no_log"])
            self.assertEqual(gate["delegate_to"], "localhost")
            self.assertEqual(gate["connection"], "ansible.builtin.local")
            self.assertFalse(gate["become"])

    def test_role_binds_validated_expiry_and_never_passes_credentials(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        module_name = (
            "sgt_trojan.checkpoint_automation."
            "cp_automation_deployment_agent_acquire"
        )
        acquisition = next(task for task in tasks if module_name in task)
        self.assertIn(
            "checkpoint_deployment_agent_acquisition_authorization",
            acquisition[module_name]["authorization_expires_at"],
        )
        controls = str(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("ansible_checkpoint_target is not defined", controls)
        self.assertIn(
            "checkpoint_deployment_agent_live_member_targets | length == 2",
            controls,
        )
        for gate in (task for task in tasks if PREFLIGHT in task):
            arguments = gate[PREFLIGHT]
            self.assertEqual(
                arguments["credential_presence"],
                "{{ checkpoint_deployment_agent_credential_presence }}",
            )
            self.assertNotIn("ansible_password", str(arguments))

    def test_executor_uses_exact_group_and_serial_execution(self) -> None:
        plays = yaml.safe_load(EXECUTOR.read_text(encoding="utf-8"))
        self.assertEqual(len(plays), 2)
        self.assertEqual(plays[0]["hosts"], "localhost")
        self.assertEqual(
            plays[1]["hosts"],
            "checkpoint_deployment_agent_members",
        )
        self.assertEqual(plays[1]["serial"], 1)
        self.assertTrue(plays[1]["any_errors_fatal"])
        self.assertIn(
            "checkpoint_deployment_agent_observation",
            str(plays[1]["roles"]),
        )

    def test_role_publishes_observation_and_numeric_decision(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        controls = str(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("checkpoint_deployment_agent_required_build", controls)
        decision_name = (
            "sgt_trojan.checkpoint_automation."
            "cp_automation_deployment_agent_decide"
        )
        decision = next(task for task in tasks if decision_name in task)
        observation = decision[decision_name]["observation"]
        self.assertEqual(
            set(observation),
            {"enabled", "build", "cloud_state"},
        )
        self.assertNotEqual(
            observation,
            "{{ checkpoint_deployment_agent_acquired.observation }}",
        )
        self.assertEqual(
            decision[decision_name]["required_build"],
            "{{ checkpoint_deployment_agent_required_build }}",
        )
        published = tasks[-1]["ansible.builtin.set_fact"][
            "checkpoint_deployment_agent_target_state"
        ]
        self.assertEqual(
            set(published),
            {
                "step_name",
                "target_id",
                "enabled",
                "build",
                "cloud_state",
                "decision",
            },
        )

    def test_example_inventory_is_sanitized_and_tls_strict(self) -> None:
        inventory = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
        group = inventory["all"]["children"][
            "checkpoint_deployment_agent_members"
        ]
        variables = group["vars"]
        self.assertTrue(variables["ansible_httpapi_use_ssl"])
        self.assertTrue(variables["ansible_httpapi_validate_certs"])
        self.assertIn(
            "vault_checkpoint_username", variables["ansible_user"]
        )
        self.assertIn(
            "vault_checkpoint_password", variables["ansible_password"]
        )
        self.assertEqual(
            [host["ansible_host"] for host in group["hosts"].values()],
            ["192.0.2.10", "192.0.2.11"],
        )
        self.assertNotIn("192.168.", INVENTORY.read_text(encoding="utf-8"))

    def test_guide_keeps_lab_tls_exception_and_pending_strict_test_visible(
        self,
    ) -> None:
        content = " ".join(GUIDE.read_text(encoding="utf-8").split())
        for required in (
            "operation: deployment_agent_observation",
            "tls_validation_mode: strict",
            "tls_validation_mode: lab_unverified",
            "ansible_httpapi_validate_certs: false",
            "checkpoint_deployment_agent_lab_tls_exception_acknowledged: true",
            "Server identity and MITM protection are absent",
            "Certificate validation remains a required pending live test",
            "ansible-playbook --check ",
            "-i examples/deployment_agent_inventory.yml",
            "-e @deployment-agent-lease.yml",
        ):
            self.assertIn(required, content)


if __name__ == "__main__":
    unittest.main()
