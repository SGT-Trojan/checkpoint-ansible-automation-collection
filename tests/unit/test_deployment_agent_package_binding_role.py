from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles" / "checkpoint_deployment_agent_package_binding"
TASKS = ROLE / "tasks" / "main.yml"
DEFAULTS = ROLE / "defaults" / "main.yml"


class DeploymentAgentPackageBindingRoleTests(unittest.TestCase):
    def test_role_composes_only_reviewed_offline_boundaries(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        ignored = {"name", "vars", "register", "changed_when"}
        actions = [next(key for key in task if key not in ignored) for task in tasks]
        self.assertEqual(
            actions,
            [
                "ansible.builtin.assert",
                "ansible.builtin.include_role",
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_package_validate"
                ),
                "ansible.builtin.assert",
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_deployment_agent_package_bind"
                ),
                "ansible.builtin.set_fact",
            ],
        )
        content = TASKS.read_text(encoding="utf-8")
        self.assertIn(
            "checkpoint_artifact_observation.artifact",
            content,
        )
        self.assertNotIn(
            "checkpoint_artifact_observation.observation",
            content,
        )
        for prohibited in (
            "ansible.builtin.command",
            "ansible.builtin.shell",
            "ansible.builtin.raw",
            "cp_automation_deployment_agent_acquire",
            "checkpoint_deployment_agent_live_lease",
        ):
            self.assertNotIn(prohibited, content)

    def test_role_requires_one_step_and_explicit_builds(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        conditions = str(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn(
            "checkpoint_deployment_agent_package_steps | length == 1",
            conditions,
        )
        self.assertIn(
            "checkpoint_deployment_agent_package_required_build is integer",
            conditions,
        )
        self.assertIn(
            "checkpoint_deployment_agent_package_expected_build is integer",
            conditions,
        )
        self.assertIn(
            'ansible_connection | default("local")',
            conditions,
        )
        self.assertIn(
            'ansible_host | default("localhost")',
            conditions,
        )
        defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        self.assertIsNone(
            defaults["checkpoint_deployment_agent_package_required_build"]
        )
        self.assertIsNone(
            defaults["checkpoint_deployment_agent_package_expected_build"]
        )


if __name__ == "__main__":
    unittest.main()
