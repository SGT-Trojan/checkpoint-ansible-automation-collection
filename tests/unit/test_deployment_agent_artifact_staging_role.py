from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
TASKS = (
    ROOT
    / "roles"
    / "checkpoint_deployment_agent_artifact_staging"
    / "tasks"
    / "main.yml"
)


class DeploymentAgentArtifactStagingRoleTests(unittest.TestCase):
    def test_role_is_local_preflight_bound_and_has_no_update_task(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        conditions = str(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("inventory_hostname == \"localhost\"", conditions)
        self.assertIn("hostvars[\"localhost\"].ansible_connection", conditions)
        self.assertIn("hostvars[\"localhost\"].ansible_host", conditions)

        stage_task = tasks[1]
        action = (
            "sgt_trojan.checkpoint_automation."
            "cp_automation_deployment_agent_artifact_stage"
        )
        self.assertIn(action, stage_task)
        self.assertEqual(stage_task["delegate_to"], "localhost")
        self.assertEqual(stage_task["connection"], "ansible.builtin.local")
        self.assertFalse(stage_task["become"])

        text = TASKS.read_text(encoding="utf-8")
        self.assertNotIn("installer agent install", text)
        self.assertNotIn("cp_automation_deployment_agent_acquire", text)
        self.assertNotIn("send_request", text)


if __name__ == "__main__":
    unittest.main()
