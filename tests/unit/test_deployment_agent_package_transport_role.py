from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
TASKS = (
    ROOT
    / "roles"
    / "checkpoint_deployment_agent_package_transport"
    / "tasks"
    / "main.yml"
)


class DeploymentAgentPackageTransportRoleTests(unittest.TestCase):
    def test_role_is_ssh_inventory_bound_and_never_executes_update(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        conditions = str(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn('inventory_hostname != "localhost"', conditions)
        self.assertIn("ansible_connection", conditions)
        self.assertIn("ansible_host", conditions)

        action = (
            "sgt_trojan.checkpoint_automation."
            "cp_automation_deployment_agent_package_transport"
        )
        transport = tasks[1]
        self.assertIn(action, transport)
        self.assertFalse(transport["become"])
        self.assertTrue(transport["no_log"])

        text = TASKS.read_text(encoding="utf-8")
        self.assertNotIn("installer agent install", text)
        self.assertNotIn("cp_automation_deployment_agent_acquire", text)
        self.assertNotIn("cp_gaia_run_script", text)
        self.assertNotIn("cp_gaia_put_file", text)


if __name__ == "__main__":
    unittest.main()
