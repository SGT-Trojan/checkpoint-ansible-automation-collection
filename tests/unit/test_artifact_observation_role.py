from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
TASKS = (
    ROOT / "roles" / "checkpoint_artifact_observation" / "tasks" / "main.yml"
)


class ArtifactObservationRoleTests(unittest.TestCase):
    def test_role_pins_observer_to_genuine_localhost(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        conditions = str(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("hostvars['localhost'].ansible_connection", conditions)
        self.assertIn("hostvars['localhost'].ansible_host", conditions)
        self.assertIn("ansible_connection | default('local')", conditions)
        self.assertIn("ansible_host | default('localhost')", conditions)
        module_task = tasks[1]
        action = (
            "sgt_trojan.checkpoint_automation."
            "cp_automation_artifact_observe"
        )
        self.assertIn(action, module_task)
        self.assertEqual(module_task["delegate_to"], "localhost")
        self.assertEqual(module_task["connection"], "ansible.builtin.local")
        self.assertFalse(module_task["become"])
        self.assertFalse(module_task["changed_when"])


if __name__ == "__main__":
    unittest.main()
