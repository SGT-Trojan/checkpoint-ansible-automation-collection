from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "roles" / "checkpoint_readiness_acquisition" / "tasks" / "main.yml"
DEFAULTS = (
    ROOT
    / "roles"
    / "checkpoint_readiness_acquisition"
    / "defaults"
    / "main.yml"
)


class ReadinessOrchestrationTests(unittest.TestCase):
    def test_role_uses_vendor_feature_facts_and_typed_custom_module(self) -> None:
        tasks = TASKS.read_text(encoding="utf-8")
        self.assertIn("check_point.gaia.cp_gaia_features_facts:", tasks)
        self.assertIn(
            "sgt_trojan.checkpoint_automation.cp_automation_readiness_acquire:",
            tasks,
        )
        self.assertNotIn("check_point.gaia.cp_gaia_run_script:", tasks)

    def test_role_binds_address_to_inventory_and_requires_exact_local_name(self) -> None:
        tasks = TASKS.read_text(encoding="utf-8")
        self.assertIn('member_address: "{{ ansible_host }}"', tasks)
        defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        self.assertIn('address: "{{ ansible_host }}"', tasks)
        self.assertIn('name: "{{ checkpoint_readiness_member_name }}"', tasks)
        self.assertNotIn("checkpoint_readiness_member_address", tasks)
        self.assertNotIn("checkpoint_readiness_member_address", defaults)

    def test_role_requires_tls_verified_gaia_httpapi(self) -> None:
        tasks = TASKS.read_text(encoding="utf-8")
        for control in (
            "ansible.netcommon.httpapi",
            "check_point.gaia.checkpoint",
            "ansible_httpapi_use_ssl",
            "ansible_httpapi_validate_certs",
            "expert_api_runscript",
        ):
            self.assertIn(control, tasks)

    def test_role_surfaces_only_safe_failure_identity(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        acquire = next(
            task
            for task in tasks
            if "sgt_trojan.checkpoint_automation.cp_automation_readiness_acquire" in task
        )
        failure = next(
            task
            for task in tasks
            if task.get("name") == "Stop after a failed readiness acquisition"
        )
        self.assertFalse(acquire["failed_when"])
        message = failure["ansible.builtin.fail"]["msg"]
        self.assertIn("checkpoint_readiness_acquired.category", message)
        self.assertIn("checkpoint_readiness_acquired.task_id", message)
        self.assertNotIn("sections", message)
        self.assertEqual(
            failure["when"],
            "checkpoint_readiness_acquired.acquisition is not defined",
        )

    def test_acquired_evidence_is_not_logged(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        sensitive_tasks = [
            task
            for task in tasks
            if (
                "sgt_trojan.checkpoint_automation.cp_automation_readiness_acquire"
                in task
                or "sgt_trojan.checkpoint_automation.cp_automation_cluster_observe"
                in task
                or "ansible.builtin.set_fact" in task
            )
        ]
        self.assertEqual(len(sensitive_tasks), 3)
        self.assertTrue(all(task.get("no_log") is True for task in sensitive_tasks))


if __name__ == "__main__":
    unittest.main()
