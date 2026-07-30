from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
TASKS = (
    ROOT
    / "roles"
    / "checkpoint_package_state_acquisition"
    / "tasks"
    / "main.yml"
)
DEFAULTS = (
    ROOT
    / "roles"
    / "checkpoint_package_state_acquisition"
    / "defaults"
    / "main.yml"
)
INVENTORY = ROOT / "examples" / "package_state_inventory.yml"


class PackageStateOrchestrationTests(unittest.TestCase):
    def test_role_uses_feature_facts_and_fixed_typed_module(self) -> None:
        content = TASKS.read_text(encoding="utf-8")
        self.assertIn("check_point.gaia.cp_gaia_features_facts:", content)
        self.assertIn(
            "sgt_trojan.checkpoint_automation."
            "cp_automation_package_state_acquire:",
            content,
        )
        self.assertNotIn("check_point.gaia.cp_gaia_run_script:", content)

    def test_role_binds_address_and_target_identity_to_inventory(self) -> None:
        content = TASKS.read_text(encoding="utf-8")
        defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        self.assertIn("member_address: \"{{ ansible_host }}\"", content)
        self.assertIn("target_id: \"{{ inventory_hostname }}\"", content)
        self.assertNotIn("checkpoint_package_state_target_id", content)
        self.assertNotIn("checkpoint_package_state_target_id", defaults)

    def test_role_requires_explicit_tls_mode_and_gaia_feature(self) -> None:
        content = TASKS.read_text(encoding="utf-8")
        defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        self.assertIs(
            defaults["checkpoint_package_state_lab_tls_exception_acknowledged"],
            False,
        )
        for control in (
            "ansible.netcommon.httpapi",
            "check_point.gaia.checkpoint",
            "ansible_httpapi_use_ssl",
            "ansible_httpapi_validate_certs is boolean",
            "tls_validation_mode",
            "lab_tls_exception_acknowledged",
            "is sameas true",
            "is sameas false",
            "expert_api_runscript",
        ):
            self.assertIn(control, content)

    def test_role_surfaces_only_safe_failure_identity(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        action = (
            "sgt_trojan.checkpoint_automation."
            "cp_automation_package_state_acquire"
        )
        acquire = next(task for task in tasks if action in task)
        failure = next(
            task
            for task in tasks
            if task.get("name") == "Stop after a failed package-state acquisition"
        )
        self.assertFalse(acquire["failed_when"])
        message = failure["ansible.builtin.fail"]["msg"]
        self.assertIn("checkpoint_package_state_acquired.category", message)
        self.assertIn("checkpoint_package_state_acquired.reason", message)
        self.assertIn("checkpoint_package_state_acquired.shape", message)
        self.assertIn("checkpoint_package_state_acquired.task_id", message)
        self.assertNotIn("checkpoint_package_state_acquired.msg", message)
        self.assertNotIn("installed_packages", message)
        self.assertEqual(
            failure["when"],
            "checkpoint_package_state_acquired.observation is not defined",
        )

    def test_acquired_and_published_state_are_not_logged(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        sensitive = [
            task
            for task in tasks
            if (
                "sgt_trojan.checkpoint_automation."
                "cp_automation_package_state_acquire" in task
                or task.get("name")
                == "Publish the inventory-bound package target state"
            )
        ]
        self.assertEqual(len(sensitive), 2)
        self.assertTrue(all(task.get("no_log") is True for task in sensitive))
        publish = next(
            task for task in sensitive if "ansible.builtin.set_fact" in task
        )
        self.assertFalse(publish["changed_when"])
        self.assertEqual(
            set(
                publish["ansible.builtin.set_fact"][
                    "checkpoint_package_target_state"
                ]
            ),
            {
                "step_name",
                "target_id",
                "installed_packages",
                "installed_packages_complete",
                "restore_point_free_bytes",
            },
        )

    def test_example_inventory_is_sanitized_and_tls_strict(self) -> None:
        inventory = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
        group = inventory["all"]["children"]["checkpoint_package_state_members"]
        variables = group["vars"]
        self.assertTrue(variables["ansible_httpapi_use_ssl"])
        self.assertTrue(variables["ansible_httpapi_validate_certs"])
        self.assertIn("vault_checkpoint_username", variables["ansible_user"])
        self.assertIn("vault_checkpoint_password", variables["ansible_password"])
        self.assertEqual(
            [host["ansible_host"] for host in group["hosts"].values()],
            ["192.0.2.10", "192.0.2.11"],
        )
        self.assertNotIn("192.168.", INVENTORY.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
