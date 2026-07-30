from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
EXECUTOR = ROOT / "playbooks" / "live_readonly_managed_discovery.yml"
PREFLIGHT_TASKS = (
    ROOT / "roles" / "checkpoint_live_readonly_preflight" / "tasks" / "main.yml"
)


class LiveExecutorOrchestrationTests(unittest.TestCase):
    def test_preflight_play_is_first_and_local(self) -> None:
        plays = yaml.safe_load(EXECUTOR.read_text(encoding="utf-8"))
        self.assertEqual(plays[0]["hosts"], "localhost")
        self.assertFalse(plays[0]["gather_facts"])
        self.assertTrue(plays[0]["any_errors_fatal"])
        self.assertIn("checkpoint_live_readonly_preflight", str(plays[0]["roles"]))
        self.assertEqual(
            plays[1]["ansible.builtin.import_playbook"],
            "resolve_managed_cluster.yml",
        )

    def test_preflight_computes_booleans_without_passing_credentials(self) -> None:
        tasks = PREFLIGHT_TASKS.read_text(encoding="utf-8")
        module_task = next(
            task
            for task in yaml.safe_load(tasks)
            if "sgt_trojan.checkpoint_automation.cp_automation_live_preflight"
            in task
        )
        arguments = module_task[
            "sgt_trojan.checkpoint_automation.cp_automation_live_preflight"
        ]
        self.assertEqual(
            arguments["credential_presence"],
            "{{ checkpoint_live_credential_presence }}",
        )
        self.assertNotIn("ansible_password", str(arguments))
        self.assertIn("checkpoint_mds_api_host", str(arguments["management_target"]))
        self.assertTrue(module_task["no_log"])

    def test_preflight_module_precedes_every_check_point_request(self) -> None:
        executor_text = EXECUTOR.read_text(encoding="utf-8")
        self.assertNotIn("check_point.", executor_text)
        self.assertLess(
            executor_text.index("checkpoint_live_readonly_preflight"),
            executor_text.index("resolve_managed_cluster.yml"),
        )

    def test_each_management_request_role_requires_authorization(self) -> None:
        for role in ("checkpoint_mds_domains", "checkpoint_domain_inventory"):
            tasks = yaml.safe_load(
                (ROOT / "roles" / role / "tasks" / "main.yml").read_text(
                    encoding="utf-8"
                )
            )
            first = tasks[0]
            self.assertIn("ansible.builtin.include_role", first)
            self.assertIn(
                "checkpoint_live_readonly_preflight",
                first["ansible.builtin.include_role"]["name"],
            )
            self.assertEqual(
                first["vars"]["checkpoint_live_session_host"],
                "{{ inventory_hostname }}",
            )
            conditions = str(tasks[1]["ansible.builtin.assert"]["that"])
            self.assertIn("checkpoint_live_authorization", conditions)
            self.assertIn("managed_discovery", conditions)

    def test_every_vendor_request_is_immediately_preflighted(self) -> None:
        request_files = (
            ROOT / "roles" / "checkpoint_mds_domains" / "tasks" / "fetch_page.yml",
            ROOT
            / "roles"
            / "checkpoint_domain_inventory"
            / "tasks"
            / "fetch_gateways_page.yml",
            ROOT
            / "roles"
            / "checkpoint_domain_inventory"
            / "tasks"
            / "fetch_clusters_page.yml",
            ROOT
            / "roles"
            / "checkpoint_domain_inventory"
            / "tasks"
            / "fetch_cluster_detail.yml",
        )
        for path in request_files:
            tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
            request_indexes = [
                index
                for index, task in enumerate(tasks)
                if any(key.startswith("check_point.") for key in task)
            ]
            self.assertTrue(request_indexes, str(path))
            for index in request_indexes:
                self.assertGreater(index, 0)
                gate = tasks[index - 1]["ansible.builtin.include_role"]["name"]
                self.assertIn("checkpoint_live_readonly_preflight", gate)

    def test_preflight_network_module_and_fact_are_delegated_to_localhost(self) -> None:
        tasks = yaml.safe_load(PREFLIGHT_TASKS.read_text(encoding="utf-8"))
        module_task = next(
            task
            for task in tasks
            if "sgt_trojan.checkpoint_automation.cp_automation_live_preflight"
            in task
        )
        publish_task = next(
            task
            for task in tasks
            if task.get("name") == "Publish only sanitized live authorization"
        )
        self.assertEqual(module_task["delegate_to"], "localhost")
        self.assertEqual(module_task["connection"], "ansible.builtin.local")
        self.assertFalse(module_task["become"])
        self.assertEqual(publish_task["delegate_to"], "localhost")
        self.assertEqual(publish_task["connection"], "ansible.builtin.local")
        self.assertTrue(publish_task["delegate_facts"])

    def test_preflight_rejects_inventory_defined_remote_localhost(self) -> None:
        tasks = yaml.safe_load(PREFLIGHT_TASKS.read_text(encoding="utf-8"))
        conditions = str(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("hostvars['localhost'].ansible_connection", conditions)
        self.assertIn("hostvars['localhost'].ansible_host", conditions)
        content = PREFLIGHT_TASKS.read_text(encoding="utf-8")
        self.assertIn("hostvars[checkpoint_live_session_host]", content)


if __name__ == "__main__":
    unittest.main()
