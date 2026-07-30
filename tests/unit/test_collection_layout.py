from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class CollectionLayoutTests(unittest.TestCase):
    def test_collection_metadata_and_dependencies(self) -> None:
        galaxy = yaml.safe_load((ROOT / "galaxy.yml").read_text())
        self.assertEqual(galaxy["namespace"], "sgt_trojan")
        self.assertEqual(galaxy["name"], "checkpoint_automation")
        self.assertEqual(
            galaxy["dependencies"]["check_point.mgmt"], ">=6.9.0,<7.0.0"
        )
        self.assertEqual(
            galaxy["dependencies"]["check_point.gaia"], ">=7.0.0,<8.0.0"
        )
        self.assertEqual(
            galaxy["dependencies"]["ansible.netcommon"], ">=8.6.0,<9.0.0"
        )

        requirements = yaml.safe_load((ROOT / "requirements.yml").read_text())
        versions = {
            item["name"]: item["version"] for item in requirements["collections"]
        }
        self.assertEqual(versions["check_point.mgmt"], "6.9.0")
        self.assertEqual(versions["check_point.gaia"], "7.0.0")
        self.assertEqual(versions["ansible.netcommon"], "8.6.0")
        self.assertEqual(versions["ansible.utils"], "6.0.3")

    def test_required_public_documents_exist(self) -> None:
        for relative in (
            "README.md",
            "LICENSE",
            "LICENSES/GPL-3.0-or-later.txt",
            "docs/ARCHITECTURE.md",
            "docs/PARITY_MATRIX.md",
            "docs/UPSTREAM_MODULES.md",
            "docs/MANAGED_TARGET_DISCOVERY.md",
            "docs/CLUSTER_READINESS.md",
            "docs/DEPLOYMENT_AGENT.md",
            "docs/LIVE_READONLY_EXECUTOR.md",
            "docs/PACKAGE_VALIDATION.md",
            "docs/PACKAGE_ACQUISITION.md",
            "roles/checkpoint_deployment_agent_completion/defaults/main.yml",
            "roles/checkpoint_deployment_agent_completion/tasks/main.yml",
            "tests/utils/verify_live_readonly_graph.py",
            "tests/utils/verify_mgmt_check_mode.py",
            "tests/utils/verify_collection_policy.py",
            "tests/utils/run_deployment_agent_completion_focus.py",
            "tests/utils/verify_package_inventory_capability.py",
            "examples/managed_target_inventory.yml",
            "examples/managed_target_vars.yml",
            "examples/package_state_inventory.yml",
            "examples/deployment_agent_inventory.yml",
            "playbooks/live_readonly_deployment_agent.yml",
            "tests/integration/deployment_agent_observation_syntax.yml",
            "tests/integration/deployment_agent_completion_composition.yml",
            "tests/integration/deployment_agent_completion_syntax.yml",
            "tests/integration/deployment_agent_package_binding.yml",
            "tests/integration/deployment_agent_package_composition.yml",
            "tests/integration/package_state_acquisition_syntax.yml",
            "plugins/modules/cp_automation_deployment_agent_package_bind.py",
            "plugins/modules/cp_automation_deployment_agent_completion.py",
            "plugins/modules/cp_automation_deployment_agent_evidence.py",
            "plugins/modules/cp_automation_deployment_agent_next_plan.py",
            "plugins/modules/cp_automation_deployment_agent_reacquire_plan.py",
            "plugins/modules/cp_automation_deployment_agent_reconcile.py",
            "plugins/modules/cp_automation_deployment_agent_update_plan.py",
            "plugins/module_utils/deployment_agent_package.py",
            "plugins/module_utils/deployment_agent_completion.py",
            "plugins/module_utils/deployment_agent_evidence.py",
            "plugins/module_utils/deployment_agent_next.py",
            "plugins/module_utils/deployment_agent_reacquire.py",
            "plugins/module_utils/deployment_agent_reconcile.py",
            "plugins/module_utils/deployment_agent_update.py",
            "tests/unit/plugins/module_utils/test_deployment_agent_reconcile.py",
            "tests/unit/plugins/module_utils/test_deployment_agent_completion.py",
            "tests/unit/plugins/module_utils/test_deployment_agent_evidence.py",
            "tests/unit/plugins/module_utils/test_deployment_agent_next.py",
            "tests/unit/plugins/module_utils/test_deployment_agent_reacquire.py",
            "tests/unit/plugins/module_utils/test_deployment_agent_update.py",
            "tests/unit/plugins/modules/test_deployment_agent_reconcile_module.py",
            "tests/unit/plugins/modules/test_deployment_agent_completion_module.py",
            "tests/unit/plugins/modules/test_deployment_agent_evidence_module.py",
            "tests/unit/plugins/modules/test_deployment_agent_next_plan_module.py",
            "tests/unit/plugins/modules/test_deployment_agent_reacquire_plan_module.py",
            "tests/unit/plugins/modules/test_deployment_agent_update_plan_module.py",
            "tests/unit/test_deployment_agent_completion_role.py",
            "tests/unit/test_deployment_agent_completion_focus.py",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_license_text_matches_declared_identifier(self) -> None:
        text = (ROOT / "LICENSES/GPL-3.0-or-later.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("GNU GENERAL PUBLIC LICENSE", text[:200])
        self.assertIn("Version 3, 29 June 2007", text[:200])
        self.assertNotIn("Apache License", text[:200])
        self.assertGreaterEqual(len(text.splitlines()), 600)

    def test_deprecated_vendor_modules_are_not_referenced(self) -> None:
        for path in ROOT.rglob("*.yml"):
            if ".github" in path.parts:
                continue
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("check_point.mgmt.checkpoint_", content, str(path))
        for path in ROOT.rglob("*.py"):
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("cp_mgmt_" + "show_task", content, str(path))

    def test_discovery_examples_are_sanitized_and_tls_strict(self) -> None:
        inventory_path = ROOT / "examples" / "managed_target_inventory.yml"
        target_path = ROOT / "examples" / "managed_target_vars.yml"
        inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
        targets = yaml.safe_load(target_path.read_text(encoding="utf-8"))
        shared_vars = inventory["all"]["vars"]
        for name in (
            "checkpoint_api_sessions_group",
            "checkpoint_mgmt_api_version",
            "checkpoint_page_size",
            "checkpoint_domain_concurrency",
            "checkpoint_cluster_interface_limit",
            "checkpoint_management_task_timeout",
        ):
            self.assertIn(name, shared_vars)
        mds_vars = inventory["all"]["children"]["checkpoint_mds_system"][
            "hosts"
        ]["mds_system"]
        self.assertNotIn("checkpoint_api_sessions_group", mds_vars)
        self.assertNotIn("checkpoint_mgmt_api_version", mds_vars)
        self.assertNotIn("checkpoint_domain_concurrency", mds_vars)
        session_vars = inventory["all"]["children"][
            "checkpoint_api_sessions"
        ]["vars"]
        self.assertTrue(session_vars["ansible_httpapi_use_ssl"])
        self.assertTrue(session_vars["ansible_httpapi_validate_certs"])
        self.assertIn("vault_checkpoint_username", session_vars["ansible_user"])
        self.assertIn(
            "vault_checkpoint_password",
            session_vars["ansible_password"],
        )
        self.assertEqual(
            targets["checkpoint_target_ips"],
            ["198.51.100.10", "198.51.100.11"],
        )
        combined = inventory_path.read_text() + target_path.read_text()
        self.assertNotIn("192.168.", combined)

    def test_playbooks_do_not_use_command_like_modules(self) -> None:
        forbidden = (
            "ansible.builtin.command:",
            "ansible.builtin.shell:",
            "ansible.builtin.script:",
            "ansible.builtin.raw:",
        )
        for directory in ("playbooks", "roles"):
            root = ROOT / directory
            if not root.exists():
                continue
            for path in root.rglob("*.yml"):
                content = path.read_text(encoding="utf-8")
                for token in forbidden:
                    self.assertNotIn(token, content, str(path))

    def test_gaia_acquisition_has_no_local_execution_escape_hatch(self) -> None:
        paths = (
            ROOT / "plugins" / "modules" / "cp_automation_readiness_acquire.py",
            ROOT / "plugins" / "module_utils" / "readiness_acquisition.py",
            ROOT / "plugins" / "modules" / "cp_automation_package_state_acquire.py",
            ROOT / "plugins" / "module_utils" / "package_state_acquisition.py",
            ROOT / "plugins" / "modules" / "cp_automation_deployment_agent_acquire.py",
            ROOT / "plugins" / "module_utils" / "deployment_agent_acquisition.py",
        )
        forbidden = (
            "import subprocess",
            "from subprocess",
            "os.system",
            "caller_command",
        )
        for path in paths:
            content = path.read_text(encoding="utf-8")
            for token in forbidden:
                self.assertNotIn(token, content, str(path))


if __name__ == "__main__":
    unittest.main()
