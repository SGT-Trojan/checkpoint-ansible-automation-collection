from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from importlib import import_module
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

from tests.unit.plugins.modules.test_deployment_agent_evidence_module import (
    ExitJson,
    FailJson,
    FakeAnsibleModule,
)


class DeploymentAgentNextPlanModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ansible = sys.modules.setdefault("ansible", ModuleType("ansible"))
        module_utils = sys.modules.setdefault(
            "ansible.module_utils", ModuleType("ansible.module_utils")
        )
        basic = sys.modules.setdefault(
            "ansible.module_utils.basic", ModuleType("ansible.module_utils.basic")
        )
        ansible.module_utils = module_utils
        module_utils.basic = basic
        basic.AnsibleModule = FakeAnsibleModule

        collections = sys.modules.setdefault(
            "ansible_collections", ModuleType("ansible_collections")
        )
        sgt_trojan = sys.modules.setdefault(
            "ansible_collections.sgt_trojan", ModuleType("sgt_trojan")
        )
        checkpoint = sys.modules.setdefault(
            "ansible_collections.sgt_trojan.checkpoint_automation",
            ModuleType("checkpoint_automation"),
        )
        plugins = sys.modules.setdefault(
            "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
            ModuleType("plugins"),
        )
        imported_utils = import_module("plugins.module_utils")
        FakeAnsibleModule.params = {
            "update_plan": {},
            "reacquisition_plan": {},
            "target_states": [],
            "evidence": {},
        }
        prefix = (
            "ansible_collections.sgt_trojan.checkpoint_automation.plugins."
            "module_utils."
        )
        sys.modules[prefix[:-1]] = imported_utils
        sys.modules[prefix + "deployment_agent_reconcile"] = import_module(
            "plugins.module_utils.deployment_agent_reconcile"
        )
        sys.modules[prefix + "deployment_agent_reacquire"] = import_module(
            "plugins.module_utils.deployment_agent_reacquire"
        )
        sys.modules[prefix + "deployment_agent_evidence"] = import_module(
            "plugins.module_utils.deployment_agent_evidence"
        )
        sys.modules[prefix + "deployment_agent_next"] = import_module(
            "plugins.module_utils.deployment_agent_next"
        )
        collections.sgt_trojan = sgt_trojan
        sgt_trojan.checkpoint_automation = checkpoint
        checkpoint.plugins = plugins
        plugins.module_utils = imported_utils
        cls.module = import_module(
            "plugins.modules.cp_automation_deployment_agent_next_plan"
        )

    def test_argument_spec_and_check_mode(self) -> None:
        with patch.object(
            self.module,
            "plan_next_deployment_agent_update",
            return_value={"plan_sha256": "a" * 64},
        ):
            with self.assertRaises(ExitJson) as caught:
                self.module.run_module()
        self.assertFalse(caught.exception.args[0]["changed"])
        self.assertTrue(FakeAnsibleModule.last_supports_check_mode)
        self.assertEqual(
            set(FakeAnsibleModule.last_argument_spec),
            {"update_plan", "reacquisition_plan", "target_states", "evidence"},
        )

    def test_validation_failure_is_sanitized(self) -> None:
        error = self.module.DeploymentAgentNextError(
            "UPDATE_COMPLETE", "no pending peer"
        )
        with patch.object(
            self.module, "plan_next_deployment_agent_update", side_effect=error
        ):
            with self.assertRaises(FailJson) as caught:
                self.module.run_module()
        self.assertEqual(caught.exception.args[0]["category"], "UPDATE_COMPLETE")


if __name__ == "__main__":
    unittest.main()
