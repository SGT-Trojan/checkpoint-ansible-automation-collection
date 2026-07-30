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


class DeploymentAgentCompletionModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.original_params = dict(FakeAnsibleModule.params)
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
        prefix = (
            "ansible_collections.sgt_trojan.checkpoint_automation.plugins."
            "module_utils."
        )
        sys.modules[prefix[:-1]] = imported_utils
        for name in (
            "deployment_agent_reconcile",
            "deployment_agent_reacquire",
            "deployment_agent_evidence",
            "deployment_agent_next",
            "deployment_agent_completion",
        ):
            sys.modules[prefix + name] = import_module(
                "plugins.module_utils." + name
            )
        collections.sgt_trojan = sgt_trojan
        sgt_trojan.checkpoint_automation = checkpoint
        checkpoint.plugins = plugins
        plugins.module_utils = imported_utils
        FakeAnsibleModule.params = {
            "first_update_plan": {},
            "first_reacquisition_plan": {},
            "first_target_states": [],
            "first_evidence": {},
            "second_reacquisition_plan": {},
            "final_target_states": [],
            "final_evidence": {},
        }
        cls.module = import_module(
            "plugins.modules.cp_automation_deployment_agent_completion"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        FakeAnsibleModule.params = cls.original_params

    def test_argument_spec_and_check_mode(self) -> None:
        with patch.object(
            self.module,
            "attest_deployment_agent_completion",
            return_value={"completion_sha256": "a" * 64},
        ):
            with self.assertRaises(ExitJson) as caught:
                self.module.run_module()
        self.assertFalse(caught.exception.args[0]["changed"])
        self.assertTrue(FakeAnsibleModule.last_supports_check_mode)
        self.assertEqual(
            set(FakeAnsibleModule.last_argument_spec),
            {
                "first_update_plan",
                "first_reacquisition_plan",
                "first_target_states",
                "first_evidence",
                "second_reacquisition_plan",
                "final_target_states",
                "final_evidence",
            },
        )

    def test_validation_failure_is_sanitized(self) -> None:
        error = self.module.DeploymentAgentCompletionError(
            "UPDATE_INCOMPLETE", "not complete"
        )
        with patch.object(
            self.module,
            "attest_deployment_agent_completion",
            side_effect=error,
        ):
            with self.assertRaises(FailJson) as caught:
                self.module.run_module()
        result = caught.exception.args[0]
        self.assertFalse(result["changed"])
        self.assertEqual(result["category"], "UPDATE_INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
