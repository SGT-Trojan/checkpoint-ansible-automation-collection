from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from importlib import import_module
import sys
from types import ModuleType
import unittest
from unittest.mock import patch


class ExitJson(Exception):
    pass


class FailJson(Exception):
    pass


class FakeAnsibleModule:
    params = {"update_plan": {}, "reacquisition_plan": {}, "target_states": []}
    last_argument_spec = None
    last_supports_check_mode = None

    def __init__(self, argument_spec, supports_check_mode):
        type(self).last_argument_spec = argument_spec
        type(self).last_supports_check_mode = supports_check_mode
        self.params = dict(type(self).params)

    def exit_json(self, **kwargs):
        raise ExitJson(kwargs)

    def fail_json(self, **kwargs):
        raise FailJson(kwargs)


class DeploymentAgentEvidenceModuleTests(unittest.TestCase):
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

        imported_utils = import_module("plugins.module_utils")
        prefix = (
            "ansible_collections.sgt_trojan.checkpoint_automation.plugins."
            "module_utils."
        )
        sys.modules[prefix + "deployment_agent_reconcile"] = import_module(
            "plugins.module_utils.deployment_agent_reconcile"
        )
        sys.modules[prefix + "deployment_agent_reacquire"] = import_module(
            "plugins.module_utils.deployment_agent_reacquire"
        )
        sys.modules[prefix + "deployment_agent_evidence"] = import_module(
            "plugins.module_utils.deployment_agent_evidence"
        )
        sys.modules[prefix[:-1]] = imported_utils
        cls.module = import_module(
            "plugins.modules.cp_automation_deployment_agent_evidence"
        )

    def test_argument_spec_and_check_mode(self) -> None:
        with patch.object(
            self.module,
            "compose_deployment_agent_evidence",
            return_value={"evidence_chain_sha256": "a" * 64},
        ):
            with self.assertRaises(ExitJson) as caught:
                self.module.run_module()
        result = caught.exception.args[0]
        self.assertFalse(result["changed"])
        self.assertTrue(FakeAnsibleModule.last_supports_check_mode)
        self.assertEqual(
            set(FakeAnsibleModule.last_argument_spec),
            {"update_plan", "reacquisition_plan", "target_states"},
        )

    def test_validation_failure_is_sanitized(self) -> None:
        error = self.module.DeploymentAgentEvidenceError(
            "REACQUISITION_MISMATCH", "reacquisition plan mismatch"
        )
        with patch.object(
            self.module,
            "compose_deployment_agent_evidence",
            side_effect=error,
        ):
            with self.assertRaises(FailJson) as caught:
                self.module.run_module()
        result = caught.exception.args[0]
        self.assertFalse(result["changed"])
        self.assertEqual(result["category"], "REACQUISITION_MISMATCH")


if __name__ == "__main__":
    unittest.main()
