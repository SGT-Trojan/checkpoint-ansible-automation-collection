from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
import unittest


ROOT = Path(__file__).resolve().parents[4]
PACKAGE = (
    "ansible_collections.sgt_trojan.checkpoint_automation."
    "plugins.module_utils"
)
for package in (
    "ansible_collections",
    "ansible_collections.sgt_trojan",
    "ansible_collections.sgt_trojan.checkpoint_automation",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
    PACKAGE,
):
    sys.modules.setdefault(package, ModuleType(package))


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


deployment_agent = load_module(
    ROOT / "plugins" / "module_utils" / "deployment_agent.py",
    f"{PACKAGE}.deployment_agent",
)
sys.modules.setdefault("ansible", ModuleType("ansible"))
sys.modules.setdefault("ansible.module_utils", ModuleType("ansible.module_utils"))
ansible_basic = sys.modules.setdefault(
    "ansible.module_utils.basic",
    ModuleType("ansible.module_utils.basic"),
)
ansible_basic.AnsibleModule = object
wrapper = load_module(
    ROOT
    / "plugins"
    / "modules"
    / "cp_automation_deployment_agent_decide.py",
    "deployment_agent_decide_wrapper",
)


class ExitJson(Exception):
    def __init__(self, payload: dict):
        super().__init__()
        self.payload = payload


class FailJson(Exception):
    def __init__(self, payload: dict):
        super().__init__()
        self.payload = payload


class FakeAnsibleModule:
    params: dict = {}
    init_kwargs: dict = {}

    def __init__(self, **kwargs):
        type(self).init_kwargs = kwargs
        self.params = dict(type(self).params)
        self.check_mode = True

    def exit_json(self, **kwargs):
        raise ExitJson(kwargs)

    def fail_json(self, **kwargs):
        raise FailJson(kwargs)


class DeploymentAgentDecisionModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_module = wrapper.AnsibleModule
        wrapper.AnsibleModule = FakeAnsibleModule
        FakeAnsibleModule.params = {
            "observation": {
                "enabled": True,
                "build": 2771,
                "cloud_state": "current",
            },
            "required_build": 2771,
            "expected_build": None,
        }

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original_module

    def test_success_is_read_only_and_typed(self) -> None:
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertTrue(caught.exception.payload["decision"]["ready"])
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])
        spec = FakeAnsibleModule.init_kwargs["argument_spec"]
        self.assertTrue(spec["observation"]["required"])
        self.assertTrue(spec["required_build"]["required"])

    def test_not_ready_is_data_not_module_failure(self) -> None:
        FakeAnsibleModule.params["observation"]["build"] = 2672
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["decision"]["ready"])
        self.assertTrue(caught.exception.payload["decision"]["requires_update"])

    def test_invalid_contract_fails_closed_without_change(self) -> None:
        FakeAnsibleModule.params["required_build"] = 0
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "DECISION_INVALID")
        self.assertFalse(caught.exception.payload["changed"])


if __name__ == "__main__":
    unittest.main()
