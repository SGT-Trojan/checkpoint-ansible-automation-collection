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
    / "cp_automation_deployment_agent_observe.py",
    "deployment_agent_observe_wrapper",
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


class DeploymentAgentObserveModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_module = wrapper.AnsibleModule
        wrapper.AnsibleModule = FakeAnsibleModule
        FakeAnsibleModule.params = {
            "status_output": (
                "Agent: Enabled\n"
                "Build number: 2771 (agent build is up to date)\n"
                "License: status omitted\n"
            )
        }

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original_module

    def test_success_is_read_only_normalized_and_hides_raw_input(self) -> None:
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertEqual(caught.exception.payload["observation"]["build"], 2771)
        self.assertNotIn("License", str(caught.exception.payload))
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])
        self.assertTrue(
            FakeAnsibleModule.init_kwargs["argument_spec"]["status_output"]["no_log"]
        )

    def test_malformed_status_fails_with_stable_category(self) -> None:
        raw_status = "Build number: private-content\n"
        FakeAnsibleModule.params["status_output"] = raw_status
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "STATUS_FORMAT")
        self.assertFalse(caught.exception.payload["changed"])
        self.assertNotIn("private-content", str(caught.exception.payload))


if __name__ == "__main__":
    unittest.main()
