from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
import unittest


ROOT = Path(__file__).resolve().parents[4]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


DOMAIN_PLAN_NAME = (
    "ansible_collections.sgt_trojan.checkpoint_automation."
    "plugins.module_utils.domain_plan"
)
for package in (
    "ansible_collections",
    "ansible_collections.sgt_trojan",
    "ansible_collections.sgt_trojan.checkpoint_automation",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils",
):
    sys.modules.setdefault(package, ModuleType(package))
load_module(ROOT / "plugins" / "module_utils" / "domain_plan.py", DOMAIN_PLAN_NAME)
ansible_package = ModuleType("ansible")
ansible_module_utils = ModuleType("ansible.module_utils")
ansible_basic = ModuleType("ansible.module_utils.basic")
ansible_basic.AnsibleModule = object
sys.modules.setdefault("ansible", ansible_package)
sys.modules.setdefault("ansible.module_utils", ansible_module_utils)
sys.modules.setdefault("ansible.module_utils.basic", ansible_basic)
wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_domain_plan.py",
    "domain_plan_wrapper",
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


def valid_domain() -> dict:
    return {
        "name": "Domain-A",
        "domain-type": "domain",
        "servers": [
            {
                "name": "CMA-A",
                "type": "management server",
                "ipv4-address": "198.51.100.10",
                "active": True,
            }
        ],
    }


class DomainPlanModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = wrapper.AnsibleModule
        wrapper.AnsibleModule = FakeAnsibleModule

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original

    def test_success_is_read_only_and_returns_plan(self) -> None:
        FakeAnsibleModule.params = {"domain_records": [valid_domain()]}
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertEqual(
            caught.exception.payload["plan"][0]["session_name"],
            "checkpoint_domain_session_0001",
        )
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])

    def test_failure_preserves_stable_category(self) -> None:
        FakeAnsibleModule.params = {"domain_records": []}
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertEqual(
            caught.exception.payload["category"],
            "DISCOVERY_INCOMPLETE",
        )

    def test_argument_spec_is_required_list_of_dicts(self) -> None:
        FakeAnsibleModule.params = {"domain_records": [valid_domain()]}
        with self.assertRaises(ExitJson):
            wrapper.run_module()
        spec = FakeAnsibleModule.init_kwargs["argument_spec"]["domain_records"]
        self.assertEqual(
            spec,
            {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
