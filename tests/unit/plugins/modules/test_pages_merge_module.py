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


PAGINATION_NAME = (
    "ansible_collections.sgt_trojan.checkpoint_automation."
    "plugins.module_utils.pagination"
)
for package in (
    "ansible_collections",
    "ansible_collections.sgt_trojan",
    "ansible_collections.sgt_trojan.checkpoint_automation",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils",
):
    sys.modules.setdefault(package, ModuleType(package))
load_module(ROOT / "plugins" / "module_utils" / "pagination.py", PAGINATION_NAME)
ansible_package = ModuleType("ansible")
ansible_module_utils = ModuleType("ansible.module_utils")
ansible_basic = ModuleType("ansible.module_utils.basic")
ansible_basic.AnsibleModule = object
sys.modules.setdefault("ansible", ansible_package)
sys.modules.setdefault("ansible.module_utils", ansible_module_utils)
sys.modules.setdefault("ansible.module_utils.basic", ansible_basic)
wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_pages_merge.py",
    "pages_merge_wrapper",
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


class PagesMergeModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = wrapper.AnsibleModule
        wrapper.AnsibleModule = FakeAnsibleModule

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original

    def test_success_is_read_only_and_returns_merged_shape(self) -> None:
        FakeAnsibleModule.params = {
            "pages": [
                {
                    "offset": 0,
                    "response": {
                        "offset": 0,
                        "total": 1,
                        "objects": [{"uid": "object-1"}],
                    },
                }
            ],
            "result_keys": ["objects"],
        }
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertEqual(caught.exception.payload["merged"]["total"], 1)
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])
        pages_spec = FakeAnsibleModule.init_kwargs["argument_spec"]["pages"]
        self.assertEqual(set(pages_spec["options"]), {"offset", "response"})
        self.assertTrue(pages_spec["options"]["offset"]["required"])
        self.assertTrue(pages_spec["options"]["response"]["required"])

    def test_failure_uses_discovery_incomplete_category(self) -> None:
        FakeAnsibleModule.params = {
            "pages": [
                {
                    "offset": 0,
                    "response": {
                        "offset": 1,
                        "total": 0,
                        "objects": [],
                    },
                }
            ],
            "result_keys": ["objects"],
        }
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertEqual(
            caught.exception.payload["category"],
            "DISCOVERY_INCOMPLETE",
        )


if __name__ == "__main__":
    unittest.main()
