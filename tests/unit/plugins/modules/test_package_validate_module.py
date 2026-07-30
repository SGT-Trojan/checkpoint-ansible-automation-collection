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


utility = load_module(
    ROOT / "plugins" / "module_utils" / "package_validation.py",
    f"{PACKAGE}.package_validation",
)
ansible_package = ModuleType("ansible")
ansible_module_utils = ModuleType("ansible.module_utils")
ansible_basic = ModuleType("ansible.module_utils.basic")
ansible_basic.AnsibleModule = object
sys.modules.setdefault("ansible", ansible_package)
sys.modules.setdefault("ansible.module_utils", ansible_module_utils)
sys.modules.setdefault("ansible.module_utils.basic", ansible_basic)
wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_package_validate.py",
    "package_validate_wrapper",
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

    def exit_json(self, **kwargs):
        raise ExitJson(kwargs)

    def fail_json(self, **kwargs):
        raise FailJson(kwargs)


class PackageValidateModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_module = wrapper.AnsibleModule
        self.original_validate = wrapper.validate_package_contract
        wrapper.AnsibleModule = FakeAnsibleModule
        FakeAnsibleModule.params = {
            "package_steps": [],
            "artifacts": [],
            "target_states": [],
        }

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original_module
        wrapper.validate_package_contract = self.original_validate

    def test_success_is_read_only_and_check_mode_safe(self) -> None:
        wrapper.validate_package_contract = lambda *args: {"valid": True}
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertTrue(caught.exception.payload["validation"]["valid"])
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])

    def test_failure_preserves_category_and_changed_false(self) -> None:
        def reject(*args):
            raise utility.PackageValidationError(
                "CHECKSUM_MISMATCH",
                "offline mismatch",
            )

        wrapper.validate_package_contract = reject
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "CHECKSUM_MISMATCH")
        self.assertFalse(caught.exception.payload["changed"])


if __name__ == "__main__":
    unittest.main()
