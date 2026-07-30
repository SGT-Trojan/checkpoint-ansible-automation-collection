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
    ROOT / "plugins" / "module_utils" / "live_preflight.py",
    f"{PACKAGE}.live_preflight",
)
ansible_package = ModuleType("ansible")
ansible_module_utils = ModuleType("ansible.module_utils")
ansible_basic = ModuleType("ansible.module_utils.basic")
ansible_basic.AnsibleModule = object
sys.modules.setdefault("ansible", ansible_package)
sys.modules.setdefault("ansible.module_utils", ansible_module_utils)
sys.modules.setdefault("ansible.module_utils.basic", ansible_basic)
wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_live_preflight.py",
    "live_preflight_wrapper",
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


class LivePreflightModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_module = wrapper.AnsibleModule
        self.original_authorize = wrapper.authorize_live_readonly
        wrapper.AnsibleModule = FakeAnsibleModule
        FakeAnsibleModule.params = {
            "lease": {},
            "management_target": "sanitized",
            "member_targets": [],
            "credential_presence": {
                "management_username": True,
                "management_secret": True,
            },
            "executor_check_mode": True,
        }

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original_module
        wrapper.authorize_live_readonly = self.original_authorize

    def test_wrapper_is_read_only_and_does_not_accept_credentials(self) -> None:
        captured = {}

        def authorize(**kwargs):
            captured.update(kwargs)
            return {"authorized": True}

        wrapper.authorize_live_readonly = authorize
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])
        argument_spec = FakeAnsibleModule.init_kwargs["argument_spec"]
        for forbidden in (
            "username",
            "password",
            "api_key",
            "credential_value",
            "mutation",
        ):
            self.assertNotIn(forbidden, argument_spec)
        self.assertIs(captured["check_mode"], True)

    def test_wrapper_preserves_safe_failure_category(self) -> None:
        def authorize(**kwargs):
            raise utility.LivePreflightError(
                "MUTATION_BLOCKED",
                "offline hostile request",
            )

        wrapper.authorize_live_readonly = authorize
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "MUTATION_BLOCKED")
        self.assertFalse(caught.exception.payload["changed"])


if __name__ == "__main__":
    unittest.main()
