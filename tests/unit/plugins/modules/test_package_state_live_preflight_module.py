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
    ROOT / "plugins" / "module_utils" / "package_state_live_preflight.py",
    f"{PACKAGE}.package_state_live_preflight",
)
ansible_package = ModuleType("ansible")
ansible_module_utils = ModuleType("ansible.module_utils")
ansible_basic = ModuleType("ansible.module_utils.basic")
ansible_basic.AnsibleModule = object
sys.modules.setdefault("ansible", ansible_package)
sys.modules.setdefault("ansible.module_utils", ansible_module_utils)
sys.modules.setdefault("ansible.module_utils.basic", ansible_basic)
wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_package_state_live_preflight.py",
    "package_state_live_preflight_wrapper",
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


class PackageStateLivePreflightModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_module = wrapper.AnsibleModule
        self.original_authorize = wrapper.authorize_package_state_readonly
        self.original_direct_controller = wrapper.require_direct_gaia_controller
        wrapper.AnsibleModule = FakeAnsibleModule
        wrapper.require_direct_gaia_controller = lambda: None
        FakeAnsibleModule.params = {
            "lease": {},
            "member_target": "198.51.100.10",
            "member_targets": ["198.51.100.10", "198.51.100.11"],
            "credential_presence": {
                "gaia_username": True,
                "gaia_secret": True,
            },
            "tls_validation_enabled": True,
            "lab_tls_exception_acknowledged": False,
        }

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original_module
        wrapper.authorize_package_state_readonly = self.original_authorize
        wrapper.require_direct_gaia_controller = self.original_direct_controller

    def test_wrapper_is_read_only_and_never_accepts_credential_values(self) -> None:
        captured = {}

        def authorize(**kwargs):
            captured.update(kwargs)
            return {"authorized": True}

        wrapper.authorize_package_state_readonly = authorize
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
            "command",
            "script",
            "path",
        ):
            self.assertNotIn(forbidden, argument_spec)
        self.assertIs(captured["check_mode"], True)
        self.assertIs(captured["tls_validation_enabled"], True)
        self.assertIs(captured["lab_tls_exception_acknowledged"], False)
        self.assertEqual(
            argument_spec["lease"]["options"]["tls_validation_mode"]["choices"],
            ["strict", "lab_unverified"],
        )
        self.assertNotIn("executor_check_mode", argument_spec)
        self.assertNotIn("options", argument_spec["credential_presence"])

    def test_wrapper_uses_ansible_check_mode_not_caller_input(self) -> None:
        captured = {}
        FakeAnsibleModule.params["executor_check_mode"] = True

        def authorize(**kwargs):
            captured.update(kwargs)
            return {"authorized": True}

        wrapper.authorize_package_state_readonly = authorize
        original_init = FakeAnsibleModule.__init__

        def initialize(module, **kwargs):
            original_init(module, **kwargs)
            module.check_mode = False

        FakeAnsibleModule.__init__ = initialize
        try:
            with self.assertRaises(ExitJson):
                wrapper.run_module()
        finally:
            FakeAnsibleModule.__init__ = original_init
        self.assertIs(captured["check_mode"], False)
        self.assertNotIn("executor_check_mode", captured)

    def test_wrapper_stops_before_authorization_when_proxy_source_exists(self) -> None:
        def reject_proxy():
            raise utility.PackageStateLivePreflightError(
                "TARGET_PROXY_UNSUPPORTED",
                "offline proxy source",
            )

        wrapper.require_direct_gaia_controller = reject_proxy
        wrapper.authorize_package_state_readonly = (
            lambda **kwargs: self.fail("authorization must not run")
        )
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(
            caught.exception.payload["category"],
            "TARGET_PROXY_UNSUPPORTED",
        )
        self.assertFalse(caught.exception.payload["changed"])

    def test_wrapper_preserves_safe_failure_category(self) -> None:
        def authorize(**kwargs):
            raise utility.PackageStateLivePreflightError(
                "TARGET_MISMATCH",
                "offline hostile request",
            )

        wrapper.authorize_package_state_readonly = authorize
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "TARGET_MISMATCH")
        self.assertFalse(caught.exception.payload["changed"])


if __name__ == "__main__":
    unittest.main()
