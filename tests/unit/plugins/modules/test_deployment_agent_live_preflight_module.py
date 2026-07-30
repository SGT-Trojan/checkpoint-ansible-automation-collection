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


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


preflight = load(
    ROOT / "plugins/module_utils/deployment_agent_live_preflight.py",
    f"{PACKAGE}.deployment_agent_live_preflight",
)
sys.modules.setdefault("ansible", ModuleType("ansible"))
sys.modules.setdefault("ansible.module_utils", ModuleType("ansible.module_utils"))
basic = sys.modules.setdefault(
    "ansible.module_utils.basic", ModuleType("ansible.module_utils.basic")
)
basic.AnsibleModule = object
wrapper = load(
    ROOT / "plugins/modules/cp_automation_deployment_agent_live_preflight.py",
    "deployment_agent_live_preflight_wrapper",
)


class ExitJson(Exception):
    def __init__(self, payload):
        self.payload = payload


class FailJson(Exception):
    def __init__(self, payload):
        self.payload = payload


class FakeModule:
    params = {}
    check_mode = True
    init_kwargs = {}

    def __init__(self, **kwargs):
        type(self).init_kwargs = kwargs
        self.params = dict(type(self).params)
        self.check_mode = type(self).check_mode

    def exit_json(self, **kwargs):
        raise ExitJson(kwargs)

    def fail_json(self, **kwargs):
        raise FailJson(kwargs)


class DeploymentAgentLivePreflightModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = (
            wrapper.AnsibleModule,
            wrapper.authorize_deployment_agent_readonly,
            wrapper.require_direct_gaia_controller,
        )
        wrapper.AnsibleModule = FakeModule
        wrapper.require_direct_gaia_controller = lambda: None
        FakeModule.params = {
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
        FakeModule.check_mode = True

    def tearDown(self) -> None:
        (
            wrapper.AnsibleModule,
            wrapper.authorize_deployment_agent_readonly,
            wrapper.require_direct_gaia_controller,
        ) = self.original

    def test_success_forwards_check_mode_and_returns_sanitized_result(self) -> None:
        captured = {}

        def authorize(**kwargs):
            captured.update(kwargs)
            return {"authorized": True, "target_fingerprint": "a" * 64}

        wrapper.authorize_deployment_agent_readonly = authorize
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertTrue(caught.exception.payload["authorization"]["authorized"])
        self.assertTrue(captured["check_mode"])
        self.assertTrue(FakeModule.init_kwargs["supports_check_mode"])

    def test_stable_failure_category_is_returned_without_secret_values(self) -> None:
        def authorize(**kwargs):
            raise preflight.DeploymentAgentLivePreflightError(
                "TARGET_MISMATCH",
                "runtime targets do not match the lease",
            )

        wrapper.authorize_deployment_agent_readonly = authorize
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "TARGET_MISMATCH")
        self.assertFalse(caught.exception.payload["changed"])
        self.assertNotIn("credential_presence", str(caught.exception.payload))

    def test_proxy_guard_runs_before_authorization(self) -> None:
        def reject():
            raise preflight.DeploymentAgentLivePreflightError(
                "TARGET_PROXY_UNSUPPORTED",
                "proxy inventory is present",
            )

        wrapper.require_direct_gaia_controller = reject
        wrapper.authorize_deployment_agent_readonly = lambda **kwargs: self.fail(
            "authorization must not run"
        )
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(
            caught.exception.payload["category"],
            "TARGET_PROXY_UNSUPPORTED",
        )


if __name__ == "__main__":
    unittest.main()
