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
    ROOT / "plugins" / "module_utils" / "deployment_agent_package.py",
    f"{PACKAGE}.deployment_agent_package",
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
    / "cp_automation_deployment_agent_package_bind.py",
    "deployment_agent_package_bind_wrapper",
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


class DeploymentAgentPackageBindModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_module = wrapper.AnsibleModule
        self.original_bind = wrapper.bind_deployment_agent_package
        wrapper.AnsibleModule = FakeAnsibleModule
        FakeAnsibleModule.params = {
            "package_step": {},
            "required_build": 2771,
            "expected_build": 2771,
        }

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original_module
        wrapper.bind_deployment_agent_package = self.original_bind

    def test_success_is_read_only_and_check_mode_safe(self) -> None:
        wrapper.bind_deployment_agent_package = lambda *args: {
            "binding_sha256": "a" * 64
        }
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertEqual(
            caught.exception.payload["binding"]["binding_sha256"],
            "a" * 64,
        )
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])
        spec = FakeAnsibleModule.init_kwargs["argument_spec"]
        self.assertTrue(spec["expected_build"]["required"])

    def test_failure_preserves_category_and_changed_false(self) -> None:
        def reject(*args):
            raise utility.DeploymentAgentPackageError(
                "CHECKSUM_INVALID",
                "offline mismatch",
            )

        wrapper.bind_deployment_agent_package = reject
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "CHECKSUM_INVALID")
        self.assertFalse(caught.exception.payload["changed"])


if __name__ == "__main__":
    unittest.main()
