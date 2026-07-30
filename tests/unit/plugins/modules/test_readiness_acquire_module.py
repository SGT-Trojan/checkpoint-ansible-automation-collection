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
    "ansible_collections.check_point",
    "ansible_collections.check_point.gaia",
    "ansible_collections.check_point.gaia.plugins",
    "ansible_collections.check_point.gaia.plugins.module_utils",
):
    sys.modules.setdefault(package, ModuleType(package))


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


acquisition = load_module(
    ROOT / "plugins" / "module_utils" / "readiness_acquisition.py",
    f"{PACKAGE}.readiness_acquisition",
)
ansible_package = sys.modules.setdefault("ansible", ModuleType("ansible"))
ansible_module_utils = sys.modules.setdefault(
    "ansible.module_utils", ModuleType("ansible.module_utils")
)
ansible_basic = sys.modules.setdefault(
    "ansible.module_utils.basic", ModuleType("ansible.module_utils.basic")
)
ansible_connection = sys.modules.setdefault(
    "ansible.module_utils.connection", ModuleType("ansible.module_utils.connection")
)
ansible_basic.AnsibleModule = object
ansible_connection.Connection = object
vendor_helper = ModuleType(
    "ansible_collections.check_point.gaia.plugins.module_utils.checkpoint"
)
vendor_helper.send_request = lambda *args: (500, {})
sys.modules[vendor_helper.__name__] = vendor_helper
wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_readiness_acquire.py",
    "readiness_acquire_wrapper",
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
        self._socket_path = "/offline/socket"
        self.check_mode = True

    def exit_json(self, **kwargs):
        raise ExitJson(kwargs)

    def fail_json(self, **kwargs):
        raise FailJson(kwargs)


class ReadinessAcquireModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_module = wrapper.AnsibleModule
        self.original_connection = wrapper.Connection
        self.original_acquire = wrapper.acquire
        self.original_send_request = wrapper._vendor_send_request
        wrapper.AnsibleModule = FakeAnsibleModule
        wrapper.Connection = lambda path: ("connection", path)
        FakeAnsibleModule.params = {
            "member_address": "192.0.2.10",
            "version": None,
            "timeout_seconds": 30,
            "poll_interval_seconds": 2,
            "max_output_bytes": 131072,
        }

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original_module
        wrapper.Connection = self.original_connection
        wrapper.acquire = self.original_acquire
        wrapper._vendor_send_request = self.original_send_request

    def test_success_is_read_only_check_mode_safe_and_typed(self) -> None:
        captured = {}

        def fake_acquire(**kwargs):
            captured.update(kwargs)
            return {"task_id": "sanitized", "polls": 1, "sections": {}}

        wrapper.acquire = fake_acquire
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])
        argument_spec = FakeAnsibleModule.init_kwargs["argument_spec"]
        self.assertTrue(argument_spec["member_address"]["required"])
        for forbidden in (
            "script",
            "command",
            "path",
            "args",
            "environment",
            "environment_variables",
        ):
            self.assertNotIn(forbidden, argument_spec)
        self.assertEqual(captured["timeout_seconds"], 30)

    def test_request_uses_vendor_helper_and_selected_api_version(self) -> None:
        FakeAnsibleModule.params["version"] = "1.7"
        calls = []

        def fake_send_request(connection, version, operation, payload):
            calls.append((connection, version, operation, payload))
            return 200, {}

        wrapper._vendor_send_request = fake_send_request

        def fake_acquire(**kwargs):
            kwargs["request"]("show-task", {"task-id": "sanitized"})
            return {"task_id": "sanitized", "polls": 1, "sections": {}}

        wrapper.acquire = fake_acquire
        with self.assertRaises(ExitJson):
            wrapper.run_module()
        self.assertEqual(calls[0][1:3], ("v1.7/", "show-task"))

    def test_invalid_member_address_fails_before_connection(self) -> None:
        FakeAnsibleModule.params["member_address"] = "member-a.example.invalid"
        wrapper.Connection = lambda path: self.fail("connection must not be created")
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "ACQUISITION_INVALID")
        self.assertNotIn("task_id", caught.exception.payload)

    def test_invalid_version_and_acquisition_error_fail_closed(self) -> None:
        for invalid_version in ("../1", "١.٧"):
            FakeAnsibleModule.params["version"] = invalid_version
            with self.assertRaises(FailJson) as caught:
                wrapper.run_module()
            self.assertEqual(
                caught.exception.payload["category"],
                "ACQUISITION_INVALID",
            )
            self.assertFalse(caught.exception.payload["changed"])

        FakeAnsibleModule.params["version"] = None

        def fail_acquire(**kwargs):
            raise acquisition.AcquisitionError(
                "ACQUISITION_PROTOCOL",
                "offline hostile result",
                task_id="63c53f94-319d-444a-8c43-ec2584bcf985",
            )

        wrapper.acquire = fail_acquire
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "ACQUISITION_PROTOCOL")
        self.assertEqual(
            caught.exception.payload["task_id"],
            "63c53f94-319d-444a-8c43-ec2584bcf985",
        )
        self.assertFalse(caught.exception.payload["changed"])


if __name__ == "__main__":
    unittest.main()
