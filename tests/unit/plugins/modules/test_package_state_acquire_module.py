from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
import unittest

ROOT = Path(__file__).resolve().parents[4]
PACKAGE = "ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils"
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
    ROOT / "plugins" / "module_utils" / "package_state_acquisition.py",
    f"{PACKAGE}.package_state_acquisition",
)
live_preflight = load_module(
    ROOT / "plugins" / "module_utils" / "package_state_live_preflight.py",
    f"{PACKAGE}.package_state_live_preflight",
)
sys.modules.setdefault("ansible", ModuleType("ansible"))
sys.modules.setdefault("ansible.module_utils", ModuleType("ansible.module_utils"))
ansible_basic = sys.modules.setdefault("ansible.module_utils.basic", ModuleType("ansible.module_utils.basic"))
ansible_connection = sys.modules.setdefault("ansible.module_utils.connection", ModuleType("ansible.module_utils.connection"))
ansible_basic.AnsibleModule = object
ansible_connection.Connection = object
vendor_helper = ModuleType("ansible_collections.check_point.gaia.plugins.module_utils.checkpoint")
vendor_helper.send_request = lambda *args: (500, {})
sys.modules[vendor_helper.__name__] = vendor_helper
wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_package_state_acquire.py",
    "package_state_acquire_wrapper",
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


class FakeConnection:
    def __init__(self, socket_path):
        self.socket_path = socket_path


class PackageStateAcquireModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_module = wrapper.AnsibleModule
        self.original_connection = wrapper.Connection
        self.original_acquire = wrapper.acquire
        self.original_send_request = wrapper._vendor_send_request
        self.original_require_direct = wrapper.require_direct_gaia_controller
        wrapper.AnsibleModule = FakeAnsibleModule
        wrapper.Connection = FakeConnection
        wrapper.require_direct_gaia_controller = lambda: None
        FakeAnsibleModule.params = {
            "member_address": "192.0.2.10",
            "version": None,
            "authorization_expires_at": "2099-08-28T14:05:00Z",
            "timeout_seconds": 120,
            "poll_interval_seconds": 2,
            "max_output_bytes": 524288,
        }

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original_module
        wrapper.Connection = self.original_connection
        wrapper.acquire = self.original_acquire
        wrapper._vendor_send_request = self.original_send_request
        wrapper.require_direct_gaia_controller = self.original_require_direct

    def test_success_is_read_only_check_mode_safe_and_normalized(self) -> None:
        captured = {}

        def fake_acquire(**kwargs):
            captured.update(kwargs)
            return {
                "task_id": "sanitized",
                "polls": 1,
                "installed_packages": [],
                "installed_packages_complete": True,
                "restore_point_free_bytes": 1,
            }

        wrapper.acquire = fake_acquire
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        payload = caught.exception.payload
        self.assertFalse(payload["changed"])
        self.assertEqual(payload["observation"]["member_address"], "192.0.2.10")
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])
        argument_spec = FakeAnsibleModule.init_kwargs["argument_spec"]
        for forbidden in (
            "script", "command", "path", "args", "environment", "environment_variables"
        ):
            self.assertNotIn(forbidden, argument_spec)
        self.assertEqual(captured["timeout_seconds"], 120)
        self.assertGreater(captured["authorization_deadline_epoch"], 0)

    def test_request_uses_vendor_helper_and_selected_api_version(self) -> None:
        FakeAnsibleModule.params["version"] = "1.7"
        calls = []

        def fake_send_request(connection, version, operation, payload):
            calls.append((connection, version, operation, payload))
            return 200, {}

        wrapper._vendor_send_request = fake_send_request

        def fake_acquire(**kwargs):
            kwargs["request"]("show-task", {"task-id": "sanitized"})
            return {
                "task_id": "sanitized", "polls": 1,
                "installed_packages": [], "installed_packages_complete": True,
                "restore_point_free_bytes": 1,
            }

        wrapper.acquire = fake_acquire
        with self.assertRaises(ExitJson):
            wrapper.run_module()
        self.assertEqual(calls[0][1:3], ("v1.7/", "show-task"))

    def test_invalid_inputs_fail_before_connection(self) -> None:
        wrapper.Connection = lambda path: self.fail("connection must not be created")
        invalid = (
            ("member_address", "member.example.invalid"),
            ("version", "../1"),
            ("timeout_seconds", 301),
            ("poll_interval_seconds", 0),
            ("max_output_bytes", 32768),
        )
        for name, value in invalid:
            FakeAnsibleModule.params = {
                "member_address": "192.0.2.10",
                "version": None,
                "authorization_expires_at": "2099-08-28T14:05:00Z",
                "timeout_seconds": 120,
                "poll_interval_seconds": 2,
                "max_output_bytes": 524288,
            }
            FakeAnsibleModule.params[name] = value
            with self.subTest(name=name):
                with self.assertRaises(FailJson) as caught:
                    wrapper.run_module()
                self.assertEqual(caught.exception.payload["category"], "ACQUISITION_INVALID")

    def test_proxy_source_is_rejected_before_connection_or_request(self) -> None:
        wrapper.Connection = lambda path: self.fail("connection must not be created")
        wrapper.acquire = lambda **kwargs: self.fail("acquire must not run")

        def reject_proxy():
            raise wrapper.PackageStateLivePreflightError(
                "TARGET_PROXY_UNSUPPORTED",
                "offline proxy source",
            )

        wrapper.require_direct_gaia_controller = reject_proxy
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(
            caught.exception.payload["category"],
            "TARGET_PROXY_UNSUPPORTED",
        )

    def test_invalid_authorization_expiry_fails_before_connection(self) -> None:
        wrapper.Connection = lambda path: self.fail("connection must not be created")
        for value in ("", "2099-08-28T14:05:00+00:00", "not-a-time"):
            FakeAnsibleModule.params["authorization_expires_at"] = value
            with self.subTest(value=value):
                with self.assertRaises(FailJson) as caught:
                    wrapper.run_module()
                self.assertEqual(
                    caught.exception.payload["category"],
                    "ACQUISITION_INVALID",
                )

    def test_acquisition_error_preserves_task_identity(self) -> None:
        def fail_acquire(**kwargs):
            raise acquisition.PackageStateAcquisitionError(
                "INVENTORY_FORMAT",
                "hostile offline result",
                task_id="63c53f94-319d-444a-8c43-ec2584bcf985",
                reason="STATUS_ROW_MALFORMED",
                shape=("MULTI_OTHER", "SINGLE_OTHER"),
            )

        wrapper.acquire = fail_acquire
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "INVENTORY_FORMAT")
        self.assertEqual(caught.exception.payload["task_id"], "63c53f94-319d-444a-8c43-ec2584bcf985")
        self.assertEqual(
            caught.exception.payload["reason"],
            "STATUS_ROW_MALFORMED",
        )
        self.assertEqual(
            caught.exception.payload["shape"],
            ["MULTI_OTHER", "SINGLE_OTHER"],
        )
        self.assertFalse(caught.exception.payload["changed"])

    def test_acquisition_error_drops_unapproved_reason(self) -> None:
        def fail_acquire(**kwargs):
            raise acquisition.PackageStateAcquisitionError(
                "INVENTORY_FORMAT",
                "static failure",
                reason="raw package content must not escape",
                shape=("MULTI_OTHER", "raw package content must not escape"),
            )

        wrapper.acquire = fail_acquire
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertNotIn("reason", caught.exception.payload)
        self.assertNotIn("shape", caught.exception.payload)


if __name__ == "__main__":
    unittest.main()
