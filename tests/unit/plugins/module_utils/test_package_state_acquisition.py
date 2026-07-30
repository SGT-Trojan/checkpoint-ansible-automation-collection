from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import base64
import importlib.util
from pathlib import Path
import sys
import unittest

MODULE = (
    Path(__file__).resolve().parents[4]
    / "plugins"
    / "module_utils"
    / "package_state_acquisition.py"
)
SPEC = importlib.util.spec_from_file_location("package_state_acquisition", MODULE)
assert SPEC and SPEC.loader
acquisition = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = acquisition
SPEC.loader.exec_module(acquisition)

TASK_ID = "63c53f94-319d-444a-8c43-ec2584bcf985"
PACKAGE_ONE = "R82 Jumbo Hotfix Accumulator Recommended Jumbo Take 60"
PACKAGE_TWO = "R82 Jumbo Hotfix Accumulator Recommended Jumbo Take 107"


def package_output() -> str:
    return f"""**                                 Hotfixes                                   **
Display name                                                                                    Type
{PACKAGE_ONE}                                          Hotfix
{PACKAGE_TWO}                                         Hotfix
"""


def installed_status_output() -> str:
    return """Check_Point_R82_jumbo_hf_main_Bundle_T60_FULL.tgz Installed
blink_image_1.1_Check_Point_R82_T777_JHF_T60_SecurityGateway.tgz Installed
"""


def framed_output(packages: str | None = None, snapshots: str | None = None) -> str:
    packages = package_output() if packages is None else packages
    snapshots = (
        "Snapshot list\nAmount of space available for restore points is 35.5 GB\n"
        if snapshots is None
        else snapshots
    )
    return (
        "__CPAUTO_PACKAGES_INSTALLED_BEGIN__\n"
        f"{packages.rstrip()}\n"
        "__CPAUTO_PACKAGES_INSTALLED_END__:0\n"
        "__CPAUTO_SNAPSHOTS_BEGIN__\n"
        f"{snapshots.rstrip()}\n"
        "__CPAUTO_SNAPSHOTS_END__:0\n"
    )


def task_response(
    *,
    status: str = "succeeded",
    task_id: str = TASK_ID,
    task_name: str = "/run-script",
    status_code: int = 200,
    progress: int = 100,
    detail: dict | None = None,
) -> dict:
    if detail is None:
        detail = {
            "error": "",
            "output": base64.b64encode(framed_output().encode()).decode(),
            "return-value": 0,
        }
    return {
        "tasks": [
            {
                "task-id": task_id,
                "task-name": task_name,
                "status": status,
                "status-code": status_code,
                "progress-percentage": progress,
                "task-details": [detail],
            }
        ]
    }


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class PackageStateAcquisitionTests(unittest.TestCase):
    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            call()
        self.assertEqual(caught.exception.category, category)

    def run_responses(self, responses: list[tuple[int, object]], **kwargs):
        calls: list[tuple[str, dict]] = []

        def request(operation, payload):
            calls.append((operation, payload))
            return responses.pop(0)

        clock = FakeClock()
        result = acquisition.acquire(
            request,
            timeout_seconds=kwargs.get("timeout_seconds", 10),
            poll_interval_seconds=kwargs.get("poll_interval_seconds", 1),
            max_output_bytes=kwargs.get("max_output_bytes", 131072),
            authorization_deadline_epoch=kwargs.get(
                "authorization_deadline_epoch", 60
            ),
            monotonic=clock.monotonic,
            wall_clock=clock.monotonic,
            sleep=clock.sleep,
        )
        return result, calls

    def test_fixed_payload_and_successful_observation(self) -> None:
        result, calls = self.run_responses(
            [(200, {"task-id": TASK_ID}), (200, task_response())]
        )
        self.assertEqual(result["installed_packages"], [PACKAGE_ONE, PACKAGE_TWO])
        self.assertIs(result["installed_packages_complete"], True)
        self.assertEqual(result["restore_point_free_bytes"], int(35.5 * 1024**3))
        self.assertEqual(result["polls"], 1)
        self.assertEqual(calls[0], ("run-script", acquisition.operation_payload()))
        self.assertEqual(calls[1], ("show-task", {"task-id": TASK_ID}))

    def test_status_rows_flow_through_complete_observation(self) -> None:
        detail = {
            "error": "",
            "output": base64.b64encode(
                framed_output(packages=installed_status_output()).encode()
            ).decode(),
            "return-value": 0,
        }
        result, calls = self.run_responses(
            [
                (200, {"task-id": TASK_ID}),
                (200, task_response(detail=detail)),
            ]
        )
        self.assertEqual(
            result["installed_packages"],
            [
                "Check_Point_R82_jumbo_hf_main_Bundle_T60_FULL.tgz",
                "blink_image_1.1_Check_Point_R82_T777_JHF_T60_SecurityGateway.tgz",
            ],
        )
        self.assertIs(result["installed_packages_complete"], True)
        self.assertEqual([call[0] for call in calls], ["run-script", "show-task"])

    def test_fixed_script_has_only_the_two_read_only_observations(self) -> None:
        script = acquisition.FIXED_PACKAGE_STATE_SCRIPT
        self.assertEqual(script.count("/bin/clish -c"), 2)
        self.assertIn("show installer packages installed", script)
        self.assertIn("show snapshots", script)
        self.assertNotIn("$1", script)
        self.assertNotIn("eval ", script)
        self.assertNotIn("installer install", script)
        payload = acquisition.operation_payload()
        self.assertEqual(set(payload), {"script", "description"})

    def test_in_progress_polling_never_replays_run_script(self) -> None:
        pending = task_response(status="in progress", progress=10)
        pending["tasks"][0]["task-details"] = []
        pending["tasks"][0].pop("status-code")
        result, calls = self.run_responses(
            [(200, {"task-id": TASK_ID}), (200, pending), (200, task_response())]
        )
        self.assertEqual(result["polls"], 2)
        self.assertEqual([call[0] for call in calls], ["run-script", "show-task", "show-task"])

    def test_initial_task_visibility_retries_without_replaying_submission(self) -> None:
        result, calls = self.run_responses(
            [
                (200, {"task-id": TASK_ID}),
                (404, {}),
                (503, {}),
                (200, task_response()),
            ]
        )
        self.assertEqual(result["polls"], 3)
        self.assertEqual(
            [call[0] for call in calls],
            ["run-script", "show-task", "show-task", "show-task"],
        )

    def test_initial_task_visibility_is_bounded_by_operation_timeout(self) -> None:
        calls = []
        clock = FakeClock()

        def request(operation, payload):
            calls.append((operation, payload))
            if operation == "run-script":
                return 200, {"task-id": TASK_ID}
            return 404, {}

        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.acquire(
                request,
                timeout_seconds=2,
                poll_interval_seconds=1,
                max_output_bytes=131072,
                authorization_deadline_epoch=60,
                monotonic=clock.monotonic,
                wall_clock=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertEqual(caught.exception.category, "ACQUISITION_TIMEOUT")
        self.assertEqual(caught.exception.task_id, TASK_ID)
        self.assertEqual(
            [call[0] for call in calls],
            ["run-script", "show-task", "show-task"],
        )

    def test_initial_task_visibility_has_a_fixed_request_ceiling(self) -> None:
        calls = []
        clock = FakeClock()

        def request(operation, payload):
            calls.append((operation, payload))
            if operation == "run-script":
                return 200, {"task-id": TASK_ID}
            return 404, {}

        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.acquire(
                request,
                timeout_seconds=300,
                poll_interval_seconds=1,
                max_output_bytes=131072,
                authorization_deadline_epoch=600,
                monotonic=clock.monotonic,
                wall_clock=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertEqual(caught.exception.category, "ACQUISITION_HTTP")
        self.assertEqual(caught.exception.task_id, TASK_ID)
        self.assertEqual(
            len(calls),
            1 + acquisition.MAX_INITIAL_TASK_VISIBILITY_POLLS,
        )

    def test_http_failure_after_task_visibility_is_not_retried(self) -> None:
        pending = task_response(status="in progress", progress=10)
        pending["tasks"][0]["task-details"] = []
        pending["tasks"][0].pop("status-code")
        responses = [
            (200, {"task-id": TASK_ID}),
            (200, pending),
            (503, {}),
        ]
        calls = []

        def request(operation, payload):
            calls.append((operation, payload))
            return responses.pop(0)

        clock = FakeClock()
        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.acquire(
                request,
                timeout_seconds=10,
                poll_interval_seconds=1,
                max_output_bytes=131072,
                authorization_deadline_epoch=60,
                monotonic=clock.monotonic,
                wall_clock=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertEqual(caught.exception.category, "ACQUISITION_HTTP")
        self.assertEqual(caught.exception.task_id, TASK_ID)
        self.assertEqual(len(calls), 3)

    def test_sections_require_order_zero_status_no_null_and_no_trailing_text(self) -> None:
        valid = framed_output()
        hostile = (
            (valid.replace("__CPAUTO_PACKAGES_INSTALLED_BEGIN__\n", ""), "ACQUISITION_SECTIONS"),
            (valid.replace("__CPAUTO_SNAPSHOTS_END__:0", "__CPAUTO_SNAPSHOTS_END__:1"), "ACQUISITION_COMMAND_FAILED"),
            (valid + "unexpected\n", "ACQUISITION_SECTIONS"),
            (valid.replace("Hotfixes", "Hotfixes\x00"), "ACQUISITION_PROTOCOL"),
        )
        for output, category in hostile:
            with self.subTest(category=category):
                self.assert_category(category, lambda output=output: acquisition.parse_sections(output))

    def test_incomplete_inventory_warnings_fail_closed(self) -> None:
        for warning in (
            "** Connection error. Packages list might be incomplete **",
            "Inventory is incomplete",
        ):
            with self.subTest(warning=warning):
                self.assert_category(
                    "INVENTORY_INCOMPLETE",
                    lambda warning=warning: acquisition.parse_installed_packages(
                        package_output() + warning + "\n"
                    ),
                )

    def test_unrecognized_warning_rows_fail_closed(self) -> None:
        for warning in (
            "WARNING:  package list truncated due to timeout",
            "Some packages  could not be retrieved",
        ):
            with self.subTest(warning=warning):
                self.assert_category(
                    "INVENTORY_FORMAT",
                    lambda warning=warning: acquisition.parse_installed_packages(
                        package_output() + warning + "\n"
                    ),
                )

    def test_recognized_package_types_are_explicit_and_case_insensitive(self) -> None:
        package_types = (
            "Hotfix",
            "Blink Version",
            "Major Version",
            "Minor Version",
            "Upgrade",
            "HOTFIX",
        )
        self.assertEqual(
            acquisition.PACKAGE_TYPES,
            {
                "hotfix",
                "blink version",
                "major version",
                "minor version",
                "upgrade",
            },
        )
        for package_type in package_types:
            with self.subTest(package_type=package_type):
                output = (
                    "** Packages **\nDisplay name  Type\nPackage identity  "
                    + package_type
                    + "\n"
                )
                self.assertEqual(
                    acquisition.parse_installed_packages(output),
                    ["Package identity"],
                )

    def test_repeated_titles_and_multiple_typed_sections_are_supported(self) -> None:
        output = (
            "** Installed packages **\n"
            "** Product packages **\n"
            "** Hotfixes **\n"
            "Display name  Type\n"
            "Package one  Hotfix\n"
            "Package two  Hotfix\n"
            "** Installed packages **\n"
            "** Product packages **\n"
            "** Blink images **\n"
            "Display name  Type\n"
            "Package three  Blink Version\n"
        )
        self.assertEqual(
            acquisition.parse_installed_packages(output),
            ["Package one", "Package two", "Package three"],
        )

    def test_repeated_titles_do_not_weaken_typed_section_validation(self) -> None:
        cases = (
            (
                "** First **\n** Second **\n",
                "TYPED_SECTION_HEADER_MISSING",
            ),
            (
                "** " + "x" * 129 + " **\nDisplay name  Type\n",
                "SECTION_BOUNDS",
            ),
            (
                "** First **\n** Second **\nDisplay name  Status\n"
                "Package one  Hotfix\n",
                "TYPED_HEADER_UNSUPPORTED",
            ),
            (
                "** First **\n** Second **\nDisplay name  Type\n"
                "Package one  Unsupported type\n",
                "TYPED_TYPE_UNKNOWN",
            ),
            (
                "** First **\nDisplay name  Type\nPackage one  Hotfix\n"
                "** Second **\n** Third **\nDisplay name  Type\n"
                "Package one  Blink Version\n",
                "INVENTORY_AMBIGUOUS",
            ),
        )
        for output, category_or_reason in cases:
            with self.subTest(category_or_reason=category_or_reason):
                with self.assertRaises(
                    acquisition.PackageStateAcquisitionError
                ) as caught:
                    acquisition.parse_installed_packages(output)
                if category_or_reason == "INVENTORY_AMBIGUOUS":
                    self.assertEqual(caught.exception.category, category_or_reason)
                else:
                    self.assertEqual(caught.exception.category, "INVENTORY_FORMAT")
                    self.assertEqual(caught.exception.reason, category_or_reason)

    def test_observed_installed_status_rows_are_supported(self) -> None:
        self.assertEqual(
            acquisition.parse_installed_packages(installed_status_output()),
            [
                "Check_Point_R82_jumbo_hf_main_Bundle_T60_FULL.tgz",
                "blink_image_1.1_Check_Point_R82_T777_JHF_T60_SecurityGateway.tgz",
            ],
        )

    def test_installed_status_rows_fail_closed_on_mixed_or_unknown_content(self) -> None:
        for output in (
            installed_status_output() + "Unexpected warning\n",
            installed_status_output().replace(" Installed", " Downloaded", 1),
            installed_status_output() + "** Hotfixes **\n",
            "Installed\n",
            "Package identity installed\n",
        ):
            with self.subTest(output=output):
                self.assert_category(
                    "INVENTORY_FORMAT",
                    lambda output=output: acquisition.parse_installed_packages(output),
                )

    def test_inventory_format_reasons_and_shapes_are_content_free(self) -> None:
        cases = (
            (
                "Package identity installed\n",
                "STATUS_STATUS_CASE",
                ("STATUS_CASE",),
            ),
            (
                "Package identity  Downloaded\n",
                "STATUS_MULTI_COLUMN",
                ("MULTI_OTHER",),
            ),
            (
                "** Hotfixes **\nDisplay name  Status\n"
                "Package identity  Hotfix\n",
                "TYPED_HEADER_UNSUPPORTED",
                ("TITLE", "HEADER_OTHER", "MULTI_TYPE"),
            ),
            (
                "unrecognized text\n",
                "STATUS_ROW_MALFORMED",
                ("SINGLE_OTHER",),
            ),
        )
        for output, reason, shape in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(
                    acquisition.PackageStateAcquisitionError
                ) as caught:
                    acquisition.parse_installed_packages(output)
                self.assertEqual(caught.exception.category, "INVENTORY_FORMAT")
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(caught.exception.shape, shape)

    def test_diagnostic_routing_preserves_parent_acceptance(self) -> None:
        self.assertEqual(
            acquisition.parse_installed_packages(
                "display name bundle Installed\n"
            ),
            ["display name bundle"],
        )
        self.assertEqual(
            acquisition.parse_installed_packages(
                "** Hotfixes **\n"
                "Display name  Type\n"
                "display name bundle  Hotfix\n"
            ),
            ["display name bundle"],
        )

    def test_multi_column_reason_and_shape_use_the_same_precedence(self) -> None:
        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.parse_installed_packages("Package identity  installed\n")
        self.assertEqual(caught.exception.reason, "STATUS_MULTI_COLUMN")
        self.assertEqual(caught.exception.shape, ("MULTI_OTHER",))

    def test_inventory_format_shape_is_capped(self) -> None:
        output = "".join(f"unknown-{index}\n" for index in range(20))
        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.parse_installed_packages(output)
        self.assertEqual(len(caught.exception.shape), 17)
        self.assertEqual(caught.exception.shape[-1], "MORE")
        self.assertEqual(set(caught.exception.shape[:-1]), {"SINGLE_OTHER"})

    def test_installed_status_rows_require_unique_bounded_identities(self) -> None:
        duplicate = installed_status_output() + (
            "Check_Point_R82_jumbo_hf_main_Bundle_T60_FULL.tgz Installed\n"
        )
        self.assert_category(
            "INVENTORY_AMBIGUOUS",
            lambda: acquisition.parse_installed_packages(duplicate),
        )
        self.assert_category(
            "INVENTORY_FORMAT",
            lambda: acquisition.parse_installed_packages(
                "x" * 513 + " Installed\n"
            ),
        )

    def test_package_table_requires_header_and_every_row_to_parse(self) -> None:
        for output in (
            package_output().replace("Display name", "Package name"),
            package_output() + "not a table row\n",
            package_output() + "** Empty section **\n",
            "unexpected prefix\n" + package_output(),
        ):
            with self.subTest(output=output):
                self.assert_category(
                    "INVENTORY_FORMAT",
                    lambda output=output: acquisition.parse_installed_packages(output),
                )

    def test_package_identities_must_be_unique_and_bounded(self) -> None:
        duplicate = package_output() + f"{PACKAGE_ONE}  Hotfix\n"
        self.assert_category(
            "INVENTORY_AMBIGUOUS",
            lambda: acquisition.parse_installed_packages(duplicate),
        )
        too_long = (
            "** Hotfixes **\nDisplay name  Type\n"
            + "x" * 513
            + "  Hotfix\n"
        )
        self.assert_category(
            "INVENTORY_FORMAT",
            lambda: acquisition.parse_installed_packages(too_long),
        )

    def test_empty_but_well_formed_installed_table_is_complete(self) -> None:
        output = "** Hotfixes **\nDisplay name  Type\n"
        self.assertEqual(acquisition.parse_installed_packages(output), [])

    def test_restore_capacity_requires_one_explicit_supported_value(self) -> None:
        self.assertEqual(
            acquisition.parse_restore_point_free_bytes(
                "Amount of space available for restore points is 1.25 GB\n"
            ),
            int(1.25 * 1024**3),
        )
        accepted = (
            ("48.2G", int(48.2 * 1024**3)),
            ("48.2GB", int(48.2 * 1024**3)),
            ("48.2GiB", int(48.2 * 1024**3)),
            ("512M", 512 * 1024**2),
            ("1024 bytes", 1024),
            ("1024B", 1024),
            ("1 iB", 1),
            ("1 Kbyte", 1024),
            ("1 GBytes", 1024**3),
            ("0.0G", 0),
        )
        for capacity, expected in accepted:
            with self.subTest(capacity=capacity):
                self.assertEqual(
                    acquisition.parse_restore_point_free_bytes(
                        "Amount of space available for restore points is "
                        + capacity
                        + "\n"
                    ),
                    expected,
                )
        for output in (
            "no capacity\n",
            "Amount of space available for restore points is 35\n",
            "Amount of space available for restore points is 48.2Gi\n",
            "Amount of space available for restore points is 48.2XB\n",
            "Amount of space available for restore points is -1 GB\n",
            "Amount of space available for restore points is 1 GB\n"
            "Amount of space available for restore points is 2 GB\n",
            "Error: stale snapshot data\n"
            "Amount of space available for restore points is 35 GB\n",
        ):
            with self.subTest(output=output):
                self.assert_category(
                    "CAPACITY_FORMAT",
                    lambda output=output: acquisition.parse_restore_point_free_bytes(output),
                )

    def test_capacity_token_and_result_are_bounded(self) -> None:
        self.assert_category(
            "CAPACITY_FORMAT",
            lambda: acquisition.parse_restore_point_free_bytes(
                "Amount of space available for restore points is "
                + "9" * 16
                + " GB\n"
            ),
        )
        self.assert_category(
            "CAPACITY_TOO_LARGE",
            lambda: acquisition.parse_restore_point_free_bytes(
                "Amount of space available for restore points is 9 EB\n"
            ),
        )

    def test_task_and_response_identity_are_strict(self) -> None:
        for response, category in (
            ({"task": TASK_ID}, "ACQUISITION_PROTOCOL"),
            ({"task-id": "invalid"}, "ACQUISITION_PROTOCOL"),
        ):
            self.assert_category(
                category,
                lambda response=response: self.run_responses([(200, response)]),
            )
        for response, category in (
            (task_response(task_id="73c53f94-319d-444a-8c43-ec2584bcf985"), "ACQUISITION_IDENTITY"),
            (task_response(task_name="/other"), "ACQUISITION_IDENTITY"),
            (task_response(status="complete"), "ACQUISITION_PROTOCOL"),
            (task_response(status="failed"), "ACQUISITION_FAILED"),
        ):
            self.assert_category(
                category,
                lambda response=response: self.run_responses(
                    [(200, {"task-id": TASK_ID}), (200, response)]
                ),
            )

    def test_detail_base64_utf8_and_size_are_strict(self) -> None:
        hostile = (
            ({"error": "failure", "output": "", "return-value": 0}, "ACQUISITION_FAILED"),
            ({"error": "", "output": "", "return-value": True}, "ACQUISITION_FAILED"),
            ({"error": "", "output": "***", "return-value": 0}, "ACQUISITION_PROTOCOL"),
            ({"error": "", "output": base64.b64encode(b"\xff").decode(), "return-value": 0}, "ACQUISITION_PROTOCOL"),
        )
        for detail, category in hostile:
            with self.subTest(category=category):
                self.assert_category(
                    category,
                    lambda detail=detail: self.run_responses(
                        [(200, {"task-id": TASK_ID}), (200, task_response(detail=detail))]
                    ),
                )
        self.assert_category(
            "ACQUISITION_TOO_LARGE",
            lambda: self.run_responses(
                [(200, {"task-id": TASK_ID}), (200, task_response())],
                max_output_bytes=32,
            ),
        )

    def test_http_and_transport_failures_preserve_known_task_identity(self) -> None:
        self.assert_category(
            "ACQUISITION_HTTP",
            lambda: self.run_responses([(500, {})]),
        )
        calls = 0

        def request(operation, payload):
            nonlocal calls
            calls += 1
            if calls == 1:
                return 200, {"task-id": TASK_ID}
            raise RuntimeError("private detail")

        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.acquire(
                request, 10, 1, 131072, 60, wall_clock=lambda: 0
            )
        self.assertEqual(caught.exception.category, "ACQUISITION_TRANSPORT")
        self.assertEqual(caught.exception.task_id, TASK_ID)
        self.assertNotIn("private detail", str(caught.exception))

    def test_authorization_deadline_must_be_finite_numeric(self) -> None:
        for value in (True, "60", float("nan"), float("inf")):
            with self.subTest(value=value):
                self.assert_category(
                    "ACQUISITION_INVALID",
                    lambda value=value: acquisition.acquire(
                        lambda operation, payload: (200, {}),
                        10,
                        1,
                        131072,
                        value,
                    ),
                )

    def test_submission_response_after_expiry_is_rejected_with_task_id(self) -> None:
        clock = FakeClock()

        def request(operation, payload):
            clock.now = 2.0
            return 200, {"task-id": TASK_ID}

        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.acquire(
                request,
                timeout_seconds=10,
                poll_interval_seconds=1,
                max_output_bytes=131072,
                authorization_deadline_epoch=1.0,
                monotonic=clock.monotonic,
                wall_clock=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertEqual(caught.exception.category, "LEASE_EXPIRED")
        self.assertEqual(caught.exception.task_id, TASK_ID)

    def test_poll_response_after_expiry_is_not_accepted(self) -> None:
        clock = FakeClock()
        calls = 0

        def request(operation, payload):
            nonlocal calls
            calls += 1
            if calls == 1:
                return 200, {"task-id": TASK_ID}
            clock.now = 2.0
            return 200, task_response()

        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.acquire(
                request,
                timeout_seconds=10,
                poll_interval_seconds=1,
                max_output_bytes=131072,
                authorization_deadline_epoch=1.0,
                monotonic=clock.monotonic,
                wall_clock=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertEqual(caught.exception.category, "LEASE_EXPIRED")
        self.assertEqual(caught.exception.task_id, TASK_ID)
        self.assertEqual(calls, 2)

    def test_expired_lease_stops_before_submission(self) -> None:
        calls = []

        def request(operation, payload):
            calls.append((operation, payload))
            return 200, {}

        self.assert_category(
            "LEASE_EXPIRED",
            lambda: acquisition.acquire(request, 10, 1, 131072, 0),
        )
        self.assertEqual(calls, [])

    def test_lease_expiry_stops_polling_without_an_extra_request(self) -> None:
        pending = task_response(status="in progress", progress=10)
        pending["tasks"][0]["task-details"] = []
        pending["tasks"][0].pop("status-code")
        responses = [
            (200, {"task-id": TASK_ID}),
            (200, pending),
            (200, pending),
        ]
        calls = []

        def request(operation, payload):
            calls.append((operation, payload))
            return responses.pop(0)

        clock = FakeClock()
        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.acquire(
                request,
                timeout_seconds=10,
                poll_interval_seconds=1,
                max_output_bytes=131072,
                authorization_deadline_epoch=1.5,
                monotonic=clock.monotonic,
                wall_clock=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertEqual(caught.exception.category, "LEASE_EXPIRED")
        self.assertEqual(caught.exception.task_id, TASK_ID)
        self.assertEqual(
            [call[0] for call in calls],
            ["run-script", "show-task", "show-task"],
        )
        self.assertEqual(clock.now, 1.5)

    def test_lease_expiry_stops_initial_visibility_without_extra_request(self) -> None:
        calls = []
        clock = FakeClock()

        def request(operation, payload):
            calls.append((operation, payload))
            if operation == "run-script":
                return 200, {"task-id": TASK_ID}
            return 404, {}

        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.acquire(
                request,
                timeout_seconds=10,
                poll_interval_seconds=1,
                max_output_bytes=131072,
                authorization_deadline_epoch=1.5,
                monotonic=clock.monotonic,
                wall_clock=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertEqual(caught.exception.category, "LEASE_EXPIRED")
        self.assertEqual(caught.exception.task_id, TASK_ID)
        self.assertEqual(
            [call[0] for call in calls],
            ["run-script", "show-task", "show-task"],
        )
        self.assertEqual(clock.now, 1.5)

    def test_wall_clock_rollback_cannot_extend_authorization(self) -> None:
        pending = task_response(status="in progress", progress=10)
        pending["tasks"][0]["task-details"] = []
        pending["tasks"][0].pop("status-code")
        responses = [
            (200, {"task-id": TASK_ID}),
            (200, pending),
            (200, pending),
        ]
        calls = []
        monotonic_now = 0.0
        wall_now = 100.0

        def request(operation, payload):
            calls.append((operation, payload))
            return responses.pop(0)

        def monotonic():
            return monotonic_now

        def wall_clock():
            return wall_now

        def sleep(seconds):
            nonlocal monotonic_now, wall_now
            monotonic_now += seconds
            wall_now = 0.0

        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            acquisition.acquire(
                request,
                timeout_seconds=10,
                poll_interval_seconds=1,
                max_output_bytes=131072,
                authorization_deadline_epoch=101.5,
                monotonic=monotonic,
                wall_clock=wall_clock,
                sleep=sleep,
            )
        self.assertEqual(caught.exception.category, "LEASE_EXPIRED")
        self.assertEqual(caught.exception.task_id, TASK_ID)
        self.assertEqual(
            [call[0] for call in calls],
            ["run-script", "show-task", "show-task"],
        )
        self.assertEqual(monotonic_now, 1.5)

    def test_timeout_is_bounded_and_preserves_task_identity(self) -> None:
        pending = task_response(status="in progress", progress=10)
        pending["tasks"][0]["task-details"] = []
        with self.assertRaises(acquisition.PackageStateAcquisitionError) as caught:
            self.run_responses(
                [(200, {"task-id": TASK_ID}), (200, pending), (200, pending)],
                timeout_seconds=1,
                poll_interval_seconds=1,
            )
        self.assertEqual(caught.exception.category, "ACQUISITION_TIMEOUT")
        self.assertEqual(caught.exception.task_id, TASK_ID)


if __name__ == "__main__":
    unittest.main()
