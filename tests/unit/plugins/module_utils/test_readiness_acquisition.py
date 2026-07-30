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
    / "readiness_acquisition.py"
)
SPEC = importlib.util.spec_from_file_location("readiness_acquisition", MODULE)
assert SPEC and SPEC.loader
acquisition = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = acquisition
SPEC.loader.exec_module(acquisition)

TASK_ID = "63c53f94-319d-444a-8c43-ec2584bcf985"


def section_output() -> str:
    values = {
        "CLUSTER_STATE": "state evidence",
        "CLUSTER_INTERFACES": "interface evidence",
        "ICAP_CPWD": "watchdog evidence",
        "ICAP_LISTENER": "listener evidence",
        "ICAP_PROCESS": "123 /usr/sbin/c-icap",
    }
    return "".join(
        f"__CPAUTO_{name}_BEGIN__\n"
        f"{values[name]}\n"
        f"__CPAUTO_{name}_END__:0\n"
        for name in acquisition.SECTION_NAMES
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
            "output": base64.b64encode(section_output().encode()).decode(),
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


class ReadinessAcquisitionTests(unittest.TestCase):
    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(acquisition.AcquisitionError) as caught:
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
            max_output_bytes=kwargs.get("max_output_bytes", 32768),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        return result, calls

    def test_fixed_payload_and_successful_sections(self) -> None:
        result, calls = self.run_responses(
            [(200, {"task-id": TASK_ID}), (200, task_response())]
        )
        self.assertEqual(result["polls"], 1)
        self.assertEqual(result["sections"]["cluster_state"], "state evidence\n")
        self.assertEqual(calls[0], ("run-script", acquisition.operation_payload()))
        self.assertNotIn("args", calls[0][1])
        self.assertNotIn("environment_variables", calls[0][1])
        self.assertEqual(calls[1], ("show-task", {"task-id": TASK_ID}))

    def test_fixed_script_initializes_expert_tools_and_listener_fallback(self) -> None:
        script = acquisition.FIXED_READINESS_SCRIPT
        self.assertIn("/etc/profile.d/CP.sh", script)
        self.assertIn("source /etc/profile.d/CP.sh", script)
        self.assertLess(
            script.index("source /etc/profile.d/CP.sh"),
            script.index("__CPAUTO_CLUSTER_STATE_BEGIN__"),
        )
        self.assertIn("exit 125", script)
        self.assertIn("command -v ss", script)
        self.assertIn("command -v netstat", script)
        self.assertNotIn("/opt/CP", script)

    def test_in_progress_is_polled_without_replaying_operation(self) -> None:
        pending = task_response(status="in progress", progress=10)
        pending["tasks"][0]["task-details"] = []
        result, calls = self.run_responses(
            [(200, {"task-id": TASK_ID}), (200, pending), (200, task_response())]
        )
        self.assertEqual(result["polls"], 2)
        self.assertEqual([call[0] for call in calls], ["run-script", "show-task", "show-task"])

    def test_http_failures_are_rejected(self) -> None:
        for responses in (
            [(500, {})],
            [(200, {"task-id": TASK_ID}), (503, {})],
        ):
            with self.subTest(responses=responses):
                self.assert_category(
                    "ACQUISITION_HTTP",
                    lambda responses=list(responses): self.run_responses(responses),
                )

    def test_transport_exceptions_fail_closed_with_known_identity(self) -> None:
        calls = 0

        def request(operation, payload):
            nonlocal calls
            calls += 1
            if calls == 1:
                return 200, {"task-id": TASK_ID}
            raise RuntimeError("offline transport failure")

        with self.assertRaises(acquisition.AcquisitionError) as caught:
            acquisition.acquire(request, 10, 1, 32768)
        self.assertEqual(caught.exception.category, "ACQUISITION_TRANSPORT")
        self.assertEqual(caught.exception.task_id, TASK_ID)
        self.assertNotIn("offline transport failure", str(caught.exception))

    def test_task_identity_and_shape_are_strict(self) -> None:
        hostile = (
            {"task": TASK_ID},
            {"task-id": "not-a-task"},
            {"task-id": TASK_ID, "extra": True},
        )
        for response in hostile:
            with self.subTest(response=response):
                self.assert_category(
                    "ACQUISITION_PROTOCOL",
                    lambda response=response: self.run_responses([(200, response)]),
                )
        for response, category in (
            ({"tasks": []}, "ACQUISITION_PROTOCOL"),
            (task_response(task_id="73c53f94-319d-444a-8c43-ec2584bcf985"), "ACQUISITION_IDENTITY"),
            (task_response(task_name="/other"), "ACQUISITION_IDENTITY"),
        ):
            with self.subTest(response=response):
                self.assert_category(
                    category,
                    lambda response=response: self.run_responses(
                        [(200, {"task-id": TASK_ID}), (200, response)]
                    ),
                )

    def test_unknown_and_failed_statuses_are_rejected(self) -> None:
        for status, category in (
            ("complete", "ACQUISITION_PROTOCOL"),
            ("failed", "ACQUISITION_FAILED"),
        ):
            self.assert_category(
                category,
                lambda status=status: self.run_responses(
                    [(200, {"task-id": TASK_ID}), (200, task_response(status=status))]
                ),
            )

    def test_status_return_code_and_detail_contract_is_strict(self) -> None:
        hostile = (
            (task_response(status_code=201), "ACQUISITION_FAILED"),
            (task_response(progress=99), "ACQUISITION_PROTOCOL"),
            (task_response(detail={"error": "failure", "output": "", "return-value": 0}), "ACQUISITION_FAILED"),
            (task_response(detail={"error": "", "output": "", "return-value": 1}), "ACQUISITION_FAILED"),
            (task_response(detail={"error": "", "output": "", "return-value": False}), "ACQUISITION_FAILED"),
            (task_response(detail={"error": "", "output": "", "return-value": 0, "extra": 1}), "ACQUISITION_PROTOCOL"),
        )
        for response, category in hostile:
            with self.subTest(category=category):
                self.assert_category(
                    category,
                    lambda response=response: self.run_responses(
                        [(200, {"task-id": TASK_ID}), (200, response)]
                    ),
                )

    def test_base64_utf8_and_size_are_bounded(self) -> None:
        invalid_base64 = {"error": "", "output": "***", "return-value": 0}
        invalid_utf8 = {
            "error": "",
            "output": base64.b64encode(b"\xff").decode(),
            "return-value": 0,
        }
        noncanonical_base64 = {"error": "", "output": "Zh==", "return-value": 0}
        for detail, category in (
            (invalid_base64, "ACQUISITION_PROTOCOL"),
            (invalid_utf8, "ACQUISITION_PROTOCOL"),
            (noncanonical_base64, "ACQUISITION_PROTOCOL"),
        ):
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

    def test_sections_require_order_zero_status_and_no_extra_text(self) -> None:
        valid = section_output()
        hostile = (
            valid.replace("__CPAUTO_CLUSTER_STATE_BEGIN__\n", ""),
            valid.replace("__CPAUTO_CLUSTER_STATE_END__:0", "__CPAUTO_CLUSTER_STATE_END__:1"),
            valid.replace("state evidence", ""),
            valid + "unexpected\n",
            valid.replace("CLUSTER_STATE", "ICAP_CPWD", 2),
        )
        for output in hostile:
            with self.subTest(output=output):
                self.assert_category(
                    (
                        "ACQUISITION_COMMAND_FAILED"
                        if "_END__:1" in output
                        else "ACQUISITION_SECTIONS"
                    ),
                    lambda output=output: acquisition.parse_sections(output),
                )

    def test_post_submission_failures_preserve_task_identity(self) -> None:
        pending = task_response(status="in progress", progress=10)
        pending["tasks"][0]["task-details"] = []
        for responses, category in (
            ([(200, {"task-id": TASK_ID}), (503, {})], "ACQUISITION_HTTP"),
            (
                [(200, {"task-id": TASK_ID}), (200, task_response(status="failed"))],
                "ACQUISITION_FAILED",
            ),
            (
                [(200, {"task-id": TASK_ID}), (200, pending), (200, pending)],
                "ACQUISITION_TIMEOUT",
            ),
        ):
            with self.subTest(category=category):
                with self.assertRaises(acquisition.AcquisitionError) as caught:
                    self.run_responses(
                        list(responses),
                        timeout_seconds=1,
                        poll_interval_seconds=1,
                    )
                self.assertEqual(caught.exception.category, category)
                self.assertEqual(caught.exception.task_id, TASK_ID)

    def test_polling_timeout_is_bounded(self) -> None:
        pending = task_response(status="in progress", progress=10)
        pending["tasks"][0]["task-details"] = []
        responses = [(200, {"task-id": TASK_ID})] + [(200, pending)] * 5
        self.assert_category(
            "ACQUISITION_TIMEOUT",
            lambda: self.run_responses(
                responses,
                timeout_seconds=2,
                poll_interval_seconds=1,
            ),
        )


if __name__ == "__main__":
    unittest.main()
