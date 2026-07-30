from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type


import base64
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[4]


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


deployment_agent = load(
    ROOT / "plugins/module_utils/deployment_agent.py",
    (
        "ansible_collections.sgt_trojan.checkpoint_automation."
        "plugins.module_utils.deployment_agent"
    ),
)
acquisition = load(
    ROOT / "plugins/module_utils/deployment_agent_acquisition.py",
    "deployment_agent_acquisition",
)
TASK_ID = "63c53f94-319d-444a-8c43-ec2584bcf985"


def envelope() -> str:
    return (
        "__CPAUTO_DEPLOYMENT_AGENT_STATUS_BEGIN__\n"
        "Agent: Enabled\n"
        "Build number: 2771 (agent build is up to date)\n"
        "License: status omitted\n"
        "__CPAUTO_DEPLOYMENT_AGENT_STATUS_END__:0\n"
    )


def task(
    *,
    status: str = "succeeded",
    task_id: str = TASK_ID,
    task_name: str = "/run-script",
    status_code: int | None = 200,
    progress: int = 100,
    detail: dict | None = None,
) -> dict:
    if detail is None:
        detail = {
            "error": "",
            "output": base64.b64encode(envelope().encode()).decode(),
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
                "task-details": [] if status == "in progress" else [detail],
            }
        ]
    }


class Clock:
    def __init__(self) -> None:
        self.monotonic_value = 0.0
        self.wall_value = 1000.0

    def monotonic(self) -> float:
        return self.monotonic_value

    def wall(self) -> float:
        return self.wall_value

    def sleep(self, seconds: float) -> None:
        self.monotonic_value += seconds
        self.wall_value += seconds


class DeploymentAgentAcquisitionTests(unittest.TestCase):
    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(acquisition.DeploymentAgentAcquisitionError) as caught:
            call()
        self.assertEqual(caught.exception.category, category)

    def run_responses(self, responses, *, timeout=10, deadline=1100.0):
        calls = []

        def request(operation, payload):
            calls.append((operation, payload))
            return responses.pop(0)

        clock = Clock()
        result = acquisition.acquire(
            request,
            timeout,
            1,
            deadline,
            clock.monotonic,
            clock.wall,
            clock.sleep,
        )
        return result, calls

    def test_fixed_payload_and_normalized_success(self) -> None:
        result, calls = self.run_responses(
            [(200, {"task-id": TASK_ID}), (200, task())]
        )
        self.assertEqual(result["build"], 2771)
        self.assertTrue(result["enabled"])
        self.assertEqual(result["cloud_state"], "current")
        self.assertEqual(calls[0], ("run-script", acquisition.operation_payload()))
        self.assertNotIn("args", calls[0][1])
        self.assertNotIn("environment", calls[0][1])
        script = calls[0][1]["script"]
        self.assertIn("show installer status all", script)
        self.assertNotIn("installer agent install", script)

    def test_in_progress_and_initial_visibility_are_polled_without_replay(self) -> None:
        result, calls = self.run_responses(
            [
                (200, {"task-id": TASK_ID}),
                (404, {}),
                (200, task(status="in progress", status_code=None, progress=10)),
                (200, task()),
            ]
        )
        self.assertEqual(result["polls"], 3)
        self.assertEqual([call[0] for call in calls].count("run-script"), 1)

    def test_task_identity_shape_and_status_fail_closed(self) -> None:
        for response, category in (
            ({"task-id": "bad"}, "ACQUISITION_PROTOCOL"),
            (task(task_id="73c53f94-319d-444a-8c43-ec2584bcf985"), "ACQUISITION_IDENTITY"),
            (task(task_name="/other"), "ACQUISITION_IDENTITY"),
            (task(status="complete"), "ACQUISITION_PROTOCOL"),
            (task(status="failed"), "ACQUISITION_FAILED"),
        ):
            with self.subTest(category=category):
                responses = (
                    [(200, response)]
                    if "task-id" in response
                    else [(200, {"task-id": TASK_ID}), (200, response)]
                )
                self.assert_category(
                    category,
                    lambda responses=responses: self.run_responses(responses),
                )

    def test_detail_base64_and_envelope_fail_closed(self) -> None:
        hostile = (
            ({"error": "x", "output": "", "return-value": 0}, "ACQUISITION_FAILED"),
            ({"error": "", "output": "***", "return-value": 0}, "ACQUISITION_PROTOCOL"),
            ({"error": "", "output": "", "return-value": 1}, "ACQUISITION_FAILED"),
        )
        for detail, category in hostile:
            self.assert_category(
                category,
                lambda detail=detail: self.run_responses(
                    [(200, {"task-id": TASK_ID}), (200, task(detail=detail))]
                ),
            )
        for output in (
            envelope().replace("__CPAUTO_DEPLOYMENT_AGENT_STATUS_BEGIN__\n", ""),
            envelope().replace("_END__:0", "_END__:1"),
            envelope() + "extra\n",
        ):
            self.assert_category(
                "ACQUISITION_SECTIONS",
                lambda output=output: acquisition.parse_envelope(output),
            )

    def test_parser_failure_is_forwarded_without_raw_status(self) -> None:
        raw = (
            "__CPAUTO_DEPLOYMENT_AGENT_STATUS_BEGIN__\n"
            "Build number: private-content\n"
            "__CPAUTO_DEPLOYMENT_AGENT_STATUS_END__:0\n"
        )
        with self.assertRaises(acquisition.DeploymentAgentAcquisitionError) as caught:
            acquisition.parse_envelope(raw)
        self.assertEqual(caught.exception.category, "STATUS_FORMAT")
        self.assertNotIn("private-content", str(caught.exception))
        for control in ("\x0b", "\x7f", "\x85", "\u2028", "\u2029"):
            with self.subTest(control=ord(control)):
                self.assert_category(
                    "STATUS_CONTROL",
                    lambda control=control: acquisition.parse_envelope(
                        envelope().replace("License:", "License:" + control)
                    ),
                )

    def test_expired_invalid_and_timed_out_leases_fail_closed(self) -> None:
        for deadline, category in (
            (True, "ACQUISITION_INVALID"),
            (float("inf"), "ACQUISITION_INVALID"),
            (1000.0, "LEASE_EXPIRED"),
        ):
            self.assert_category(
                category,
                lambda deadline=deadline: self.run_responses([], deadline=deadline),
            )
        pending = task(status="in progress", status_code=None, progress=10)
        with self.assertRaises(acquisition.DeploymentAgentAcquisitionError) as caught:
            self.run_responses(
                [(200, {"task-id": TASK_ID}), (200, pending)],
                timeout=1,
            )
        self.assertEqual(caught.exception.category, "ACQUISITION_TIMEOUT")
        self.assertEqual(caught.exception.task_id, TASK_ID)

    def test_transport_failures_preserve_only_known_task_identity(self) -> None:
        def fail_submit(operation, payload):
            raise RuntimeError("private")

        with self.assertRaises(acquisition.DeploymentAgentAcquisitionError) as caught:
            acquisition.acquire(fail_submit, 10, 1, 1100.0, Clock().monotonic, Clock().wall)
        self.assertEqual(caught.exception.category, "ACQUISITION_TRANSPORT")
        self.assertIsNone(caught.exception.task_id)
        self.assertNotIn("private", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
