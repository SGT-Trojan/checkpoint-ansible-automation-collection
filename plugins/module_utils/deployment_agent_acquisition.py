# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Bounded Gaia acquisition for Check Point Deployment Agent status."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import base64
import binascii
import math
import re
import time
from typing import Any, Callable

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent import (
    DeploymentAgentError,
    parse_status,
)


class DeploymentAgentAcquisitionError(ValueError):
    """The fixed Gaia operation or its result violated the contract."""

    def __init__(self, category: str, message: str, task_id: str | None = None):
        super().__init__(message)
        self.category = category
        self.task_id = task_id


TASK_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
MAX_INITIAL_TASK_VISIBILITY_POLLS = 40
MAX_OUTPUT_BYTES = 32768

# Callers cannot add a command, path, argument, variable, or environment entry.
FIXED_DEPLOYMENT_AGENT_SCRIPT = r"""#!/bin/bash
if [ ! -r /etc/profile.d/CP.sh ]; then
    exit 125
fi
source /etc/profile.d/CP.sh >/dev/null 2>&1 || exit 125
export LC_ALL=C
export PATH="${PATH:-}:/bin:/usr/bin:/sbin:/usr/sbin"
printf '%s\n' '__CPAUTO_DEPLOYMENT_AGENT_STATUS_BEGIN__'
/bin/clish -c 'show installer status all'
printf '__CPAUTO_DEPLOYMENT_AGENT_STATUS_END__:%s\n' "$?"
"""


def operation_payload() -> dict[str, str]:
    """Return the only operation payload this module may send."""

    return {
        "script": FIXED_DEPLOYMENT_AGENT_SCRIPT,
        "description": "Ansible bounded Deployment Agent status observation",
    }


def _fail(category: str, message: str) -> None:
    raise DeploymentAgentAcquisitionError(category, message)


def _task_id(response: object) -> str:
    if not isinstance(response, dict) or set(response) != {"task-id"}:
        _fail("ACQUISITION_PROTOCOL", "run-script response must contain only task-id")
    value = response["task-id"]
    if not isinstance(value, str) or TASK_ID.fullmatch(value) is None:
        _fail("ACQUISITION_PROTOCOL", "run-script returned an invalid task identity")
    return value


def _single_task(response: object, expected_task_id: str) -> dict[str, Any]:
    if not isinstance(response, dict) or set(response) != {"tasks"}:
        _fail("ACQUISITION_PROTOCOL", "show-task response must contain only tasks")
    tasks = response["tasks"]
    if not isinstance(tasks, list) or len(tasks) != 1 or not isinstance(tasks[0], dict):
        _fail("ACQUISITION_PROTOCOL", "show-task must return exactly one task")
    task = tasks[0]
    if task.get("task-id") != expected_task_id:
        _fail("ACQUISITION_IDENTITY", "show-task identity does not match run-script")
    if task.get("task-name") != "/run-script":
        _fail("ACQUISITION_IDENTITY", "task is not the fixed run-script operation")
    status = task.get("status")
    if status not in ("in progress", "succeeded", "failed"):
        _fail("ACQUISITION_PROTOCOL", "task returned an unsupported status")
    status_code = task.get("status-code")
    if status == "in progress" and status_code is None:
        return task
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        _fail("ACQUISITION_PROTOCOL", "task status-code must be an integer")
    return task


def _decode_output(task: dict[str, Any]) -> str:
    if task["status"] != "succeeded" or task["status-code"] != 200:
        _fail("ACQUISITION_FAILED", "fixed Deployment Agent operation failed")
    if task.get("progress-percentage") != 100:
        _fail("ACQUISITION_PROTOCOL", "succeeded task progress must be 100")
    details = task.get("task-details")
    if not isinstance(details, list) or len(details) != 1 or not isinstance(details[0], dict):
        _fail("ACQUISITION_PROTOCOL", "succeeded task must have exactly one detail")
    detail = details[0]
    if set(detail) != {"error", "output", "return-value"}:
        _fail("ACQUISITION_PROTOCOL", "task detail fields do not match run-script")
    if detail["error"] not in ("", None):
        _fail("ACQUISITION_FAILED", "fixed Deployment Agent operation returned an error")
    return_value = detail["return-value"]
    if isinstance(return_value, bool) or return_value != 0:
        _fail("ACQUISITION_FAILED", "fixed operation return-value is not zero")
    encoded = detail["output"]
    if not isinstance(encoded, str):
        _fail("ACQUISITION_PROTOCOL", "run-script output must be base64 text")
    maximum_encoded = ((MAX_OUTPUT_BYTES + 2) // 3) * 4
    if len(encoded) > maximum_encoded:
        _fail("ACQUISITION_TOO_LARGE", "encoded Deployment Agent output exceeds the limit")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise DeploymentAgentAcquisitionError(
            "ACQUISITION_PROTOCOL",
            "run-script output is not canonical base64",
        ) from error
    if base64.b64encode(decoded).decode("ascii") != encoded:
        _fail("ACQUISITION_PROTOCOL", "run-script output is not canonical base64")
    if len(decoded) > MAX_OUTPUT_BYTES:
        _fail("ACQUISITION_TOO_LARGE", "decoded Deployment Agent output exceeds the limit")
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DeploymentAgentAcquisitionError(
            "ACQUISITION_PROTOCOL",
            "run-script output is not UTF-8",
        ) from error


def parse_envelope(output: str) -> dict[str, Any]:
    """Require one exact zero-status section and normalize its body."""

    begin = "__CPAUTO_DEPLOYMENT_AGENT_STATUS_BEGIN__"
    end = "__CPAUTO_DEPLOYMENT_AGENT_STATUS_END__:0"
    if any(
        (
            ord(character) < 32
            and character not in {"\t", "\r", "\n"}
        )
        or 0x7F <= ord(character) <= 0x9F
        or character in {"\u2028", "\u2029"}
        for character in output
    ):
        _fail("STATUS_CONTROL", "Deployment Agent envelope contains control text")
    lines = output.replace("\r\n", "\n").splitlines()
    if len(lines) < 3 or lines[0] != begin or lines[-1] != end:
        _fail("ACQUISITION_SECTIONS", "Deployment Agent section envelope is invalid")
    if any(line.startswith("__CPAUTO_") for line in lines[1:-1]):
        _fail("ACQUISITION_SECTIONS", "Deployment Agent section contains a marker")
    body = "\n".join(lines[1:-1]) + "\n"
    if not body.strip():
        _fail("ACQUISITION_SECTIONS", "Deployment Agent section is empty")
    try:
        return parse_status(body)
    except DeploymentAgentError as error:
        raise DeploymentAgentAcquisitionError(error.category, str(error)) from error


def acquire(
    request: Callable[[str, dict[str, Any]], tuple[int, object]],
    timeout_seconds: int,
    poll_interval_seconds: int,
    authorization_deadline_epoch: float,
    monotonic: Callable[[], float] = time.monotonic,
    wall_clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Run and validate the fixed operation through a supplied Gaia requester."""

    if (
        isinstance(authorization_deadline_epoch, bool)
        or not isinstance(authorization_deadline_epoch, (int, float))
        or not math.isfinite(float(authorization_deadline_epoch))
    ):
        _fail("ACQUISITION_INVALID", "authorization deadline must be an epoch number")
    initial_wall_time = wall_clock()
    if initial_wall_time >= authorization_deadline_epoch:
        _fail("LEASE_EXPIRED", "authorization lease expired before submission")
    authorization_monotonic_deadline = (
        monotonic() + authorization_deadline_epoch - initial_wall_time
    )

    def expired() -> bool:
        return (
            wall_clock() >= authorization_deadline_epoch
            or monotonic() >= authorization_monotonic_deadline
        )

    try:
        code, response = request("run-script", operation_payload())
    except Exception as error:  # pylint: disable=broad-exception-caught
        raise DeploymentAgentAcquisitionError(
            "ACQUISITION_TRANSPORT",
            "run-script request failed",
        ) from error
    if expired():
        submitted_task_id = None
        if code == 200:
            try:
                submitted_task_id = _task_id(response)
            except DeploymentAgentAcquisitionError:
                pass
        raise DeploymentAgentAcquisitionError(
            "LEASE_EXPIRED",
            "authorization lease expired during submission",
            task_id=submitted_task_id,
        )
    if code != 200:
        _fail("ACQUISITION_HTTP", "run-script request did not return HTTP 200")
    task_id = _task_id(response)
    operation_deadline = monotonic() + timeout_seconds
    polls = 0
    task_visible = False
    initial_visibility_failures = 0
    try:
        while True:
            if expired():
                _fail("LEASE_EXPIRED", "authorization lease expired during acquisition")
            if monotonic() >= operation_deadline:
                _fail("ACQUISITION_TIMEOUT", "fixed Deployment Agent operation timed out")
            polls += 1
            try:
                code, response = request("show-task", {"task-id": task_id})
            except Exception as error:  # pylint: disable=broad-exception-caught
                raise DeploymentAgentAcquisitionError(
                    "ACQUISITION_TRANSPORT",
                    "show-task request failed",
                    task_id=task_id,
                ) from error
            if expired():
                _fail("LEASE_EXPIRED", "authorization lease expired during task poll")
            if code != 200:
                if task_visible:
                    _fail("ACQUISITION_HTTP", "visible task later returned non-200")
                initial_visibility_failures += 1
                if initial_visibility_failures >= MAX_INITIAL_TASK_VISIBILITY_POLLS:
                    _fail("ACQUISITION_HTTP", "task did not become visible in time")
                remaining = min(
                    operation_deadline - monotonic(),
                    authorization_deadline_epoch - wall_clock(),
                    authorization_monotonic_deadline - monotonic(),
                )
                if remaining > 0:
                    sleep(min(poll_interval_seconds, remaining))
                continue
            task_visible = True
            task = _single_task(response, task_id)
            if task["status"] == "in progress":
                remaining = min(
                    operation_deadline - monotonic(),
                    authorization_deadline_epoch - wall_clock(),
                    authorization_monotonic_deadline - monotonic(),
                )
                if remaining > 0:
                    sleep(min(poll_interval_seconds, remaining))
                continue
            observation = parse_envelope(_decode_output(task))
            return {"task_id": task_id, "polls": polls, **observation}
    except DeploymentAgentAcquisitionError as error:
        error.task_id = task_id
        raise
