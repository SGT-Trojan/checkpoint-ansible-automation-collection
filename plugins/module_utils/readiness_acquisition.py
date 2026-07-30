# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Bounded validation for the fixed Gaia readiness operation."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import base64
import binascii
import re
import time
from typing import Any, Callable


class AcquisitionError(ValueError):
    """The fixed Gaia operation or its result violated the contract."""

    def __init__(
        self,
        category: str,
        message: str,
        task_id: str | None = None,
    ):
        super().__init__(message)
        self.category = category
        self.task_id = task_id


TASK_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
SECTION_NAMES = (
    "CLUSTER_STATE",
    "CLUSTER_INTERFACES",
    "ICAP_CPWD",
    "ICAP_LISTENER",
    "ICAP_PROCESS",
)

# This is deliberately not caller-configurable. Gaia executes it through the
# run-script endpoint when Gaia reports the expert_api_runScript feature record.
FIXED_READINESS_SCRIPT = r"""#!/bin/bash
if [ ! -r /etc/profile.d/CP.sh ]; then
    exit 125
fi
source /etc/profile.d/CP.sh >/dev/null 2>&1 || exit 125
export LC_ALL=C
export PATH="${PATH:-}:/bin:/usr/bin:/sbin:/usr/sbin"
printf '%s\n' '__CPAUTO_CLUSTER_STATE_BEGIN__'
cphaprob state
printf '__CPAUTO_CLUSTER_STATE_END__:%s\n' "$?"
printf '%s\n' '__CPAUTO_CLUSTER_INTERFACES_BEGIN__'
cphaprob -a if
printf '__CPAUTO_CLUSTER_INTERFACES_END__:%s\n' "$?"
printf '%s\n' '__CPAUTO_ICAP_CPWD_BEGIN__'
cpwd_admin list
printf '__CPAUTO_ICAP_CPWD_END__:%s\n' "$?"
printf '%s\n' '__CPAUTO_ICAP_LISTENER_BEGIN__'
if command -v ss >/dev/null 2>&1; then
    ss -lnt
elif command -v netstat >/dev/null 2>&1; then
    netstat -lnt
else
    false
fi
printf '__CPAUTO_ICAP_LISTENER_END__:%s\n' "$?"
printf '%s\n' '__CPAUTO_ICAP_PROCESS_BEGIN__'
ps -eo pid=,args=
printf '__CPAUTO_ICAP_PROCESS_END__:%s\n' "$?"
"""


def operation_payload() -> dict[str, str]:
    """Return the only operation payload this module may send."""

    return {
        "script": FIXED_READINESS_SCRIPT,
        "description": "Ansible bounded readiness observation",
    }


def _fail(category: str, message: str) -> None:
    raise AcquisitionError(category, message)


def _task_id(response: object) -> str:
    if not isinstance(response, dict) or set(response) != {"task-id"}:
        _fail("ACQUISITION_PROTOCOL", "run-script response must contain only task-id")
    value = response["task-id"]
    if not isinstance(value, str) or not TASK_ID.fullmatch(value):
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
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        _fail("ACQUISITION_PROTOCOL", "task status-code must be an integer")
    return task


def _decode_output(task: dict[str, Any], max_output_bytes: int) -> str:
    if task["status"] != "succeeded":
        _fail("ACQUISITION_FAILED", "fixed readiness operation did not succeed")
    if task["status-code"] != 200:
        _fail("ACQUISITION_FAILED", "fixed readiness operation status-code is not 200")
    if task.get("progress-percentage") != 100:
        _fail("ACQUISITION_PROTOCOL", "succeeded task progress must be 100")
    details = task.get("task-details")
    if not isinstance(details, list) or len(details) != 1 or not isinstance(details[0], dict):
        _fail("ACQUISITION_PROTOCOL", "succeeded task must have exactly one detail")
    detail = details[0]
    if set(detail) != {"error", "output", "return-value"}:
        _fail("ACQUISITION_PROTOCOL", "task detail fields do not match run-script")
    if detail["error"] not in ("", None):
        _fail("ACQUISITION_FAILED", "fixed readiness operation returned an error")
    return_value = detail["return-value"]
    if isinstance(return_value, bool) or return_value != 0:
        _fail("ACQUISITION_FAILED", "fixed readiness operation return-value is not zero")
    encoded = detail["output"]
    if not isinstance(encoded, str):
        _fail("ACQUISITION_PROTOCOL", "run-script output must be base64 text")
    maximum_encoded = ((max_output_bytes + 2) // 3) * 4
    if len(encoded) > maximum_encoded:
        _fail("ACQUISITION_TOO_LARGE", "encoded readiness output exceeds the limit")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise AcquisitionError(
            "ACQUISITION_PROTOCOL",
            "run-script output is not canonical base64",
        ) from error
    if base64.b64encode(decoded).decode("ascii") != encoded:
        _fail("ACQUISITION_PROTOCOL", "run-script output is not canonical base64")
    if len(decoded) > max_output_bytes:
        _fail("ACQUISITION_TOO_LARGE", "decoded readiness output exceeds the limit")
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AcquisitionError(
            "ACQUISITION_PROTOCOL",
            "run-script output is not UTF-8",
        ) from error


def parse_sections(output: str) -> dict[str, str]:
    """Require the exact ordered section envelope and zero command statuses."""

    lines = output.replace("\r\n", "\n").splitlines()
    result: dict[str, str] = {}
    cursor = 0
    for section in SECTION_NAMES:
        begin = f"__CPAUTO_{section}_BEGIN__"
        end_prefix = f"__CPAUTO_{section}_END__:"
        if cursor >= len(lines) or lines[cursor] != begin:
            _fail("ACQUISITION_SECTIONS", f"missing or out-of-order {section} section")
        cursor += 1
        body: list[str] = []
        while cursor < len(lines) and not lines[cursor].startswith(end_prefix):
            if lines[cursor].startswith("__CPAUTO_"):
                _fail("ACQUISITION_SECTIONS", f"malformed {section} section envelope")
            body.append(lines[cursor])
            cursor += 1
        if cursor >= len(lines) or lines[cursor] != end_prefix + "0":
            _fail("ACQUISITION_COMMAND_FAILED", f"{section} command did not return zero")
        if not any(line.strip() for line in body):
            _fail("ACQUISITION_SECTIONS", f"{section} section is empty")
        result[section.casefold()] = "\n".join(body) + "\n"
        cursor += 1
    if any(line.strip() for line in lines[cursor:]):
        _fail("ACQUISITION_SECTIONS", "unexpected output follows readiness sections")
    return result


def acquire(
    request: Callable[[str, dict[str, Any]], tuple[int, object]],
    timeout_seconds: int,
    poll_interval_seconds: int,
    max_output_bytes: int,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Run and validate the fixed operation through a supplied Gaia requester."""

    try:
        code, response = request("run-script", operation_payload())
    except Exception as error:  # pylint: disable=broad-exception-caught
        raise AcquisitionError(
            "ACQUISITION_TRANSPORT",
            "run-script request failed",
        ) from error
    if code != 200:
        _fail("ACQUISITION_HTTP", "run-script request did not return HTTP 200")
    task_id = _task_id(response)
    deadline = monotonic() + timeout_seconds
    polls = 0
    try:
        while True:
            if monotonic() >= deadline:
                _fail("ACQUISITION_TIMEOUT", "fixed readiness operation timed out")
            polls += 1
            try:
                code, response = request("show-task", {"task-id": task_id})
            except Exception as error:  # pylint: disable=broad-exception-caught
                raise AcquisitionError(
                    "ACQUISITION_TRANSPORT",
                    "show-task request failed",
                    task_id=task_id,
                ) from error
            if code != 200:
                _fail("ACQUISITION_HTTP", "show-task request did not return HTTP 200")
            task = _single_task(response, task_id)
            if task["status"] == "in progress":
                sleep(poll_interval_seconds)
                continue
            output = _decode_output(task, max_output_bytes)
            return {
                "task_id": task_id,
                "polls": polls,
                "sections": parse_sections(output),
            }
    except AcquisitionError as error:
        error.task_id = task_id
        raise
