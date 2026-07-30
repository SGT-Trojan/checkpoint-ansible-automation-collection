# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Bounded Gaia acquisition for installed packages and restore capacity."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import base64
import binascii
from decimal import Decimal, ROUND_FLOOR
import math
import re
import time
from typing import Any, Callable


SAFE_PARSER_REASONS = frozenset(
    {
        "IDENTITY_BOUNDS",
        "IDENTITY_CONTROL",
        "SECTION_BOUNDS",
        "SECTION_CONTROL",
        "STATUS_EMPTY",
        "STATUS_MULTI_COLUMN",
        "STATUS_ROW_MALFORMED",
        "STATUS_STATUS_CASE",
        "TYPE_BOUNDS",
        "TYPE_CONTROL",
        "TYPED_HEADER_MISSING",
        "TYPED_HEADER_UNSUPPORTED",
        "TYPED_OUTSIDE_TABLE",
        "TYPED_ROW_COLUMNS",
        "TYPED_SECTION_HEADER_MISSING",
        "TYPED_TYPE_UNKNOWN",
    }
)
SAFE_LINE_SHAPES = frozenset(
    {
        "HEADER_OTHER",
        "HEADER_TYPE",
        "MORE",
        "MULTI_OTHER",
        "MULTI_TYPE",
        "SEPARATOR",
        "SINGLE_OTHER",
        "STATUS_CASE",
        "STATUS_INSTALLED",
        "TITLE",
    }
)


class PackageStateAcquisitionError(ValueError):
    """The fixed Gaia operation or its result violated the contract."""

    def __init__(
        self,
        category: str,
        message: str,
        task_id: str | None = None,
        reason: str | None = None,
        shape: tuple[str, ...] | None = None,
    ):
        super().__init__(message)
        self.category = category
        self.task_id = task_id
        self.reason = reason if reason in SAFE_PARSER_REASONS else None
        self.shape = (
            shape
            if (
                isinstance(shape, tuple)
                and 0 < len(shape) <= 17
                and all(item in SAFE_LINE_SHAPES for item in shape)
            )
            else None
        )


TASK_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
SECTION_NAMES = ("PACKAGES_INSTALLED", "SNAPSHOTS")
MAX_INITIAL_TASK_VISIBILITY_POLLS = 40

# This script is fixed collection content. Callers cannot add commands, paths,
# arguments, variables, or environment entries.
FIXED_PACKAGE_STATE_SCRIPT = r"""#!/bin/bash
if [ ! -r /etc/profile.d/CP.sh ]; then
    exit 125
fi
source /etc/profile.d/CP.sh >/dev/null 2>&1 || exit 125
export LC_ALL=C
export PATH="${PATH:-}:/bin:/usr/bin:/sbin:/usr/sbin"
printf '%s\n' '__CPAUTO_PACKAGES_INSTALLED_BEGIN__'
/bin/clish -c 'show installer packages installed'
printf '__CPAUTO_PACKAGES_INSTALLED_END__:%s\n' "$?"
printf '%s\n' '__CPAUTO_SNAPSHOTS_BEGIN__'
/bin/clish -c 'show snapshots'
printf '__CPAUTO_SNAPSHOTS_END__:%s\n' "$?"
"""


def operation_payload() -> dict[str, str]:
    """Return the only operation payload this module may send."""

    return {
        "script": FIXED_PACKAGE_STATE_SCRIPT,
        "description": "Ansible bounded package state observation",
    }


def _fail(category: str, message: str, reason: str | None = None) -> None:
    raise PackageStateAcquisitionError(category, message, reason=reason)


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
    if status == "in progress" and status_code is None:
        return task
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        _fail("ACQUISITION_PROTOCOL", "task status-code must be an integer")
    return task


def _decode_output(task: dict[str, Any], max_output_bytes: int) -> str:
    if task["status"] != "succeeded":
        _fail("ACQUISITION_FAILED", "fixed package state operation did not succeed")
    if task["status-code"] != 200:
        _fail("ACQUISITION_FAILED", "fixed package state operation status-code is not 200")
    if task.get("progress-percentage") != 100:
        _fail("ACQUISITION_PROTOCOL", "succeeded task progress must be 100")
    details = task.get("task-details")
    if not isinstance(details, list) or len(details) != 1 or not isinstance(details[0], dict):
        _fail("ACQUISITION_PROTOCOL", "succeeded task must have exactly one detail")
    detail = details[0]
    if set(detail) != {"error", "output", "return-value"}:
        _fail("ACQUISITION_PROTOCOL", "task detail fields do not match run-script")
    if detail["error"] not in ("", None):
        _fail("ACQUISITION_FAILED", "fixed package state operation returned an error")
    return_value = detail["return-value"]
    if isinstance(return_value, bool) or return_value != 0:
        _fail("ACQUISITION_FAILED", "fixed package state operation return-value is not zero")
    encoded = detail["output"]
    if not isinstance(encoded, str):
        _fail("ACQUISITION_PROTOCOL", "run-script output must be base64 text")
    maximum_encoded = ((max_output_bytes + 2) // 3) * 4
    if len(encoded) > maximum_encoded:
        _fail("ACQUISITION_TOO_LARGE", "encoded package state output exceeds the limit")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise PackageStateAcquisitionError(
            "ACQUISITION_PROTOCOL",
            "run-script output is not canonical base64",
        ) from error
    if base64.b64encode(decoded).decode("ascii") != encoded:
        _fail("ACQUISITION_PROTOCOL", "run-script output is not canonical base64")
    if len(decoded) > max_output_bytes:
        _fail("ACQUISITION_TOO_LARGE", "decoded package state output exceeds the limit")
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PackageStateAcquisitionError(
            "ACQUISITION_PROTOCOL",
            "run-script output is not UTF-8",
        ) from error


def parse_sections(output: str) -> dict[str, str]:
    """Require the exact ordered section envelope and zero command statuses."""

    if "\x00" in output:
        _fail("ACQUISITION_PROTOCOL", "run-script output contains a null byte")
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
        _fail("ACQUISITION_SECTIONS", "unexpected output follows package state sections")
    return result


INCOMPLETE_MARKER = re.compile(
    r"(?:connection\s+error|might\s+be\s+incomplete|inventory\s+is\s+incomplete)",
    re.IGNORECASE,
)
CAPACITY_LINE = re.compile(
    r"^\s*Amount of space available for restore points is\s+"
    r"([0-9]{1,15}(?:\.[0-9]{1,6})?)\s*"
    r"(?:(?:([KMGTPE])(?:i?B|bytes?)?)|(?:i?B|bytes?))\s*$",
    re.IGNORECASE,
)
SNAPSHOT_FAILURE_MARKER = re.compile(
    r"^\s*(?:error|failed|failure|invalid command|CLINFR[0-9]+)\b",
    re.IGNORECASE | re.MULTILINE,
)
CAPACITY_FACTORS = {
    "": 1,
    "K": 1024,
    "M": 1024**2,
    "G": 1024**3,
    "T": 1024**4,
    "P": 1024**5,
    "E": 1024**6,
}
MAX_PACKAGE_COUNT = 4096
MAX_RESTORE_POINT_BYTES = 2**63 - 1
PACKAGE_TYPES = frozenset(
    {
        "hotfix",
        "blink version",
        "major version",
        "minor version",
        "upgrade",
    }
)
INSTALLED_STATUS_ROW = re.compile(r"^(.+?)\s+Installed$")
MAX_FORMAT_SHAPE_LINES = 16


def _package_output_shape(output: str) -> tuple[str, ...]:
    shape: list[str] = []
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if len(shape) == MAX_FORMAT_SHAPE_LINES:
            shape.append("MORE")
            break
        if re.fullmatch(r"\*\*\s+([^*].*?)\s+\*\*", stripped):
            kind = "TITLE"
        elif stripped.startswith("Display name") and re.search(
            r"\s{2,}Type\s*$", raw_line, re.IGNORECASE
        ):
            kind = "HEADER_TYPE"
        elif stripped.casefold().startswith("display name"):
            kind = "HEADER_OTHER"
        elif set(stripped) <= {"*", "-", " "}:
            kind = "SEPARATOR"
        elif INSTALLED_STATUS_ROW.fullmatch(stripped):
            kind = "STATUS_INSTALLED"
        elif re.search(r"\s{2,}", stripped):
            final_column = re.split(r"\s{2,}", stripped)[-1].casefold()
            kind = "MULTI_TYPE" if final_column in PACKAGE_TYPES else "MULTI_OTHER"
        elif stripped.casefold().endswith(" installed"):
            kind = "STATUS_CASE"
        else:
            kind = "SINGLE_OTHER"
        shape.append(kind)
    return tuple(shape)


def _bounded_text(value: str, limit: int, label: str) -> str:
    reason_prefix = {
        "package identity": "IDENTITY",
        "package section": "SECTION",
        "package type": "TYPE",
    }.get(label)
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > limit:
        reason = f"{reason_prefix}_BOUNDS" if reason_prefix is not None else None
        _fail(
            "INVENTORY_FORMAT",
            f"{label} is empty or exceeds its limit",
            reason,
        )
    if any(ord(character) < 32 for character in normalized):
        reason = f"{reason_prefix}_CONTROL" if reason_prefix is not None else None
        _fail("INVENTORY_FORMAT", f"{label} contains control text", reason)
    return normalized


def _append_package(packages: list[str], seen: set[str], value: str) -> None:
    name = _bounded_text(value, 512, "package identity")
    if name in seen:
        _fail("INVENTORY_AMBIGUOUS", "installed package identities are not unique")
    seen.add(name)
    packages.append(name)
    if len(packages) > MAX_PACKAGE_COUNT:
        _fail("INVENTORY_TOO_LARGE", "installed package count exceeds the limit")


def _parse_typed_package_table(output: str) -> list[str]:
    packages: list[str] = []
    seen: set[str] = set()
    header_seen = False
    section_needs_header = False
    in_table = False
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        title = re.fullmatch(r"\*\*\s+([^*].*?)\s+\*\*", stripped)
        if title:
            _bounded_text(title.group(1), 128, "package section")
            section_needs_header = True
            in_table = False
            continue
        if stripped.startswith("Display name") and re.search(
            r"\s{2,}Type\s*$", raw_line, re.IGNORECASE
        ):
            header_seen = True
            section_needs_header = False
            in_table = True
            continue
        if not in_table and stripped.casefold().startswith("display name"):
            _fail(
                "INVENTORY_FORMAT",
                "installed package table header is not recognized",
                "TYPED_HEADER_UNSUPPORTED",
            )
        if set(stripped) <= {"*", "-", " "}:
            continue
        if not in_table:
            _fail(
                "INVENTORY_FORMAT",
                "unexpected text outside a package table",
                "TYPED_OUTSIDE_TABLE",
            )
        parts = re.split(r"\s{2,}", stripped, maxsplit=1)
        if len(parts) != 2:
            _fail(
                "INVENTORY_FORMAT",
                "installed package row is malformed",
                "TYPED_ROW_COLUMNS",
            )
        package_type = _bounded_text(parts[1], 128, "package type")
        if package_type.casefold() not in PACKAGE_TYPES:
            _fail(
                "INVENTORY_FORMAT",
                "installed package type is not recognized",
                "TYPED_TYPE_UNKNOWN",
            )
        _append_package(packages, seen, parts[0])
    if section_needs_header:
        _fail(
            "INVENTORY_FORMAT",
            "package section has no table header",
            "TYPED_SECTION_HEADER_MISSING",
        )
    if not header_seen:
        _fail(
            "INVENTORY_FORMAT",
            "installed package table header is missing",
            "TYPED_HEADER_MISSING",
        )
    return packages


def _parse_installed_status_rows(output: str) -> list[str]:
    packages: list[str] = []
    seen: set[str] = set()
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        match = INSTALLED_STATUS_ROW.fullmatch(stripped)
        if match is None:
            if re.search(r"\s{2,}", stripped):
                reason = "STATUS_MULTI_COLUMN"
            elif stripped.casefold().endswith(" installed"):
                reason = "STATUS_STATUS_CASE"
            else:
                reason = "STATUS_ROW_MALFORMED"
            _fail(
                "INVENTORY_FORMAT",
                "installed package status row is malformed",
                reason,
            )
        _append_package(packages, seen, match.group(1))
    if not packages:
        _fail(
            "INVENTORY_FORMAT",
            "installed package status list is empty",
            "STATUS_EMPTY",
        )
    return packages


def parse_installed_packages(output: str) -> list[str]:
    """Parse every row of one recognized CPUSE installed-package format."""

    if INCOMPLETE_MARKER.search(output):
        _fail("INVENTORY_INCOMPLETE", "CPUSE reported an incomplete package inventory")
    meaningful_lines = [line.strip() for line in output.splitlines() if line.strip()]
    typed_table = any(
        line.startswith("Display name")
        or re.fullmatch(r"\*\*\s+([^*].*?)\s+\*\*", line)
        for line in meaningful_lines
    )
    try:
        if typed_table:
            return _parse_typed_package_table(output)
        return _parse_installed_status_rows(output)
    except PackageStateAcquisitionError as error:
        if error.category != "INVENTORY_FORMAT":
            raise
        raise PackageStateAcquisitionError(
            error.category,
            str(error),
            reason=error.reason,
            shape=_package_output_shape(output),
        ) from error


def parse_restore_point_free_bytes(output: str) -> int:
    """Parse one explicit restore-point capacity using binary unit factors."""

    if SNAPSHOT_FAILURE_MARKER.search(output):
        _fail("CAPACITY_FORMAT", "snapshot output contains a failure marker")
    matches = [
        match
        for line in output.splitlines()
        if (match := CAPACITY_LINE.fullmatch(line)) is not None
    ]
    if len(matches) != 1:
        _fail("CAPACITY_FORMAT", "restore-point capacity must appear exactly once")
    amount = Decimal(matches[0].group(1))
    factor = CAPACITY_FACTORS[(matches[0].group(2) or "").upper()]
    value = int((amount * factor).to_integral_value(rounding=ROUND_FLOOR))
    if value > MAX_RESTORE_POINT_BYTES:
        _fail("CAPACITY_TOO_LARGE", "restore-point capacity exceeds the limit")
    return value


def parse_observation(output: str) -> dict[str, Any]:
    """Convert fixed framed output to the package validator's data shape."""

    sections = parse_sections(output)
    return {
        "installed_packages": parse_installed_packages(
            sections["packages_installed"]
        ),
        "installed_packages_complete": True,
        "restore_point_free_bytes": parse_restore_point_free_bytes(
            sections["snapshots"]
        ),
    }


def acquire(
    request: Callable[[str, dict[str, Any]], tuple[int, object]],
    timeout_seconds: int,
    poll_interval_seconds: int,
    max_output_bytes: int,
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

    def authorization_expired() -> bool:
        return (
            wall_clock() >= authorization_deadline_epoch
            or monotonic() >= authorization_monotonic_deadline
        )

    try:
        code, response = request("run-script", operation_payload())
    except Exception as error:  # pylint: disable=broad-exception-caught
        raise PackageStateAcquisitionError(
            "ACQUISITION_TRANSPORT",
            "run-script request failed",
        ) from error
    if authorization_expired():
        submitted_task_id = None
        if code == 200:
            try:
                submitted_task_id = _task_id(response)
            except PackageStateAcquisitionError:
                pass
        raise PackageStateAcquisitionError(
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
            if authorization_expired():
                _fail("LEASE_EXPIRED", "authorization lease expired during acquisition")
            current_monotonic = monotonic()
            if current_monotonic >= operation_deadline:
                _fail("ACQUISITION_TIMEOUT", "fixed package state operation timed out")
            polls += 1
            try:
                code, response = request("show-task", {"task-id": task_id})
            except Exception as error:  # pylint: disable=broad-exception-caught
                raise PackageStateAcquisitionError(
                    "ACQUISITION_TRANSPORT",
                    "show-task request failed",
                    task_id=task_id,
                ) from error
            if authorization_expired():
                _fail("LEASE_EXPIRED", "authorization lease expired during task poll")
            if code != 200:
                if task_visible:
                    _fail(
                        "ACQUISITION_HTTP",
                        "visible task later returned a non-200 response",
                    )
                initial_visibility_failures += 1
                if (
                    initial_visibility_failures
                    >= MAX_INITIAL_TASK_VISIBILITY_POLLS
                ):
                    _fail(
                        "ACQUISITION_HTTP",
                        "task did not become visible within the HTTP retry limit",
                    )
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
            observation = parse_observation(_decode_output(task, max_output_bytes))
            return {
                "task_id": task_id,
                "polls": polls,
                **observation,
            }
    except PackageStateAcquisitionError as error:
        error.task_id = task_id
        raise
