# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Bind one validated Deployment Agent package to numeric build policy."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any


MAX_BUILD = 9999999999
SHA256 = re.compile(r"^[0-9a-f]{64}$")
STEP_KEYS = frozenset(
    {
        "name",
        "action",
        "package_type",
        "package_name",
        "target_ids",
        "requires_present",
        "requires_absent",
        "source_path",
        "checksum_sha256",
        "artifact_size",
    }
)


class DeploymentAgentPackageError(ValueError):
    """The Deployment Agent package binding is malformed or unsafe."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _fail(category: str, message: str) -> None:
    raise DeploymentAgentPackageError(category, message)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _fail("BINDING_INVALID", f"{label} must be normalized text")
    if not value.isprintable():
        _fail("BINDING_INVALID", f"{label} contains prohibited control text")
    return value


def _build(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_BUILD
    ):
        _fail("BUILD_INVALID", f"{label} is outside the approved range")
    return value


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        _fail("BINDING_INVALID", f"{label} must be a normalized list")
    result = [_text(item, label) for item in value]
    if len(result) != len(set(result)):
        _fail("BINDING_AMBIGUOUS", f"{label} contains duplicate identities")
    return result


def bind_deployment_agent_package(
    package_step: object,
    required_build: object,
    expected_build: object,
) -> dict[str, Any]:
    """Return one detached package and build binding for later execution."""

    if not isinstance(package_step, dict) or set(package_step) != STEP_KEYS:
        _fail(
            "BINDING_INVALID",
            "package_step is not one normalized install or upgrade step",
        )

    name = _text(package_step["name"], "package step name")
    action_value = package_step["action"]
    action = (
        action_value
        if isinstance(action_value, str) and action_value == action_value.strip()
        else ""
    )
    if action not in {"install", "upgrade"}:
        _fail("ACTION_INVALID", "Deployment Agent action must be install or upgrade")
    if package_step["package_type"] != "deployment_agent":
        _fail(
            "PACKAGE_TYPE_INVALID",
            "package step is not a Deployment Agent package",
        )

    package_name = _text(package_step["package_name"], "package name")
    source_path = _text(package_step["source_path"], "source path")
    path = PurePosixPath(source_path)
    if (
        not path.is_absolute()
        or source_path.startswith("//")
        or ".." in path.parts
        or source_path.endswith("/")
        or str(path) != source_path
        or path.name != package_name
    ):
        _fail(
            "PACKAGE_IDENTITY_INVALID",
            "package name and canonical source path do not identify one file",
        )

    checksum = package_step["checksum_sha256"]
    if not isinstance(checksum, str) or SHA256.fullmatch(checksum) is None:
        _fail(
            "CHECKSUM_INVALID",
            "package SHA-256 must be normalized lowercase hexadecimal",
        )
    size = package_step["artifact_size"]
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        _fail("PACKAGE_IDENTITY_INVALID", "artifact size must be positive")

    target_ids = _string_list(package_step["target_ids"], "target_ids")
    if len(target_ids) != 2:
        _fail(
            "TARGET_INVALID",
            "Deployment Agent package binding requires exactly two targets",
        )
    _string_list(package_step["requires_present"], "requires_present")
    _string_list(package_step["requires_absent"], "requires_absent")

    minimum = _build(required_build, "required_build")
    expected = _build(expected_build, "expected_build")
    if expected < minimum:
        _fail("BUILD_INVALID", "expected_build must meet required_build")

    binding: dict[str, Any] = {
        "step_name": name,
        "operation": "installer_agent_install",
        "plan_action": action,
        "package_name": package_name,
        "source_path": source_path,
        "checksum_sha256": checksum,
        "artifact_size": size,
        "target_ids": target_ids,
        "required_build": minimum,
        "expected_build": expected,
    }
    canonical = json.dumps(
        binding,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    binding["binding_sha256"] = hashlib.sha256(canonical).hexdigest()
    return binding
