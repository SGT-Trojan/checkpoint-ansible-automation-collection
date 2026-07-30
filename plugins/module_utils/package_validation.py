# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Transport-free package identity and prerequisite validation."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from pathlib import PurePosixPath
import re
from typing import Any


SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
INSTALL_ACTIONS = frozenset({"install", "upgrade"})
ALL_ACTIONS = INSTALL_ACTIONS | {"remove"}
MAJOR_UPGRADE_TYPES = frozenset({"blink", "blink_image", "major_upgrade"})
SUPPORTED_PACKAGE_TYPES = frozenset(
    {
        "jhf",
        "hotfix",
        "deployment_agent",
        "wrapper",
    }
) | MAJOR_UPGRADE_TYPES
BLINK_MARKER = re.compile(r"blink", re.IGNORECASE)
STEP_KEYS = frozenset(
    {
        "name",
        "action",
        "package_type",
        "package_name",
        "source_path",
        "checksum_sha256",
        "target_ids",
        "requires_present",
        "requires_absent",
        "minimum_restore_point_bytes",
    }
)
ARTIFACT_KEYS = frozenset({"path", "size", "sha256"})
TARGET_KEYS = frozenset(
    {
        "step_name",
        "target_id",
        "installed_packages",
        "installed_packages_complete",
        "restore_point_free_bytes",
    }
)


class PackageValidationError(ValueError):
    """The package contract is malformed, ambiguous, or unsatisfied."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _fail(category: str, message: str) -> None:
    raise PackageValidationError(category, message)


def _mapping(value: object, label: str, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("INVALID_INPUT", f"{label} must be a dictionary")
    unknown = set(value) - keys
    if unknown:
        _fail("INVALID_INPUT", f"{label} contains unsupported fields")
    return value


def _text(value: object, label: str, *, required: bool = True) -> str:
    if not isinstance(value, str):
        _fail("INVALID_INPUT", f"{label} must be a string")
    result = value.strip()
    if required and not result:
        _fail("INVALID_INPUT", f"{label} must not be empty")
    if "\x00" in result or "\n" in result or "\r" in result:
        _fail("INVALID_INPUT", f"{label} contains prohibited control text")
    return result


def _string_list(value: object, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        _fail("INVALID_INPUT", f"{label} must be a list")
    result = [_text(item, label) for item in value]
    if len(result) != len(set(result)):
        _fail("PACKAGE_AMBIGUOUS", f"{label} contains duplicate identities")
    return result


def _absolute_path(value: object, label: str) -> str:
    result = _text(value, label)
    path = PurePosixPath(result)
    if not path.is_absolute() or ".." in path.parts or result.endswith("/"):
        _fail("PACKAGE_IDENTITY_INVALID", f"{label} must be an absolute file path")
    if str(path) != result:
        _fail("PACKAGE_IDENTITY_INVALID", f"{label} must be lexically canonical")
    if path.name in {"", ".", ".."}:
        _fail("PACKAGE_IDENTITY_INVALID", f"{label} must identify one file")
    return result


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str):
        _fail("CHECKSUM_INVALID", f"{label} must be exactly 64 hexadecimal digits")
    result = value.strip()
    if not SHA256.fullmatch(result):
        _fail("CHECKSUM_INVALID", f"{label} must be exactly 64 hexadecimal digits")
    return result.lower()


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail("INVALID_INPUT", f"{label} must be a positive integer")
    return value


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail("INVALID_INPUT", f"{label} must be a non-negative integer")
    return value


def _artifacts(values: object) -> dict[str, dict[str, Any]]:
    if not isinstance(values, list):
        _fail("INVALID_INPUT", "artifacts must be a list")
    result: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(values):
        artifact = _mapping(raw, f"artifact {index}", ARTIFACT_KEYS)
        path = _absolute_path(artifact.get("path"), f"artifact {index} path")
        if path in result:
            _fail("PACKAGE_AMBIGUOUS", "artifact paths must be unique")
        result[path] = {
            "path": path,
            "size": _positive_integer(
                artifact.get("size"),
                f"artifact {index} size",
            ),
            "sha256": _sha256(
                artifact.get("sha256"),
                f"artifact {index} sha256",
            ),
        }
    return result


def _targets(values: object) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(values, list):
        _fail("INVALID_INPUT", "target_states must be a list")
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for index, raw in enumerate(values):
        target = _mapping(raw, f"target state {index}", TARGET_KEYS)
        step_name = _text(
            target.get("step_name"),
            f"target state {index} step name",
        )
        target_id = _text(target.get("target_id"), f"target state {index} identity")
        key = (step_name, target_id)
        if key in result:
            _fail(
                "PACKAGE_AMBIGUOUS",
                "target identities must be unique within each package step",
            )
        packages = _string_list(
            target.get("installed_packages"),
            f"target {target_id} installed packages",
        )
        if target.get("installed_packages_complete") is not True:
            _fail(
                "INVENTORY_INCOMPLETE",
                "installed package inventory must be explicitly complete",
            )
        restore = target.get("restore_point_free_bytes")
        if restore is not None:
            restore = _nonnegative_integer(
                restore,
                f"target {target_id} restore-point capacity",
            )
        result[key] = {
            "step_name": step_name,
            "target_id": target_id,
            "installed_packages": packages,
            "installed_packages_complete": True,
            "restore_point_free_bytes": restore,
        }
    return result


def validate_package_contract(
    package_steps: object,
    artifacts: object,
    target_states: object,
) -> dict[str, Any]:
    """Validate exact package actions against structured offline observations."""

    if not isinstance(package_steps, list) or not package_steps:
        _fail("INVALID_INPUT", "package_steps must be a non-empty list")
    artifact_by_path = _artifacts(artifacts)
    targets = _targets(target_states)
    normalized_steps: list[dict[str, Any]] = []
    names: set[str] = set()
    used_artifacts: set[str] = set()
    used_target_states: set[tuple[str, str]] = set()

    for index, raw in enumerate(package_steps):
        step = _mapping(raw, f"package step {index}", STEP_KEYS)
        name = _text(step.get("name"), f"package step {index} name")
        if name in names:
            _fail("PACKAGE_AMBIGUOUS", "package step names must be unique")
        names.add(name)
        action_value = step.get("action")
        action = action_value.strip() if isinstance(action_value, str) else ""
        if action not in ALL_ACTIONS:
            _fail("ACTION_INVALID", f"package step {name} has unsupported action")
        package_type = _text(
            step.get("package_type"),
            f"package step {name} type",
        ).lower()
        if package_type not in SUPPORTED_PACKAGE_TYPES:
            _fail(
                "PACKAGE_TYPE_INVALID",
                f"package step {name} has unsupported package type",
            )
        package_name = _text(
            step.get("package_name"),
            f"package step {name} package name",
        )
        target_ids = _string_list(
            step.get("target_ids"),
            f"package step {name} target_ids",
        )
        if not target_ids:
            _fail(
                "TARGET_INVALID",
                f"package step {name} requires expected target identities",
            )
        requires_present = _string_list(
            step.get("requires_present"),
            f"package step {name} requires_present",
        )
        requires_absent = _string_list(
            step.get("requires_absent"),
            f"package step {name} requires_absent",
        )
        if set(requires_present) & set(requires_absent):
            _fail(
                "PREREQUISITE_INVALID",
                f"package step {name} has contradictory prerequisites",
            )

        normalized: dict[str, Any] = {
            "name": name,
            "action": action,
            "package_type": package_type,
            "package_name": package_name,
            "target_ids": target_ids,
            "requires_present": requires_present,
            "requires_absent": requires_absent,
        }
        if action in INSTALL_ACTIONS:
            source_path = _absolute_path(
                step.get("source_path"),
                f"package step {name} source path",
            )
            if PurePosixPath(source_path).name != package_name:
                _fail(
                    "PACKAGE_IDENTITY_INVALID",
                    f"package step {name} name does not match its source file",
                )
            expected_sha256 = _sha256(
                step.get("checksum_sha256"),
                f"package step {name} SHA-256",
            )
            artifact = artifact_by_path.get(source_path)
            if artifact is None:
                _fail(
                    "ARTIFACT_MISSING",
                    f"package step {name} has no exact artifact observation",
                )
            if artifact["sha256"] != expected_sha256:
                _fail(
                    "CHECKSUM_MISMATCH",
                    f"package step {name} artifact SHA-256 does not match",
                )
            if source_path in used_artifacts:
                _fail(
                    "PACKAGE_AMBIGUOUS",
                    f"package artifact {source_path} is assigned more than once",
                )
            used_artifacts.add(source_path)
            normalized.update(
                {
                    "source_path": source_path,
                    "checksum_sha256": expected_sha256,
                    "artifact_size": artifact["size"],
                }
            )
        else:
            if package_name == name:
                _fail(
                    "PACKAGE_IDENTITY_INVALID",
                    f"removal step {name} must name the package, not the step",
                )
            if _text(
                step.get("source_path", ""),
                f"package step {name} source path",
                required=False,
            ) or _text(
                step.get("checksum_sha256", ""),
                f"package step {name} SHA-256",
                required=False,
            ):
                _fail(
                    "ACTION_INVALID",
                    f"removal step {name} must not declare an artifact or checksum",
                )

        minimum_restore = step.get("minimum_restore_point_bytes")
        major_upgrade = (
            action in INSTALL_ACTIONS
            and package_type in MAJOR_UPGRADE_TYPES
        )
        identity_blob = " ".join(
            value
            for value in (
                package_name,
                normalized.get("source_path", ""),
            )
            if value
        )
        if package_type not in MAJOR_UPGRADE_TYPES and BLINK_MARKER.search(
            identity_blob
        ):
            _fail(
                "PACKAGE_TYPE_INVALID",
                f"package step {name} has a Blink identity but a non-major type",
            )
        if major_upgrade:
            minimum_restore = _positive_integer(
                minimum_restore,
                f"package step {name} minimum restore-point capacity",
            )
            normalized["minimum_restore_point_bytes"] = minimum_restore
        elif minimum_restore is not None:
            _fail(
                "PREREQUISITE_INVALID",
                f"package step {name} cannot declare restore-point capacity",
            )

        step_targets = {
            key: target
            for key, target in targets.items()
            if key[0] == name
        }
        used_target_states.update(step_targets)
        observed_target_ids = {key[1] for key in step_targets}
        if observed_target_ids != set(target_ids):
            _fail(
                "TARGET_MISMATCH",
                f"package step {name} target observations do not match its target_ids",
            )
        for (_step_name, target_id), target in step_targets.items():
            installed = set(target["installed_packages"])
            missing = sorted(set(requires_present) - installed)
            conflicting = sorted(set(requires_absent) & installed)
            if missing or conflicting:
                _fail(
                    "PREREQUISITE_FAILED",
                    f"package step {name} prerequisites fail on target {target_id}",
                )
            if major_upgrade:
                available = target["restore_point_free_bytes"]
                if available is None:
                    _fail(
                        "PREREQUISITE_INCOMPLETE",
                        f"target {target_id} lacks restore-point capacity",
                    )
                if available < minimum_restore:
                    _fail(
                        "PREREQUISITE_FAILED",
                        f"target {target_id} lacks required restore-point capacity",
                    )
        normalized_steps.append(normalized)

    if set(artifact_by_path) != used_artifacts:
        _fail(
            "PACKAGE_AMBIGUOUS",
            "artifact observations must exactly match install and upgrade steps",
        )
    if set(targets) != used_target_states:
        _fail(
            "PREREQUISITE_INVALID",
            "target observations reference an unknown package step",
        )
    return {
        "valid": True,
        "step_count": len(normalized_steps),
        "artifact_count": len(used_artifacts),
        "target_count": len(targets),
        "steps": normalized_steps,
    }
