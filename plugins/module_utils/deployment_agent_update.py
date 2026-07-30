# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Create one deterministic, transport-free Deployment Agent update plan."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import hashlib
import json
import re
from typing import Any


MAX_BUILD = 9999999999
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BINDING_KEYS = frozenset(
    {
        "step_name",
        "operation",
        "plan_action",
        "package_name",
        "source_path",
        "checksum_sha256",
        "artifact_size",
        "target_ids",
        "required_build",
        "expected_build",
        "binding_sha256",
    }
)
STATE_KEYS = frozenset({"target_id", "enabled", "build", "cloud_state"})
CLOUD_STATES = frozenset({"current", "update_available", "unknown"})


class DeploymentAgentUpdateError(ValueError):
    """The update planning evidence is malformed, ambiguous, or unsafe."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _fail(category: str, message: str) -> None:
    raise DeploymentAgentUpdateError(category, message)


def _text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not value.isprintable()
    ):
        _fail("PLAN_INVALID", f"{label} must be normalized printable text")
    return value


def _build(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_BUILD
    ):
        _fail("BUILD_INVALID", f"{label} is outside the approved range")
    return value


def _binding(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != BINDING_KEYS:
        _fail("BINDING_INVALID", "package binding has an unexpected shape")
    if value["operation"] != "installer_agent_install":
        _fail("BINDING_INVALID", "package binding operation changed")
    if value["plan_action"] not in {"install", "upgrade"}:
        _fail("BINDING_INVALID", "package binding action is not approved")
    for key in ("step_name", "package_name", "source_path"):
        _text(value[key], key)
    if not isinstance(value["checksum_sha256"], str) or SHA256.fullmatch(
        value["checksum_sha256"]
    ) is None:
        _fail("BINDING_INVALID", "package binding SHA-256 is malformed")
    if (
        isinstance(value["artifact_size"], bool)
        or not isinstance(value["artifact_size"], int)
        or value["artifact_size"] <= 0
    ):
        _fail("BINDING_INVALID", "package binding size is invalid")
    targets = value["target_ids"]
    if (
        not isinstance(targets, list)
        or len(targets) != 2
        or any(_text(target, "target_id") != target for target in targets)
        or len(set(targets)) != 2
    ):
        _fail("TARGET_INVALID", "package binding requires two unique targets")
    required = _build(value["required_build"], "required_build")
    expected = _build(value["expected_build"], "expected_build")
    if expected < required:
        _fail("BUILD_INVALID", "expected build is below the required build")
    digest = value["binding_sha256"]
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        _fail("BINDING_INVALID", "package binding digest is malformed")
    canonical = {
        key: item for key, item in value.items() if key != "binding_sha256"
    }
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    if hashlib.sha256(encoded).hexdigest() != digest:
        _fail("BINDING_MISMATCH", "package binding digest does not match")
    return dict(value)


def _states(value: object, targets: list[str]) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 2:
        _fail("TARGET_INVALID", "exactly two target states are required")
    normalized: dict[str, dict[str, Any]] = {}
    for state in value:
        if not isinstance(state, dict) or set(state) != STATE_KEYS:
            _fail("TARGET_INVALID", "target state has an unexpected shape")
        target = _text(state["target_id"], "target_id")
        if target in normalized:
            _fail("TARGET_AMBIGUOUS", "target state is duplicated")
        if not isinstance(state["enabled"], bool):
            _fail("TARGET_INVALID", "target enabled state must be boolean")
        build = _build(state["build"], "observed build")
        if state["cloud_state"] not in CLOUD_STATES:
            _fail("TARGET_INVALID", "target cloud state is not normalized")
        normalized[target] = {
            "target_id": target,
            "enabled": state["enabled"],
            "build": build,
            "cloud_state": state["cloud_state"],
        }
    if set(normalized) != set(targets):
        _fail("TARGET_MISMATCH", "target states do not match the package binding")
    return normalized


def plan_deployment_agent_update(
    package_binding: object,
    target_states: object,
    selected_target_id: object,
) -> dict[str, Any]:
    """Return one fixed-operation plan without staging or contacting a target."""

    binding = _binding(package_binding)
    states = _states(target_states, binding["target_ids"])
    selected = _text(selected_target_id, "selected_target_id")
    if selected not in states:
        _fail("TARGET_MISMATCH", "selected target is not package-bound")
    peer = next(target for target in binding["target_ids"] if target != selected)
    selected_state = states[selected]
    peer_state = states[peer]
    if not selected_state["enabled"]:
        _fail("TARGET_NOT_READY", "selected target Deployment Agent is disabled")
    if not peer_state["enabled"]:
        _fail("PEER_NOT_READY", "peer Deployment Agent is disabled")
    expected = binding["expected_build"]
    for state in (selected_state, peer_state):
        if state["build"] > expected:
            _fail("BUILD_DRIFT", "observed build exceeds the bound expected build")

    execution_required = selected_state["build"] != expected
    plan: dict[str, Any] = {
        "operation": binding["operation"],
        "execution_required": execution_required,
        "selected_target_id": selected,
        "peer_target_id": peer,
        "observed_build": selected_state["build"],
        "peer_observed_build": peer_state["build"],
        "required_build": binding["required_build"],
        "expected_build": expected,
        "package_name": binding["package_name"],
        "source_path": binding["source_path"],
        "checksum_sha256": binding["checksum_sha256"],
        "artifact_size": binding["artifact_size"],
        "binding_sha256": binding["binding_sha256"],
    }
    encoded = json.dumps(
        plan,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    plan["plan_sha256"] = hashlib.sha256(encoded).hexdigest()
    return plan
