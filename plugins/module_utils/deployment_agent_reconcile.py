# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reconcile one Deployment Agent update plan from normalized offline state."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import hashlib
import json
import re
from typing import Any


MAX_BUILD = 9999999999
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PLAN_KEYS = frozenset(
    {
        "operation",
        "execution_required",
        "selected_target_id",
        "peer_target_id",
        "observed_build",
        "peer_observed_build",
        "required_build",
        "expected_build",
        "package_name",
        "source_path",
        "checksum_sha256",
        "artifact_size",
        "binding_sha256",
        "plan_sha256",
    }
)
STATE_KEYS = frozenset({"target_id", "enabled", "build", "cloud_state"})
CLOUD_STATES = frozenset({"current", "update_available", "unknown"})


class DeploymentAgentReconcileError(ValueError):
    """Reconciliation evidence is malformed, ambiguous, or unsafe."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _fail(category: str, message: str) -> None:
    raise DeploymentAgentReconcileError(category, message)


def _text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not value.isprintable()
    ):
        _fail("RECONCILIATION_INVALID", f"{label} must be normalized text")
    return value


def _build(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_BUILD
    ):
        _fail("BUILD_INVALID", f"{label} is outside the approved range")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        _fail("PLAN_INVALID", f"{label} is not a normalized SHA-256")
    return value


def validate_deployment_agent_update_plan(value: object) -> dict[str, Any]:
    """Return a verified copy of one exact update plan."""

    if not isinstance(value, dict) or set(value) != PLAN_KEYS:
        _fail("PLAN_INVALID", "update plan has an unexpected shape")
    if value["operation"] != "installer_agent_install":
        _fail("PLAN_INVALID", "update plan operation changed")
    if not isinstance(value["execution_required"], bool):
        _fail("PLAN_INVALID", "execution_required must be boolean")
    selected = _text(value["selected_target_id"], "selected_target_id")
    peer = _text(value["peer_target_id"], "peer_target_id")
    if selected == peer:
        _fail("TARGET_AMBIGUOUS", "selected target and peer must differ")
    observed = _build(value["observed_build"], "observed_build")
    peer_observed = _build(value["peer_observed_build"], "peer_observed_build")
    required = _build(value["required_build"], "required_build")
    expected = _build(value["expected_build"], "expected_build")
    if expected < required:
        _fail("BUILD_INVALID", "expected build is below the required build")
    if observed > expected or peer_observed > expected:
        _fail("BUILD_DRIFT", "planned observed build exceeds expected build")
    if value["execution_required"] != (observed != expected):
        _fail("PLAN_INVALID", "execution requirement contradicts observed build")
    for key in ("package_name", "source_path"):
        _text(value[key], key)
    _digest(value["checksum_sha256"], "checksum_sha256")
    _digest(value["binding_sha256"], "binding_sha256")
    if (
        isinstance(value["artifact_size"], bool)
        or not isinstance(value["artifact_size"], int)
        or value["artifact_size"] <= 0
    ):
        _fail("PLAN_INVALID", "artifact_size must be a positive integer")
    plan_digest = _digest(value["plan_sha256"], "plan_sha256")
    canonical = {key: item for key, item in value.items() if key != "plan_sha256"}
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    if hashlib.sha256(encoded).hexdigest() != plan_digest:
        _fail("PLAN_MISMATCH", "update plan digest does not match")
    return dict(value)


def _states(value: object, targets: set[str]) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 2:
        _fail("TARGET_INVALID", "exactly two reconciled target states are required")
    normalized: dict[str, dict[str, Any]] = {}
    for state in value:
        if not isinstance(state, dict) or set(state) != STATE_KEYS:
            _fail("TARGET_INVALID", "reconciled target state has an unexpected shape")
        target = _text(state["target_id"], "target_id")
        if target in normalized:
            _fail("TARGET_AMBIGUOUS", "reconciled target state is duplicated")
        if not isinstance(state["enabled"], bool):
            _fail("TARGET_INVALID", "target enabled state must be boolean")
        build = _build(state["build"], "reconciled build")
        if state["cloud_state"] not in CLOUD_STATES:
            _fail("TARGET_INVALID", "target cloud state is not normalized")
        normalized[target] = {
            "enabled": state["enabled"],
            "build": build,
        }
    if set(normalized) != targets:
        _fail("TARGET_MISMATCH", "reconciled targets do not match the update plan")
    return normalized


def reconcile_deployment_agent_update(
    update_plan: object,
    target_states: object,
) -> dict[str, Any]:
    """Return exact offline reconciliation without staging or transport."""

    plan = validate_deployment_agent_update_plan(update_plan)
    selected = plan["selected_target_id"]
    peer = plan["peer_target_id"]
    states = _states(target_states, {selected, peer})
    if not states[selected]["enabled"]:
        _fail("TARGET_NOT_READY", "selected target Deployment Agent is disabled")
    if not states[peer]["enabled"]:
        _fail("PEER_NOT_READY", "peer Deployment Agent is disabled")
    expected = plan["expected_build"]
    if states[selected]["build"] != expected:
        _fail("EXPECTED_BUILD_MISMATCH", "selected target is not at expected build")
    if states[peer]["build"] != plan["peer_observed_build"]:
        _fail("PEER_DRIFT", "peer build changed during selected-target update")

    peer_pending = states[peer]["build"] != expected
    result: dict[str, Any] = {
        "status": "next_target_pending" if peer_pending else "complete",
        "completed_target_id": selected,
        "next_target_id": peer if peer_pending else None,
        "selected_build": states[selected]["build"],
        "peer_build": states[peer]["build"],
        "expected_build": expected,
        "source_plan_sha256": plan["plan_sha256"],
    }
    encoded = json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    result["reconciliation_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result
