# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Authorize one exact Deployment Agent plan without performing it."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import re
from typing import Any

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_reconcile import (
    DeploymentAgentReconcileError,
    validate_deployment_agent_update_plan,
)


MAX_LEASE_SECONDS = 900
CLOCK_SKEW_SECONDS = 30
LEASE_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")
UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
LEASE_KEYS = frozenset(
    {
        "lease_id",
        "issued_at",
        "expires_at",
        "operation",
        "execution_mode",
        "tls_validation_mode",
        "candidate_commit",
        "plan_sha256",
        "binding_sha256",
        "member_targets",
    }
)
TARGET_KEYS = frozenset({"target_id", "member_address"})
ARTIFACT_KEYS = frozenset({"path", "size", "sha256"})


class DeploymentAgentExecutionPreflightError(ValueError):
    """A Deployment Agent update plan is not authorized for execution."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _fail(category: str, message: str) -> None:
    raise DeploymentAgentExecutionPreflightError(category, message)


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or UTC_TIMESTAMP.fullmatch(value) is None:
        _fail("LEASE_INVALID", f"{field} must be an RFC3339 UTC timestamp")
    try:
        form = "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value else "%Y-%m-%dT%H:%M:%SZ"
        return datetime.strptime(value, form).replace(tzinfo=timezone.utc)
    except (OverflowError, ValueError) as error:
        raise DeploymentAgentExecutionPreflightError(
            "LEASE_INVALID", f"{field} must be an RFC3339 UTC timestamp"
        ) from error


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        _fail("LEASE_INVALID", f"{field} must be lowercase SHA-256")
    return value


def _commit(value: object) -> str:
    if not isinstance(value, str) or COMMIT_ID.fullmatch(value) is None:
        _fail("LEASE_INVALID", "candidate_commit must be a full lowercase commit")
    return value


def _address(value: object, field: str) -> str:
    if not isinstance(value, str) or value != value.strip() or "%" in value:
        _fail("TARGET_INVALID", f"{field} must be one unscoped IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise DeploymentAgentExecutionPreflightError(
            "TARGET_INVALID", f"{field} must be one IP address"
        ) from error
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
    ):
        _fail("TARGET_INVALID", f"{field} is not an eligible live target")
    return str(address)


def _targets(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, list) or len(value) != 2:
        _fail("TARGET_INVALID", f"{field} must contain exactly two members")
    result: dict[str, str] = {}
    addresses: set[str] = set()
    for index, target in enumerate(value):
        if not isinstance(target, dict) or set(target) != TARGET_KEYS:
            _fail("TARGET_INVALID", f"{field}[{index}] has an unexpected shape")
        target_id = target["target_id"]
        if (
            not isinstance(target_id, str)
            or not target_id
            or target_id != target_id.strip()
            or not target_id.isprintable()
        ):
            _fail("TARGET_INVALID", f"{field}[{index}].target_id is invalid")
        address = _address(
            target["member_address"], f"{field}[{index}].member_address"
        )
        if target_id in result or address in addresses:
            _fail("TARGET_INVALID", f"{field} members must be unique")
        result[target_id] = address
        addresses.add(address)
    return result


def authorize_deployment_agent_execution(
    lease: object,
    update_plan: object,
    artifact_observation: object,
    member_target_id: object,
    member_address: object,
    member_targets: object,
    runtime_commit: object,
    tls_validation_enabled: object,
    lab_tls_exception_acknowledged: object,
    check_mode: object,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return sanitized authorization for one selected member and exact plan."""

    if check_mode is not False:
        _fail("EXECUTION_MODE_INVALID", "update execution is blocked in check mode")
    if not isinstance(lease, dict) or set(lease) != LEASE_KEYS:
        _fail("LEASE_INVALID", "lease fields do not match the execution contract")
    if not isinstance(lease["lease_id"], str) or LEASE_ID.fullmatch(
        lease["lease_id"]
    ) is None:
        _fail("LEASE_INVALID", "lease_id must be a UUIDv4")
    if lease["operation"] != "deployment_agent_update":
        _fail("OPERATION_INVALID", "lease does not authorize Deployment Agent update")
    if lease["execution_mode"] != "mutating":
        _fail("EXECUTION_MODE_INVALID", "lease execution_mode must be mutating")

    issued_at = _timestamp(lease["issued_at"], "issued_at")
    expires_at = _timestamp(lease["expires_at"], "expires_at")
    if expires_at <= issued_at:
        _fail("LEASE_INVALID", "lease expiry must follow issuance")
    if (expires_at - issued_at).total_seconds() > MAX_LEASE_SECONDS:
        _fail("LEASE_INVALID", "lease duration exceeds 15 minutes")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        _fail("LEASE_INVALID", "executor clock must be timezone-aware")
    current = current.astimezone(timezone.utc)
    if issued_at > current + timedelta(seconds=CLOCK_SKEW_SECONDS):
        _fail("LEASE_INVALID", "lease issuance is in the future")
    if expires_at <= current:
        _fail("LEASE_EXPIRED", "lease has expired")

    candidate_commit = _commit(lease["candidate_commit"])
    if runtime_commit != candidate_commit:
        _fail("COMMIT_MISMATCH", "runtime commit does not match the approved lease")
    try:
        plan = validate_deployment_agent_update_plan(update_plan)
    except DeploymentAgentReconcileError as error:
        raise DeploymentAgentExecutionPreflightError(
            error.category, str(error)
        ) from error
    if not plan["execution_required"]:
        _fail("UPDATE_NOT_REQUIRED", "the selected member is already at exact build")
    if (
        _digest(lease["plan_sha256"], "plan_sha256") != plan["plan_sha256"]
        or _digest(lease["binding_sha256"], "binding_sha256")
        != plan["binding_sha256"]
    ):
        _fail("PLAN_MISMATCH", "lease digests do not match the update plan")

    if (
        not isinstance(artifact_observation, dict)
        or set(artifact_observation) != ARTIFACT_KEYS
        or artifact_observation["path"] != plan["source_path"]
        or artifact_observation["size"] != plan["artifact_size"]
        or artifact_observation["sha256"] != plan["checksum_sha256"]
    ):
        _fail("ARTIFACT_MISMATCH", "artifact observation does not match the plan")

    actual_targets = _targets(member_targets, "member_targets")
    leased_targets = _targets(lease["member_targets"], "lease.member_targets")
    if actual_targets != leased_targets:
        _fail("TARGET_MISMATCH", "runtime members do not match the lease")
    if set(actual_targets) != {
        plan["selected_target_id"],
        plan["peer_target_id"],
    }:
        _fail("TARGET_MISMATCH", "runtime member identities do not match the plan")
    if member_target_id != plan["selected_target_id"]:
        _fail("TARGET_MISMATCH", "only the selected plan member is authorized")
    normalized_address = _address(member_address, "member_address")
    if actual_targets[plan["selected_target_id"]] != normalized_address:
        _fail("TARGET_MISMATCH", "selected member address does not match runtime")

    tls_mode = lease["tls_validation_mode"]
    if tls_mode not in {"strict", "lab_unverified"}:
        _fail("TLS_VALIDATION_INVALID", "lease TLS mode is not supported")
    expected_tls = tls_mode == "strict"
    expected_ack = tls_mode == "lab_unverified"
    if (
        tls_validation_enabled is not expected_tls
        or lab_tls_exception_acknowledged is not expected_ack
    ):
        _fail("TLS_VALIDATION_INVALID", "effective TLS controls do not match lease")

    target_material = json.dumps(
        actual_targets, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return {
        "authorized": True,
        "lease_id": lease["lease_id"].lower(),
        "operation": "deployment_agent_update",
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "candidate_commit": candidate_commit,
        "plan_sha256": plan["plan_sha256"],
        "selected_target_fingerprint": hashlib.sha256(
            plan["selected_target_id"].encode("utf-8")
        ).hexdigest(),
        "target_set_fingerprint": hashlib.sha256(target_material).hexdigest(),
    }
