# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fail-closed authorization for live read-only Deployment Agent observation."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import os
import re
from typing import Any


class DeploymentAgentLivePreflightError(ValueError):
    """A live Deployment Agent request is not authorized."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


MAX_LEASE_SECONDS = 900
CLOCK_SKEW_SECONDS = 30
LEASE_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?Z$"
)
LEASE_KEYS = {
    "lease_id",
    "issued_at",
    "expires_at",
    "operation",
    "execution_mode",
    "tls_validation_mode",
    "member_targets",
}
CONTROLLER_PROXY_INVENTORY = "/etc/ansible/hosts"


def _fail(category: str, message: str) -> None:
    raise DeploymentAgentLivePreflightError(category, message)


def _utc_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
        _fail("LEASE_INVALID", f"{field} must be an RFC3339 UTC timestamp")
    try:
        timestamp_format = (
            "%Y-%m-%dT%H:%M:%S.%fZ"
            if "." in value
            else "%Y-%m-%dT%H:%M:%SZ"
        )
        return datetime.strptime(value, timestamp_format).replace(
            tzinfo=timezone.utc
        )
    except (OverflowError, ValueError) as error:
        raise DeploymentAgentLivePreflightError(
            "LEASE_INVALID",
            f"{field} must be an RFC3339 UTC timestamp",
        ) from error


def _target(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "%" in value:
        _fail("TARGET_INVALID", f"{field} must be one unscoped IP address")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise DeploymentAgentLivePreflightError(
            "TARGET_INVALID",
            f"{field} must be one IP address",
        ) from error
    if isinstance(address, ipaddress.IPv6Address):
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None:
            address = mapped
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
    ):
        _fail("TARGET_INVALID", f"{field} is not an eligible live target")
    return str(address)


def _targets(values: object, field: str) -> tuple[str, str]:
    if not isinstance(values, list) or len(values) != 2:
        _fail("TARGET_INVALID", f"{field} must contain exactly two addresses")
    targets = tuple(
        _target(value, f"{field}[{index}]")
        for index, value in enumerate(values)
    )
    if len(set(targets)) != 2:
        _fail("TARGET_INVALID", f"{field} addresses must be unique")
    return targets  # type: ignore[return-value]


def require_direct_gaia_controller(
    path: str = CONTROLLER_PROXY_INVENTORY,
) -> None:
    """Reject the vendor plugin source that can silently enable proxy mode."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise DeploymentAgentLivePreflightError(
            "TARGET_PROXY_UNSUPPORTED",
            "controller proxy inventory state could not be verified",
        ) from error
    _fail(
        "TARGET_PROXY_UNSUPPORTED",
        "direct Gaia execution requires /etc/ansible/hosts to be absent",
    )


def authorize_deployment_agent_readonly(
    lease: object,
    member_target: object,
    member_targets: object,
    credential_presence: object,
    tls_validation_enabled: object,
    lab_tls_exception_acknowledged: object,
    check_mode: object,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Authorize one exact, short-lived Deployment Agent observation."""

    if check_mode is not True:
        _fail("MUTATION_BLOCKED", "live executor requires Ansible check mode")
    if not isinstance(lease, dict) or set(lease) != LEASE_KEYS:
        _fail(
            "LEASE_INVALID",
            "lease fields do not match the Deployment Agent contract",
        )
    lease_id = lease["lease_id"]
    if not isinstance(lease_id, str) or not LEASE_ID.fullmatch(lease_id):
        _fail("LEASE_INVALID", "lease_id must be a UUIDv4")
    if lease["operation"] != "deployment_agent_observation":
        _fail(
            "MUTATION_BLOCKED",
            "lease operation is not deployment_agent_observation",
        )
    if lease["execution_mode"] != "read_only":
        _fail("MUTATION_BLOCKED", "lease execution_mode is not read_only")

    tls_validation_mode = lease["tls_validation_mode"]
    if tls_validation_mode not in {"strict", "lab_unverified"}:
        _fail(
            "TLS_VALIDATION_INVALID",
            "lease tls_validation_mode is not supported",
        )
    if (
        tls_validation_enabled is not True
        and tls_validation_enabled is not False
    ):
        _fail(
            "TLS_VALIDATION_INVALID",
            "TLS validation state must be a literal boolean",
        )
    if (
        lab_tls_exception_acknowledged is not True
        and lab_tls_exception_acknowledged is not False
    ):
        _fail(
            "TLS_VALIDATION_INVALID",
            "lab TLS exception acknowledgment must be a literal boolean",
        )
    if tls_validation_mode == "strict":
        if (
            tls_validation_enabled is not True
            or lab_tls_exception_acknowledged is not False
        ):
            _fail(
                "TLS_VALIDATION_INVALID",
                "strict mode requires TLS validation and no lab acknowledgment",
            )
    elif (
        tls_validation_enabled is not False
        or lab_tls_exception_acknowledged is not True
    ):
        _fail(
            "TLS_VALIDATION_INVALID",
            "lab_unverified mode requires disabled validation and explicit acknowledgment",
        )

    issued_at = _utc_timestamp(lease["issued_at"], "issued_at")
    expires_at = _utc_timestamp(lease["expires_at"], "expires_at")
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

    actual_targets = _targets(member_targets, "member_targets")
    leased_targets = _targets(lease["member_targets"], "lease.member_targets")
    if set(actual_targets) != set(leased_targets):
        _fail("TARGET_MISMATCH", "runtime targets do not match the lease")
    actual_member = _target(member_target, "member_target")
    if actual_member not in actual_targets:
        _fail("TARGET_MISMATCH", "current inventory member is outside the target set")

    required_credentials = {"gaia_username", "gaia_secret"}
    if (
        not isinstance(credential_presence, dict)
        or set(credential_presence) != required_credentials
        or any(value is not True for value in credential_presence.values())
    ):
        _fail(
            "CREDENTIALS_INVALID",
            "required Gaia credential references are not populated",
        )

    target_material = "\n".join(sorted(actual_targets)).encode("ascii")
    return {
        "authorized": True,
        "lease_id": lease_id.lower(),
        "operation": "deployment_agent_observation",
        "tls_validation_mode": tls_validation_mode,
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "target_count": 2,
        "target_fingerprint": hashlib.sha256(target_material).hexdigest(),
    }
