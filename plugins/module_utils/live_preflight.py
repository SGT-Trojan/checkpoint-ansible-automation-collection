# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fail-closed authorization for constrained live read-only execution."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import re
from typing import Any


class LivePreflightError(ValueError):
    """A live execution request is not authorized."""

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
    "management_target",
    "member_targets",
}


def _fail(category: str, message: str) -> None:
    raise LivePreflightError(category, message)


def _utc_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
        _fail("LEASE_INVALID", f"{field} must be an RFC3339 UTC timestamp")
    try:
        timestamp_format = (
            "%Y-%m-%dT%H:%M:%S.%fZ"
            if "." in value
            else "%Y-%m-%dT%H:%M:%SZ"
        )
        parsed = datetime.strptime(value, timestamp_format).replace(
            tzinfo=timezone.utc
        )
    except (OverflowError, ValueError) as error:
        raise LivePreflightError(
            "LEASE_INVALID",
            f"{field} must be an RFC3339 UTC timestamp",
        ) from error
    if parsed.utcoffset() != timedelta(0):
        _fail("LEASE_INVALID", f"{field} must use UTC")
    return parsed


def _target(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail("TARGET_INVALID", f"{field} must be one IP address")
    if "%" in value:
        _fail("TARGET_INVALID", f"{field} must not contain a scope identifier")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise LivePreflightError(
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


def _targets(
    management_target: object,
    member_targets: object,
) -> tuple[str, tuple[str, str]]:
    management = _target(management_target, "management_target")
    if not isinstance(member_targets, list) or len(member_targets) != 2:
        _fail("TARGET_INVALID", "member_targets must contain exactly two addresses")
    members = tuple(
        _target(value, f"member_targets[{index}]")
        for index, value in enumerate(member_targets)
    )
    if len(set(members)) != 2:
        _fail("TARGET_INVALID", "member target addresses must be unique")
    if management in members:
        _fail("TARGET_INVALID", "management and member targets must be distinct")
    return management, members  # type: ignore[return-value]


def authorize_live_readonly(
    lease: object,
    management_target: object,
    member_targets: object,
    credential_presence: object,
    check_mode: object,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Authorize one exact, short-lived managed-discovery execution."""

    if check_mode is not True:
        _fail("MUTATION_BLOCKED", "live executor requires Ansible check mode")
    if not isinstance(lease, dict) or set(lease) != LEASE_KEYS:
        _fail("LEASE_INVALID", "lease fields do not match the live contract")
    lease_id = lease["lease_id"]
    if not isinstance(lease_id, str) or not LEASE_ID.fullmatch(lease_id):
        _fail("LEASE_INVALID", "lease_id must be a UUID")
    if lease["operation"] != "managed_discovery":
        _fail("MUTATION_BLOCKED", "lease operation is not managed_discovery")
    if lease["execution_mode"] != "read_only":
        _fail("MUTATION_BLOCKED", "lease execution_mode is not read_only")

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

    actual_management, actual_members = _targets(
        management_target,
        member_targets,
    )
    leased_management, leased_members = _targets(
        lease["management_target"],
        lease["member_targets"],
    )
    if (
        actual_management != leased_management
        or set(actual_members) != set(leased_members)
    ):
        _fail("TARGET_MISMATCH", "runtime targets do not match the lease")

    required_credentials = {"management_username", "management_secret"}
    if (
        not isinstance(credential_presence, dict)
        or set(credential_presence) != required_credentials
        or any(value is not True for value in credential_presence.values())
    ):
        _fail(
            "CREDENTIALS_INVALID",
            "required management credential references are not populated",
        )

    target_material = "\n".join(
        [actual_management] + sorted(actual_members)
    ).encode("ascii")
    return {
        "authorized": True,
        "lease_id": lease_id.lower(),
        "operation": "managed_discovery",
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "target_count": 3,
        "target_fingerprint": hashlib.sha256(target_material).hexdigest(),
    }
