# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fail-closed readiness decisions for two-member Check Point clusters."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from typing import Any

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.cluster_observations import (
    ObservationError,
    interface_signature,
    normalize_ip,
)


class ReadinessError(ValueError):
    """A readiness request is invalid or the cluster is not ready."""

    def __init__(self, category: str, message: str, result: dict[str, Any]):
        super().__init__(message)
        self.category = category
        self.result = result


def _identity(member: dict[str, Any]) -> tuple[str, str]:
    name = str(member.get("name") or "").strip()
    address = str(member.get("address") or "").strip()
    if not name or not address:
        raise ReadinessError(
            "INVALID_INPUT",
            "every member requires a name and address",
            {"ready": False, "reasons": ["member identity is incomplete"]},
        )
    try:
        normalized_address = normalize_ip(address)
    except ObservationError as error:
        raise ReadinessError(
            "INVALID_INPUT",
            str(error),
            {"ready": False, "reasons": ["member address is invalid"]},
        ) from error
    return name, normalized_address


def _selector_matches(member: dict[str, Any], selector: str) -> bool:
    wanted = selector.strip().casefold()
    name, address = _identity(member)
    try:
        wanted = normalize_ip(wanted).casefold()
    except ObservationError:
        pass
    return wanted in {name.casefold(), address.casefold()}


def _baseline_by_identity(
    baseline_members: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for member in baseline_members:
        if not isinstance(member, dict):
            raise ReadinessError(
                "INVALID_INPUT",
                "baseline members must be dictionaries",
                {"ready": False, "reasons": ["baseline member is malformed"]},
            )
        name, address = _identity(member)
        key = (name.casefold(), address.casefold())
        if key in result:
            raise ReadinessError(
                "INVALID_INPUT",
                "baseline contains duplicate member identity",
                {"ready": False, "reasons": ["baseline identity is ambiguous"]},
            )
        result[key] = member
    return result


def decide_readiness(
    members: list[dict[str, Any]],
    *,
    icap_mode: str = "optional",
    baseline_members: list[dict[str, Any]] | None = None,
    expected_active: str = "",
    expected_standby: str = "",
) -> dict[str, Any]:
    """Evaluate a complete two-member readiness snapshot."""

    if icap_mode not in {"required", "optional", "disabled"}:
        raise ReadinessError(
            "INVALID_INPUT",
            f"unsupported ICAP mode: {icap_mode}",
            {"ready": False, "reasons": ["ICAP mode is invalid"]},
        )
    if len(members) != 2 or not all(isinstance(member, dict) for member in members):
        raise ReadinessError(
            "UNSUPPORTED_TOPOLOGY",
            "readiness requires exactly two member observations",
            {"ready": False, "reasons": ["exactly two members are required"]},
        )

    identities: set[tuple[str, str]] = set()
    names: set[str] = set()
    addresses: set[str] = set()
    reasons: list[str] = []
    active: list[dict[str, Any]] = []
    standby: list[dict[str, Any]] = []

    for member in members:
        name, address = _identity(member)
        key = (name.casefold(), address.casefold())
        if key in identities or name.casefold() in names or address.casefold() in addresses:
            raise ReadinessError(
                "INVALID_INPUT",
                "member identities must be unique by name and address",
                {"ready": False, "reasons": ["member identity is ambiguous"]},
            )
        identities.add(key)
        names.add(name.casefold())
        addresses.add(address.casefold())

        state = str(member.get("cluster_state") or "").strip().upper()
        if state == "ACTIVE":
            active.append(member)
        elif state == "STANDBY":
            standby.append(member)
        else:
            reasons.append(f"{name}: unsupported ClusterXL state {state or '<missing>'}")
        if member.get("pnotes_ok") is not True:
            reasons.append(f"{name}: active PNOTEs are not explicitly clear")
        if member.get("interfaces_ok") is not True:
            reasons.append(f"{name}: monitored cluster interfaces are not healthy")
        if icap_mode == "required" and member.get("icap_ok") is not True:
            reasons.append(f"{name}: required ICAP health is not explicitly true")

    if len(active) != 1:
        reasons.append(f"expected exactly one ACTIVE member, observed {len(active)}")
    if len(standby) != 1:
        reasons.append(f"expected exactly one STANDBY member, observed {len(standby)}")

    if expected_active:
        matches = [member for member in active if _selector_matches(member, expected_active)]
        if len(matches) != 1:
            reasons.append(f"expected ACTIVE member {expected_active!r} was not observed")
    if expected_standby:
        matches = [
            member for member in standby if _selector_matches(member, expected_standby)
        ]
        if len(matches) != 1:
            reasons.append(
                f"expected STANDBY member {expected_standby!r} was not observed"
            )

    if baseline_members is not None:
        if len(baseline_members) != 2:
            raise ReadinessError(
                "INVALID_INPUT",
                "interface baseline must contain exactly two members",
                {"ready": False, "reasons": ["interface baseline is incomplete"]},
            )
        baseline = _baseline_by_identity(baseline_members)
        if set(baseline) != identities:
            reasons.append("current member identities do not match the baseline")
        else:
            for member in members:
                name, address = _identity(member)
                key = (name.casefold(), address.casefold())
                try:
                    current_signature = interface_signature(member)
                    baseline_signature = interface_signature(baseline[key])
                except ObservationError as error:
                    raise ReadinessError(
                        error.category,
                        str(error),
                        {"ready": False, "reasons": [str(error)]},
                    ) from error
                if current_signature != baseline_signature:
                    reasons.append(
                        f"{name}: cluster interface identity differs from baseline"
                    )

    result = {
        "ready": not reasons,
        "reasons": reasons,
        "active_member": (
            {"name": _identity(active[0])[0], "address": _identity(active[0])[1]}
            if len(active) == 1
            else {}
        ),
        "standby_member": (
            {
                "name": _identity(standby[0])[0],
                "address": _identity(standby[0])[1],
            }
            if len(standby) == 1
            else {}
        ),
        "icap_mode": icap_mode,
        "baseline_checked": baseline_members is not None,
    }
    return result
