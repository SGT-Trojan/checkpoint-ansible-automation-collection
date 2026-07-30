# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Build isolated Management API session plans from complete domain facts."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import ipaddress
from typing import Any


class DomainPlanError(ValueError):
    """A domain session plan cannot be built safely."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _normalized_type(value: object) -> str:
    return " ".join(
        str(value or "").casefold().replace("-", " ").replace("_", " ").split()
    )


def _domain_type(row: dict[str, Any]) -> str:
    return _normalized_type(row.get("domain-type") or row.get("type"))


def _normalize_ip(value: object) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def _management_servers(row: dict[str, Any]) -> list[dict[str, Any]]:
    servers: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], object] = {}
    domain_name = str(row.get("name") or "<unnamed>").strip()
    for key in ("servers", "domain-servers"):
        raw_servers = row.get(key) or []
        if not isinstance(raw_servers, list):
            raise DomainPlanError(
                "DISCOVERY_INCOMPLETE",
                f"domain {domain_name}: {key} is not a list",
            )
        for server in raw_servers:
            if not isinstance(server, dict):
                raise DomainPlanError(
                    "DISCOVERY_INCOMPLETE",
                    f"domain {domain_name}: management server data "
                    "contains a non-object row",
                )
            if "active" in server and not isinstance(server["active"], bool):
                raise DomainPlanError(
                    "DISCOVERY_INCOMPLETE",
                    f"domain {domain_name}: management server active "
                    "state is not Boolean",
                )
            server_type = _normalized_type(server.get("type"))
            if "management server" not in server_type or "log" in server_type:
                continue
            raw_address = (
                server.get("ipv4-address")
                or server.get("ipv6-address")
                or server.get("ip-address")
                or ""
            )
            identity = (
                str(server.get("name") or "").strip().casefold(),
                _normalize_ip(raw_address) or str(raw_address).strip(),
            )
            active_state = server.get("active", None)
            if identity in seen:
                if seen[identity] != active_state:
                    raise DomainPlanError(
                        "DISCOVERY_INCOMPLETE",
                        f"domain {domain_name}: management server "
                        "active state conflicts across domain facts",
                    )
                continue
            seen[identity] = active_state
            servers.append(server)
    return servers


def _domain_item(row: dict[str, Any]) -> dict[str, Any]:
    name = str(row.get("name") or row.get("domain-name") or "").strip()
    if not name:
        raise DomainPlanError(
            "DISCOVERY_INCOMPLETE",
            "regular domain has no name",
        )

    servers = _management_servers(row)
    active = [server for server in servers if server.get("active") is True]
    unknown = [server for server in servers if "active" not in server]
    if len(active) > 1:
        raise DomainPlanError(
            "AMBIGUOUS",
            f"domain {name}: multiple active non-logging management servers",
        )
    if len(active) == 1:
        selected = active[0]
    elif len(servers) == 1 and len(unknown) == 1:
        selected = unknown[0]
    else:
        raise DomainPlanError(
            "DISCOVERY_INCOMPLETE",
            f"domain {name}: no authoritative active non-logging "
            "management server",
        )

    cma_name = str(selected.get("name") or "").strip()
    raw_address = (
        selected.get("ipv4-address")
        or selected.get("ipv6-address")
        or selected.get("ip-address")
    )
    cma_address = _normalize_ip(raw_address)
    if not cma_name:
        raise DomainPlanError(
            "DISCOVERY_INCOMPLETE",
            f"domain {name}: active management server has no CMA name",
        )
    if not cma_address:
        raise DomainPlanError(
            "DISCOVERY_INCOMPLETE",
            f"domain {name}: active CMA address is not valid IPv4 or IPv6",
        )
    return {
        "name": name,
        "cma_name": cma_name,
        "cma_address": cma_address,
        "domain": row,
    }


def build_domain_plan(
    domain_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return a deterministic plan with one isolated session per regular domain."""

    if not isinstance(domain_records, list):
        raise DomainPlanError(
            "INVALID_INPUT",
            "domain_records must be a list of domain objects",
        )
    records = domain_records

    regular: list[dict[str, Any]] = []
    for index, row in enumerate(records):
        if not isinstance(row, dict):
            raise DomainPlanError(
                "INVALID_INPUT",
                f"domain_records[{index}] is not an object",
            )
        domain_type = _domain_type(row)
        if "global" in domain_type:
            continue
        if domain_type != "domain":
            raise DomainPlanError(
                "DISCOVERY_INCOMPLETE",
                f"domain_records[{index}] has unsupported domain type "
                f"{domain_type or '<missing>'!r}",
            )
        regular.append(row)
    if not regular:
        raise DomainPlanError(
            "DISCOVERY_INCOMPLETE",
            "domain discovery returned no regular domains",
        )

    items = [_domain_item(row) for row in regular]
    names: set[str] = set()
    for item in items:
        normalized_name = item["name"].casefold()
        if normalized_name in names:
            raise DomainPlanError(
                "AMBIGUOUS",
                f"duplicate regular domain name: {item['name']}",
            )
        names.add(normalized_name)

    items.sort(key=lambda item: item["name"].casefold())
    for index, item in enumerate(items, start=1):
        item["session_name"] = f"checkpoint_domain_session_{index:04d}"
    return items
