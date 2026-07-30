# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fail-closed Check Point managed-target resolution."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from dataclasses import dataclass
import ipaddress
from typing import Any, Iterable


class TopologyError(ValueError):
    """A topology result is unsafe or incomplete."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class Domain:
    name: str
    cma_name: str
    cma_ip: str


@dataclass(frozen=True)
class Candidate:
    domain: Domain
    name: str
    object_type: str
    addresses: frozenset[str]
    members: tuple[dict[str, Any], ...]
    policy: str
    version: str


def normalize_ip(value: object) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def normalize_target_ips(values: Iterable[object]) -> list[str]:
    result: list[str] = []
    for value in values:
        normalized = normalize_ip(value)
        if not normalized:
            raise TopologyError("INVALID_INPUT", f"invalid target IP address: {value!r}")
        if normalized not in result:
            result.append(normalized)
    if not result:
        raise TopologyError("INVALID_INPUT", "at least one target IP is required")
    return result


def _management_servers(row: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for key in ("servers", "domain-servers"):
        for server in row.get(key) or []:
            if not isinstance(server, dict):
                continue
            server_type = str(server.get("type") or "").casefold()
            address = normalize_ip(
                server.get("ipv4-address")
                or server.get("ipv6-address")
                or server.get("ip-address")
            )
            name = str(server.get("name") or "").strip()
            identity = (name.casefold(), address)
            if (
                "management server" in server_type
                and "log" not in server_type
                and name
                and address
                and identity not in seen
            ):
                result.append(server)
                seen.add(identity)
    return result


def domain_identity(row: dict[str, Any]) -> Domain:
    name = str(row.get("name") or row.get("domain-name") or "").strip()
    if not name:
        raise TopologyError("DISCOVERY_INCOMPLETE", "domain has no name")
    servers = _management_servers(row)
    active = [server for server in servers if server.get("active") is True]
    unknown = [server for server in servers if "active" not in server]
    if len(active) == 1:
        selected = active[0]
    elif len(servers) == 1 and unknown:
        selected = servers[0]
    else:
        detail = (
            "multiple active management servers"
            if len(active) > 1
            else "no authoritative active non-logging management server"
        )
        raise TopologyError("DISCOVERY_INCOMPLETE", f"domain {name}: {detail}")
    cma_name = str(selected.get("name") or "").strip()
    cma_ip = normalize_ip(
        selected.get("ipv4-address")
        or selected.get("ipv6-address")
        or selected.get("ip-address")
    )
    if not cma_name or not cma_ip:
        raise TopologyError("DISCOVERY_INCOMPLETE", f"domain {name}: incomplete CMA identity")
    return Domain(name=name, cma_name=cma_name, cma_ip=cma_ip)


def _kind(row: dict[str, Any]) -> str:
    return str(row.get("type") or "").casefold().replace("_", "-")


def _is_cluster(row: dict[str, Any]) -> bool:
    value = _kind(row)
    return "cluster" in value and "member" not in value


def _is_member(row: dict[str, Any]) -> bool:
    value = _kind(row)
    return "cluster" in value and "member" in value


ADDRESS_KEYS = (
    "ipv4-address",
    "ipv6-address",
    "ip-address",
    "main-ip",
    "ipv4-addresses",
    "ipv6-addresses",
)


def addresses(row: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    containers = [row]
    interfaces = row.get("interfaces") or []
    if isinstance(interfaces, dict):
        interfaces = interfaces.get("objects") or interfaces.get("interfaces") or []
    containers.extend(value for value in interfaces if isinstance(value, dict))
    for container in containers:
        for key in ADDRESS_KEYS:
            raw = container.get(key)
            values = raw if isinstance(raw, list) else [raw]
            for value in values:
                normalized = normalize_ip(value)
                if normalized:
                    result.add(normalized)
    return result


def _primary(row: dict[str, Any], found: set[str]) -> str:
    for key in ("ipv4-address", "ip-address", "main-ip", "ipv6-address"):
        normalized = normalize_ip(row.get(key))
        if normalized:
            return normalized
    return sorted(found)[0] if found else ""


def _member_names(row: dict[str, Any]) -> set[str]:
    result = {
        value.strip()
        for value in row.get("cluster-member-names") or []
        if isinstance(value, str) and value.strip()
    }
    for key in ("cluster-members", "members"):
        for member in row.get(key) or []:
            if isinstance(member, dict):
                name = str(member.get("name") or member.get("member-name") or "").strip()
                if name:
                    result.add(name)
    return result


def _members(detail: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    result: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    seen_ips: set[str] = set()
    for key in ("cluster-members", "members"):
        for member in detail.get(key) or []:
            if not isinstance(member, dict):
                continue
            found = addresses(member)
            name = str(member.get("name") or member.get("member-name") or "").strip()
            member_ip = _primary(member, found)
            if not name or not member_ip:
                identity = detail.get("name") or detail.get("uid") or "unknown"
                raise TopologyError(
                    "DISCOVERY_INCOMPLETE",
                    f"cluster {identity} has incomplete member data",
                )
            normalized_name = name.casefold()
            if normalized_name in seen_names or member_ip in seen_ips:
                raise TopologyError(
                    "DISCOVERY_INCOMPLETE",
                    f"cluster {detail.get('name') or detail.get('uid')} has duplicate member identity",
                )
            seen_names.add(normalized_name)
            seen_ips.add(member_ip)
            result.append(
                {"hostname": name, "ip": member_ip, "all_ips": sorted(found)}
            )
    return tuple(result)


def _policy(row: dict[str, Any]) -> str:
    value = row.get("policy")
    if not isinstance(value, dict):
        return ""
    return str(value.get("access-policy-name") or "").strip()


def _domain_candidates(
    domain: Domain,
    objects: list[dict[str, Any]],
    details: dict[str, dict[str, Any]],
    targets: set[str],
) -> list[Candidate]:
    clusters = [row for row in objects if _is_cluster(row)]
    top_members = [row for row in objects if _is_member(row)]
    matched_names = {
        str(row.get("name") or "").strip()
        for row in top_members
        if targets & addresses(row)
    }
    relevant = [
        row
        for row in clusters
        if targets & addresses(row) or matched_names & _member_names(row)
    ]
    if matched_names and not relevant:
        relevant = clusters
    result: list[Candidate] = []
    for cluster in relevant:
        uid = str(cluster.get("uid") or "").strip()
        if not uid or not isinstance(details.get(uid), dict):
            raise TopologyError(
                "DISCOVERY_INCOMPLETE",
                f"cluster {cluster.get('name') or uid or 'unknown'} has no detail record",
            )
        detail = details[uid]
        member_rows = _members(detail)
        if not member_rows:
            raise TopologyError(
                "DISCOVERY_INCOMPLETE",
                f"cluster {cluster.get('name') or uid} returned no members",
            )
        if len(member_rows) != 2:
            raise TopologyError(
                "UNSUPPORTED_TOPOLOGY",
                f"cluster {cluster.get('name') or uid} must contain exactly two members",
            )
        found = addresses(cluster)
        for member in member_rows:
            found.update(member["all_ips"])
        name = str(cluster.get("name") or detail.get("name") or "").strip()
        if not name:
            raise TopologyError("DISCOVERY_INCOMPLETE", f"cluster UID {uid} has no name")
        result.append(
            Candidate(
                domain=domain,
                name=name,
                object_type=str(cluster.get("type") or detail.get("type") or ""),
                addresses=frozenset(found),
                members=member_rows,
                policy=_policy(cluster) or _policy(detail),
                version=str(
                    cluster.get("version")
                    or detail.get("version")
                    or cluster.get("os-name")
                    or ""
                ),
            )
        )
    return result


def resolve_targets(
    domain_data: list[dict[str, Any]],
    target_ips: Iterable[object],
    preferred_domain: str = "",
) -> dict[str, Any]:
    normalized_targets = normalize_target_ips(target_ips)
    preferred = str(preferred_domain or "").strip()
    targets = set(normalized_targets)
    candidates: list[Candidate] = []
    covered: set[str] = set()
    domains_seen: set[str] = set()
    preferred_matches = 0

    for item in domain_data:
        if not isinstance(item, dict) or not isinstance(item.get("domain"), dict):
            raise TopologyError("DISCOVERY_INCOMPLETE", "invalid domain result")
        domain_row = item["domain"]
        domain_type = " ".join(
            str(
                domain_row.get("domain-type")
                or domain_row.get("type")
                or ""
            )
            .casefold()
            .replace("-", " ")
            .replace("_", " ")
            .split()
        )
        if "global" in domain_type:
            continue
        if domain_type != "domain":
            raise TopologyError(
                "DISCOVERY_INCOMPLETE",
                f"unsupported domain type for "
                f"{domain_row.get('name') or '<unnamed>'}: "
                f"{domain_type or '<missing>'}",
            )
        domain = domain_identity(domain_row)
        identity = domain.name.casefold()
        if identity in domains_seen:
            raise TopologyError("DISCOVERY_INCOMPLETE", f"duplicate domain: {domain.name}")
        domains_seen.add(identity)
        if preferred.casefold() in {
            domain.name.casefold(),
            domain.cma_name.casefold(),
        }:
            preferred_matches += 1
        objects = item.get("objects")
        details = item.get("cluster_details")
        if not isinstance(objects, list) or not isinstance(details, dict):
            raise TopologyError(
                "DISCOVERY_INCOMPLETE",
                f"domain {domain.name}: missing objects or cluster details",
            )
        current = _domain_candidates(domain, objects, details, targets)
        candidates.extend(current)
        for candidate in current:
            covered.update(targets & candidate.addresses)

    if not domains_seen:
        raise TopologyError("DISCOVERY_INCOMPLETE", "no regular domains returned")
    if preferred and preferred_matches != 1:
        raise TopologyError(
            "INVALID_INPUT",
            f"preferred domain or CMA {preferred_domain!r} was not uniquely discovered",
        )
    all_complete = [candidate for candidate in candidates if targets <= candidate.addresses]
    complete = all_complete
    if preferred:
        wanted = preferred.casefold()
        complete = [
            candidate
            for candidate in complete
            if wanted
            in {candidate.domain.name.casefold(), candidate.domain.cma_name.casefold()}
        ]
        if not complete and all_complete:
            identities = ", ".join(
                f"{candidate.domain.name}/{candidate.name}"
                for candidate in all_complete
            )
            raise TopologyError(
                "INVALID_INPUT",
                f"target IPs resolve outside preferred domain {preferred!r}: {identities}",
            )
    if len(complete) > 1:
        identities = ", ".join(
            f"{candidate.domain.name}/{candidate.name}" for candidate in complete
        )
        raise TopologyError(
            "AMBIGUOUS",
            f"target IPs resolve to multiple managed objects: {identities}",
        )
    if not complete:
        if targets <= covered:
            identities = ", ".join(
                f"{candidate.domain.name}/{candidate.name}"
                for candidate in candidates
                if targets & candidate.addresses
            )
            raise TopologyError(
                "AMBIGUOUS",
                f"target IPs span multiple managed objects: {identities}",
            )
        raise TopologyError(
            "NOT_FOUND",
            f"unresolved target IPs: {sorted(targets - covered)}",
        )

    candidate = complete[0]
    return {
        "input_ips": normalized_targets,
        "matched_ips": sorted(targets & candidate.addresses),
        "domain": candidate.domain.name,
        "cma_name": candidate.domain.cma_name,
        "cma_ip": candidate.domain.cma_ip,
        "cluster_name": candidate.name,
        "cluster_mode": "cluster",
        "policy_package": candidate.policy,
        "members": list(candidate.members),
        "matched_object_type": candidate.object_type,
        "current_version": candidate.version,
    }
