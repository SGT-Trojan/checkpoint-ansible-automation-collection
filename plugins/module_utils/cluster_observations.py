# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Parse read-only Check Point member observations."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import ipaddress
import re
from typing import Any


class ObservationError(ValueError):
    """A member observation is malformed or incomplete."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


_ANSI_CSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_ANSI_OSC = re.compile(r"\x1b\].*?\x07")
_STATE_ROW = re.compile(
    r"^\s*\d+\s*(?P<local>\(local\))?\s+\S+\s+\S+\s+"
    r"(?P<state>\S+)\s+(?P<name>\S+)\s*$"
)
_INTERFACE_ROW = re.compile(
    r"^(?P<name>\S+)(?P<markers>(?:\s+\([^)]*\))*)\s+"
    r"(?P<status>.+?)\s*$"
)
_VIRTUAL_ROW = re.compile(
    r"^(?P<name>\S+)\s+"
    r"(?P<address>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+)\s*$"
)
_CLISH_PROMPT = re.compile(r"^[A-Za-z0-9_.:-]+>\s*$")
_EXPERT_PROMPT = re.compile(r"^\[Expert@[^]]+\]#\s*$", re.IGNORECASE)
_CAPTURE_END_WRAPPER = re.compile(r"^=+\s+END\s+COMMAND\b.*=+$")
_SS_LISTENER = re.compile(
    r"^\s*LISTEN\s+\d+\s+\d+\s+\S*(?:^|[\s:.\]])1344(?:\s|$)",
    re.IGNORECASE,
)
_NETSTAT_LISTENER = re.compile(
    r"^\s*tcp6?\s+\d+\s+\d+\s+\S*(?:^|[\s:.\]])1344(?:\s|$)"
    r".*\bLISTEN\b",
    re.IGNORECASE,
)
_PROCESS_EXECUTABLE = re.compile(r"^\s*\d+\s+(?P<executable>\S+)(?:\s|$)")


def strip_terminal_control(value: object) -> str:
    """Remove terminal control sequences without otherwise rewriting output."""

    text = str(value or "")
    text = _ANSI_CSI.sub("", text)
    text = _ANSI_OSC.sub("", text)
    return text.replace("\r", "").replace("\b", "")


def normalize_ip(value: object) -> str:
    """Return one normalized IP address or reject malformed identity."""

    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError as error:
        raise ObservationError(
            "OBSERVATION_INVALID",
            f"invalid IP address: {value!r}",
        ) from error


def parse_cluster_state(output: object) -> dict[str, Any]:
    """Parse one member's ``cphaprob state`` output."""

    text = strip_terminal_control(output)
    rows: list[dict[str, Any]] = []
    local_rows: list[dict[str, Any]] = []
    names: set[str] = set()
    for line in text.splitlines():
        match = _STATE_ROW.match(line)
        if not match:
            continue
        name = match.group("name").strip()
        normalized_name = name.casefold()
        if normalized_name in names:
            raise ObservationError(
                "OBSERVATION_INVALID",
                f"duplicate ClusterXL member row: {name}",
            )
        names.add(normalized_name)
        row = {
            "name": name,
            "state": match.group("state").strip().upper(),
            "local": bool(match.group("local")),
        }
        rows.append(row)
        if row["local"]:
            local_rows.append(row)

    if len(local_rows) != 1:
        raise ObservationError(
            "OBSERVATION_INCOMPLETE",
            "cphaprob state must contain exactly one local member row",
        )
    if len(rows) != 2:
        raise ObservationError(
            "UNSUPPORTED_TOPOLOGY",
            "cphaprob state must contain exactly two unique member rows",
        )

    pnote_lines = re.findall(
        r"(?im)^\s*Active PNOTEs:\s*(.*?)\s*$",
        text,
    )
    return {
        "local_name": local_rows[0]["name"],
        "local_state": local_rows[0]["state"],
        "members": rows,
        "pnotes_ok": (
            len(pnote_lines) == 1
            and pnote_lines[0].strip().casefold() == "none"
        ),
    }


def _marker_values(value: str) -> list[str]:
    return [
        match.group(1).strip().upper()
        for match in re.finditer(r"\(([^)]*)\)", value)
    ]


def parse_cluster_interfaces(output: object) -> dict[str, Any]:
    """Parse one member's ``cphaprob -a if`` output."""

    text = strip_terminal_control(output)
    required_match = re.search(r"Required interfaces:\s*(\d+)", text)
    secured_match = re.search(r"Required secured interfaces:\s*(\d+)", text)
    virtual_match = re.search(
        r"(?m)^Virtual cluster interfaces:\s*(\d+)\s*$",
        text,
    )
    if not required_match or not secured_match or not virtual_match:
        raise ObservationError(
            "OBSERVATION_INCOMPLETE",
            "cluster interface output is missing declared interface counts",
        )

    interfaces: list[dict[str, Any]] = []
    virtual_interfaces: list[dict[str, str]] = []
    names: set[str] = set()
    virtual_identities: set[tuple[str, str]] = set()
    table = ""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Interface Name:"):
            table = "interfaces"
            continue
        if line.startswith("S - sync"):
            table = ""
            continue
        if line.startswith("Virtual cluster interfaces:"):
            table = "virtual"
            continue
        if _EXPERT_PROMPT.match(line) or line.startswith("cphaprob "):
            continue

        if table == "interfaces":
            match = _INTERFACE_ROW.match(line)
            if not match:
                raise ObservationError(
                    "OBSERVATION_INVALID",
                    f"unrecognized cluster interface row: {line}",
                )
            name = match.group("name")
            normalized_name = name.casefold()
            if normalized_name in names:
                raise ObservationError(
                    "OBSERVATION_INVALID",
                    f"duplicate cluster interface row: {name}",
                )
            names.add(normalized_name)
            markers = _marker_values(match.group("markers"))
            status = match.group("status").strip()
            monitored = status.casefold() != "non-monitored"
            interfaces.append(
                {
                    "name": name,
                    "markers": markers,
                    "sync": any(
                        marker == "S"
                        or marker.startswith("S-")
                        or marker.endswith("-S")
                        for marker in markers
                    ),
                    "status": status,
                    "monitored": monitored,
                    "up": monitored and status.upper() == "UP",
                }
            )
            continue

        if table == "done":
            if _CLISH_PROMPT.match(line) or _CAPTURE_END_WRAPPER.match(line):
                continue
            raise ObservationError(
                "OBSERVATION_INVALID",
                f"unrecognized trailing cluster interface output: {line}",
            )

        if table == "virtual":
            match = _VIRTUAL_ROW.match(line)
            if not match:
                if (
                    len(virtual_interfaces) == int(virtual_match.group(1))
                    and (
                        _CLISH_PROMPT.match(line)
                        or _CAPTURE_END_WRAPPER.match(line)
                    )
                ):
                    table = "done"
                    continue
                raise ObservationError(
                    "OBSERVATION_INVALID",
                    f"unrecognized virtual cluster interface row: {line}",
                )
            address = normalize_ip(match.group("address"))
            identity = (match.group("name").casefold(), address)
            if identity in virtual_identities:
                raise ObservationError(
                    "OBSERVATION_INVALID",
                    "duplicate virtual cluster interface row",
                )
            virtual_identities.add(identity)
            virtual_interfaces.append(
                {
                    "name": match.group("name"),
                    "ip": address,
                }
            )

    declared_virtual = int(virtual_match.group(1))
    if len(virtual_interfaces) != declared_virtual:
        raise ObservationError(
            "OBSERVATION_INCOMPLETE",
            "virtual cluster interface count does not match the declared count",
        )
    required = int(required_match.group(1))
    required_secured = int(secured_match.group(1))
    monitored = [row for row in interfaces if row["monitored"]]
    secured = [row for row in monitored if row["sync"]]
    return {
        "declared_virtual_interfaces": declared_virtual,
        "required_interfaces": required,
        "required_secured_interfaces": required_secured,
        "interfaces": interfaces,
        "virtual_interfaces": virtual_interfaces,
        "ok": (
            len(monitored) == required
            and all(row["up"] for row in monitored)
            and len(secured) == required_secured
        ),
    }


def parse_icap_status(
    cpwd_output: object,
    listener_output: object,
    process_output: object,
) -> dict[str, bool]:
    """Parse explicit ICAP watchdog, listener, and process evidence."""

    cpwd_text = strip_terminal_control(cpwd_output)
    listener_text = strip_terminal_control(listener_output)
    process_text = strip_terminal_control(process_output)
    cpwd_rows = [
        line.strip()
        for line in cpwd_text.splitlines()
        if re.search(r"\bCICAP\b", line, re.IGNORECASE)
    ]
    watchdog_ok = (
        len(cpwd_rows) == 1
        and re.search(r"^\s*CICAP\s+\d+\s+E\b", cpwd_rows[0], re.IGNORECASE)
        is not None
    )
    listener_ok = any(
        _SS_LISTENER.search(line) or _NETSTAT_LISTENER.search(line)
        for line in listener_text.splitlines()
    )
    process_ok = False
    for line in process_text.splitlines():
        match = _PROCESS_EXECUTABLE.match(line)
        if not match:
            continue
        executable = match.group("executable").rstrip("/")
        if executable.rsplit("/", 1)[-1].casefold() == "c-icap":
            process_ok = True
            break
    return {
        "watchdog_ok": watchdog_ok,
        "listener_ok": listener_ok,
        "process_ok": process_ok,
        "ok": watchdog_ok and listener_ok and process_ok,
    }


def interface_signature(observation: dict[str, Any]) -> dict[str, Any]:
    """Return the stable interface identity used for baseline comparison."""

    interfaces = observation.get("interfaces")
    virtual_interfaces = observation.get("virtual_interfaces")
    if not isinstance(interfaces, list) or not isinstance(virtual_interfaces, list):
        raise ObservationError(
            "OBSERVATION_INCOMPLETE",
            "interface observation is missing interface inventories",
        )
    all_interfaces = [
        {
            "name": str(row.get("name") or ""),
            "markers": sorted(str(value) for value in row.get("markers") or []),
            "sync": bool(row.get("sync")),
            "monitored": row.get("monitored") is True,
        }
        for row in interfaces
        if isinstance(row, dict)
    ]
    virtual = [
        {
            "name": str(row.get("name") or ""),
            "ip": str(row.get("ip") or ""),
        }
        for row in virtual_interfaces
        if isinstance(row, dict)
    ]
    return {
        "declared_virtual_interfaces": observation.get(
            "declared_virtual_interfaces"
        ),
        "required_interfaces": observation.get("required_interfaces"),
        "required_secured_interfaces": observation.get(
            "required_secured_interfaces"
        ),
        "interfaces": sorted(
            all_interfaces,
            key=lambda row: row["name"].casefold(),
        ),
        "virtual_cluster_interfaces": sorted(
            virtual,
            key=lambda row: (row["name"].casefold(), row["ip"]),
        ),
    }
