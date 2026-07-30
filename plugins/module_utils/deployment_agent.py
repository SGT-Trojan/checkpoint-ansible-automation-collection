# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Normalize and evaluate Check Point Deployment Agent status."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import re
from typing import Any


class DeploymentAgentError(ValueError):
    """Deployment Agent evidence or requested policy is invalid."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


MAX_STATUS_BYTES = 32768
MAX_STATUS_LINES = 256
MAX_LINE_LENGTH = 1024
MAX_BUILD = 9999999999
AGENT_LINE = re.compile(r"^\s*Agent:\s*(Enabled|Disabled)\s*$")
AGENT_FIELD = re.compile(r"^\s*Agent\s*:")
BUILD_LINE = re.compile(
    r"^\s*Build number:\s*([0-9]{1,10})"
    r"(?:\s+\(([^()\r\n]{1,160})\))?\s*$"
)
BUILD_FIELD = re.compile(r"^\s*Build number\s*:")


def _fail(category: str, message: str) -> None:
    raise DeploymentAgentError(category, message)


def _bounded_lines(output: object) -> list[str]:
    if not isinstance(output, str):
        _fail("STATUS_INVALID", "Deployment Agent status must be text")
    try:
        encoded = output.encode("utf-8")
    except UnicodeEncodeError as error:
        raise DeploymentAgentError(
            "STATUS_CONTROL",
            "Deployment Agent status is not valid UTF-8 text",
        ) from error
    if len(encoded) > MAX_STATUS_BYTES:
        _fail("STATUS_TOO_LARGE", "Deployment Agent status exceeds the byte limit")
    if any(
        (
            ord(character) < 32
            and character not in {"\t", "\r", "\n"}
        )
        or 0x7F <= ord(character) <= 0x9F
        or character in {"\u2028", "\u2029"}
        for character in output
    ):
        _fail("STATUS_CONTROL", "Deployment Agent status contains control text")
    lines = output.replace("\r\n", "\n").splitlines()
    if len(lines) > MAX_STATUS_LINES:
        _fail("STATUS_TOO_LARGE", "Deployment Agent status exceeds the line limit")
    for line in lines:
        if len(line) > MAX_LINE_LENGTH:
            _fail("STATUS_TOO_LARGE", "Deployment Agent status line exceeds the limit")
        if any(ord(character) < 32 and character != "\t" for character in line):
            _fail("STATUS_CONTROL", "Deployment Agent status contains control text")
    return lines


def _cloud_state(note: str | None) -> str:
    if note is None:
        return "unknown"
    normalized = " ".join(note.casefold().split())
    if normalized == "agent build is up to date":
        return "current"
    if "newer build is available" in normalized:
        return "update_available"
    return "unknown"


def parse_status(output: object) -> dict[str, Any]:
    """Return bounded, non-secret state from ``show installer status all``."""

    agent_values: list[str] = []
    build_values: list[tuple[int, str]] = []
    for line in _bounded_lines(output):
        agent = AGENT_LINE.fullmatch(line)
        if agent is not None:
            agent_values.append(agent.group(1))
            continue
        if AGENT_FIELD.match(line):
            _fail("STATUS_FORMAT", "Agent field is malformed")
        build = BUILD_LINE.fullmatch(line)
        if build is not None:
            number = int(build.group(1), 10)
            if number < 1:
                _fail("STATUS_FORMAT", "Deployment Agent build must be positive")
            build_values.append((number, _cloud_state(build.group(2))))
            continue
        if BUILD_FIELD.match(line):
            _fail("STATUS_FORMAT", "Build number field is malformed")
    if len(agent_values) != 1:
        _fail("STATUS_AMBIGUOUS", "Deployment Agent status must contain one Agent field")
    if len(build_values) != 1:
        _fail(
            "STATUS_AMBIGUOUS",
            "Deployment Agent status must contain one Build number field",
        )
    return {
        "enabled": agent_values[0] == "Enabled",
        "build": build_values[0][0],
        "cloud_state": build_values[0][1],
    }


def decide(
    observation: object,
    required_build: object,
    expected_build: object | None = None,
) -> dict[str, Any]:
    """Compare normalized state with the required and optional exact build."""

    if (
        not isinstance(observation, dict)
        or set(observation) != {"enabled", "build", "cloud_state"}
        or not isinstance(observation["enabled"], bool)
        or isinstance(observation["build"], bool)
        or not isinstance(observation["build"], int)
        or not 1 <= observation["build"] <= MAX_BUILD
        or observation["cloud_state"] not in {
            "current",
            "update_available",
            "unknown",
        }
    ):
        _fail("DECISION_INVALID", "Deployment Agent observation is not normalized")
    if (
        isinstance(required_build, bool)
        or not isinstance(required_build, int)
        or not 1 <= required_build <= MAX_BUILD
    ):
        _fail("DECISION_INVALID", "required_build is outside the approved range")
    if expected_build is not None and (
        isinstance(expected_build, bool)
        or not isinstance(expected_build, int)
        or expected_build > MAX_BUILD
        or expected_build < required_build
    ):
        _fail(
            "DECISION_INVALID",
            "expected_build is outside the approved range",
        )

    reasons: list[str] = []
    if not observation["enabled"]:
        reasons.append("Deployment Agent is disabled")
    if observation["build"] < required_build:
        reasons.append("Deployment Agent build is below the required minimum")
    if expected_build is not None and observation["build"] != expected_build:
        reasons.append("Deployment Agent build does not match the expected build")
    return {
        "ready": not reasons,
        "requires_update": observation["build"] < required_build,
        "observed_build": observation["build"],
        "required_build": required_build,
        "expected_build": expected_build,
        "enabled": observation["enabled"],
        "cloud_state": observation["cloud_state"],
        "reasons": reasons,
    }
