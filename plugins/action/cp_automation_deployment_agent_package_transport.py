# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Controller-side bounded streaming for Deployment Agent package transport."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import os

from ansible.plugins.action import ActionBase

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_package_transport import (
    CHUNK_SIZE,
    DeploymentAgentPackageTransportError,
    prepare_deployment_agent_package_transport,
    require_unexpired,
)


class ActionModule(ActionBase):
    """Stream an exact retained controller artifact through bounded module calls."""

    TRANSFERS_FILES = True

    def _fail(self, category, message):
        return {"failed": True, "changed": False, "category": category, "msg": message}

    def _connection_contract(self, task_vars):
        transport = getattr(self._connection, "transport", "")
        play_context = getattr(self._connection, "_play_context", None)
        remote_address = getattr(play_context, "remote_addr", None)
        try:
            host_key_checking = self._connection.get_option("host_key_checking")
        except (AttributeError, KeyError):
            host_key_checking = None
        if transport != "ssh":
            raise DeploymentAgentPackageTransportError(
                "TRANSPORT_INVALID",
                "package transport requires the Ansible SSH connection plugin",
            )
        if host_key_checking is not True:
            raise DeploymentAgentPackageTransportError(
                "SSH_HOST_KEY_VALIDATION_INVALID",
                "package transport requires SSH host-key validation",
            )
        inventory_id = task_vars.get("inventory_hostname")
        inventory_address = task_vars.get("ansible_host", remote_address)
        if (
            not isinstance(inventory_id, str)
            or not inventory_id
            or not isinstance(inventory_address, str)
            or not isinstance(remote_address, str)
        ):
            raise DeploymentAgentPackageTransportError(
                "TARGET_INVALID", "inventory target identity is incomplete"
            )
        try:
            expected = str(ipaddress.ip_address(inventory_address.strip()))
            connected = str(ipaddress.ip_address(remote_address.strip()))
        except ValueError as error:
            raise DeploymentAgentPackageTransportError(
                "TARGET_INVALID", "inventory and connection targets must be IP literals"
            ) from error
        if expected != connected:
            raise DeploymentAgentPackageTransportError(
                "TARGET_MISMATCH",
                "SSH connection address does not match the inventory target",
            )
        return inventory_id, expected, host_key_checking

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(task_vars=task_vars)
        source_fd = -1
        try:
            member_target_id, member_address, host_key_checking = (
                self._connection_contract(task_vars)
            )
            arguments = dict(self._task.args)
            required = {
                "lease",
                "update_plan",
                "staging",
                "member_targets",
                "runtime_commit",
                "tls_validation_enabled",
                "lab_tls_exception_acknowledged",
            }
            if set(arguments) != required:
                return self._fail(
                    "TRANSPORT_INPUT_INVALID",
                    "package transport arguments do not match the public contract",
                )
            source_fd, source_metadata, plan, authorization = (
                prepare_deployment_agent_package_transport(
                    member_target_id=member_target_id,
                    member_address=member_address,
                    ssh_host_key_checking_enabled=host_key_checking,
                    check_mode=self._task.check_mode,
                    now=datetime.now(timezone.utc),
                    **arguments,
                )
            )
            digest = hashlib.sha256()
            offset = 0
            read_calls = 0
            read_budget = (
                (plan["artifact_size"] + CHUNK_SIZE - 1) // CHUNK_SIZE
            ) * 4 + 8
            while offset < plan["artifact_size"]:
                expected_chunk_size = min(
                    CHUNK_SIZE, plan["artifact_size"] - offset
                )
                parts = []
                collected = 0
                while collected < expected_chunk_size:
                    if read_calls >= read_budget:
                        raise DeploymentAgentPackageTransportError(
                            "READ_BUDGET_EXHAUSTED",
                            "transport source read-call budget was exhausted",
                        )
                    part = os.read(source_fd, expected_chunk_size - collected)
                    read_calls += 1
                    if not part:
                        raise DeploymentAgentPackageTransportError(
                            "STAGING_MISMATCH",
                            "staged package ended before its bound size",
                        )
                    parts.append(part)
                    collected += len(part)
                current = b"".join(parts)
                digest.update(current)
                final = offset + len(current) == plan["artifact_size"]
                value = os.fstat(source_fd)
                current_metadata = (
                    value.st_dev,
                    value.st_ino,
                    value.st_mode,
                    value.st_size,
                    value.st_mtime_ns,
                    value.st_ctime_ns,
                )
                if final and (
                    digest.hexdigest() != plan["checksum_sha256"]
                    or current_metadata != source_metadata
                    or os.read(source_fd, 1)
                ):
                    raise DeploymentAgentPackageTransportError(
                        "STAGING_MISMATCH",
                        "staged package changed during transport",
                    )
                require_unexpired(
                    authorization, lambda: datetime.now(timezone.utc)
                )
                module_args = {
                    **arguments,
                    "_member_target_id": member_target_id,
                    "_member_address": member_address,
                    "_ssh_host_key_checking_enabled": host_key_checking,
                    "_offset": offset,
                    "_content_base64": base64.b64encode(current).decode("ascii"),
                    "_final": final,
                }
                chunk_result = self._execute_module(
                    module_name=(
                        "sgt_trojan.checkpoint_automation."
                        "cp_automation_deployment_agent_package_transport"
                    ),
                    module_args=module_args,
                    task_vars=task_vars,
                    wrap_async=False,
                )
                if chunk_result.get("failed"):
                    chunk_result.setdefault("changed", False)
                    return chunk_result
                offset += len(current)
                if final:
                    result.update(chunk_result)
                    result.pop("progress", None)
                    result["changed"] = chunk_result.get("changed", False)
                    return result
            raise DeploymentAgentPackageTransportError(
                "TRANSFER_SIZE_MISMATCH", "transport ended before final publication"
            )
        except DeploymentAgentPackageTransportError as error:
            return self._fail(error.category, str(error))
        finally:
            if source_fd >= 0:
                os.close(source_fd)
