#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later
#
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r"""
---
module: cp_automation_deployment_agent_acquire
short_description: Acquire fixed Check Point Deployment Agent status
version_added: "0.1.0"
description:
  - Runs one fixed read-only C(show installer status all) operation through the
    Gaia C(run-script) endpoint and polls its exact task identity.
  - Accepts no script, command, path, argument, or environment option.
  - Returns only normalized Deployment Agent state.
  - Inventory binding and full lease authorization remain a separate calling
    role responsibility; do not use this module live by itself.
options:
  member_address:
    description: Expected inventory member IPv4 or IPv6 address.
    type: str
    required: true
  version:
    description: Gaia API version, for example C(1.7).
    type: str
  authorization_expires_at:
    description:
      - RFC3339 UTC expiry from the immediately preceding preflight.
      - Must be in the future and no more than 15 minutes from the module clock.
    type: str
    required: true
  timeout_seconds:
    description: Task polling deadline from 5 through 120 seconds.
    type: int
    default: 30
  poll_interval_seconds:
    description: Delay between task polls from 1 through 10 seconds.
    type: int
    default: 2
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
"""

EXAMPLES = r"""
- name: Acquire fixed Deployment Agent status after approved preflight
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_acquire:
    member_address: 192.0.2.10
    authorization_expires_at: "2026-08-28T14:05:00Z"
  register: deployment_agent_state
"""

RETURN = r"""
observation:
  description: Normalized address, enabled state, build, cloud state, task ID, and polls.
  type: dict
  returned: success
category:
  description: Stable acquisition or parsing failure category.
  type: str
  returned: failure
task_id:
  description: Gaia task identity after submission.
  type: str
  returned: failure after task submission
"""

from datetime import datetime, timezone
import ipaddress
import os
import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_acquisition import (
    DeploymentAgentAcquisitionError,
    acquire,
)


UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
CONTROLLER_PROXY_INVENTORY = "/etc/ansible/hosts"
MAX_AUTHORIZATION_HORIZON_SECONDS = 900


def _vendor_send_request(connection, version, operation, payload):
    from ansible_collections.check_point.gaia.plugins.module_utils.checkpoint import (
        send_request,
    )

    return send_request(connection, version, operation, payload)


def _current_epoch():
    return datetime.now(timezone.utc).timestamp()


def _authorization_deadline(value, now_epoch=None):
    if not isinstance(value, str) or UTC_TIMESTAMP.fullmatch(value) is None:
        raise ValueError("authorization_expires_at must be an RFC3339 UTC timestamp")
    timestamp_format = (
        "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value else "%Y-%m-%dT%H:%M:%SZ"
    )
    deadline = datetime.strptime(value, timestamp_format).replace(
        tzinfo=timezone.utc
    ).timestamp()
    current = _current_epoch() if now_epoch is None else now_epoch
    if deadline <= current:
        raise ValueError("authorization_expires_at has expired")
    if deadline - current > MAX_AUTHORIZATION_HORIZON_SECONDS:
        raise ValueError("authorization_expires_at exceeds 15 minutes")
    return deadline


def _require_direct_gaia_controller():
    try:
        os.lstat(CONTROLLER_PROXY_INVENTORY)
    except FileNotFoundError:
        return
    except OSError as error:
        raise DeploymentAgentAcquisitionError(
            "TARGET_PROXY_UNSUPPORTED",
            "controller proxy inventory state could not be verified",
        ) from error
    raise DeploymentAgentAcquisitionError(
        "TARGET_PROXY_UNSUPPORTED",
        "direct Gaia execution requires /etc/ansible/hosts to be absent",
    )


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "member_address": {"type": "str", "required": True},
            "version": {"type": "str"},
            "authorization_expires_at": {"type": "str", "required": True},
            "timeout_seconds": {"type": "int", "default": 30},
            "poll_interval_seconds": {"type": "int", "default": 2},
        },
        supports_check_mode=True,
    )
    try:
        member_address = str(
            ipaddress.ip_address(module.params["member_address"].strip())
        )
    except ValueError:
        module.fail_json(
            msg="member_address must be an IPv4 or IPv6 address literal",
            category="ACQUISITION_INVALID",
            changed=False,
        )
    if not 5 <= module.params["timeout_seconds"] <= 120:
        module.fail_json(
            msg="timeout_seconds must be between 5 and 120",
            category="ACQUISITION_INVALID",
            changed=False,
        )
    if not 1 <= module.params["poll_interval_seconds"] <= 10:
        module.fail_json(
            msg="poll_interval_seconds must be between 1 and 10",
            category="ACQUISITION_INVALID",
            changed=False,
        )
    try:
        authorization_deadline_epoch = _authorization_deadline(
            module.params["authorization_expires_at"]
        )
    except (OverflowError, ValueError):
        module.fail_json(
            msg=(
                "authorization_expires_at must be a current RFC3339 UTC "
                "timestamp no more than 15 minutes in the future"
            ),
            category="ACQUISITION_INVALID",
            changed=False,
        )
    version = module.params["version"]
    if version is not None:
        version = version.strip()
        if not version or re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version) is None:
            module.fail_json(
                msg="Gaia API version must contain dot-separated integers",
                category="ACQUISITION_INVALID",
                changed=False,
            )
        version = "v{0}/".format(version)
    else:
        version = ""
    try:
        _require_direct_gaia_controller()
    except DeploymentAgentAcquisitionError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    connection = Connection(module._socket_path)

    def request(operation, payload):
        return _vendor_send_request(connection, version, operation, payload)

    try:
        observation = acquire(
            request=request,
            timeout_seconds=module.params["timeout_seconds"],
            poll_interval_seconds=module.params["poll_interval_seconds"],
            authorization_deadline_epoch=authorization_deadline_epoch,
        )
    except DeploymentAgentAcquisitionError as error:
        failure = {"msg": str(error), "category": error.category, "changed": False}
        if error.task_id is not None:
            failure["task_id"] = error.task_id
        module.fail_json(**failure)
    observation["member_address"] = member_address
    module.exit_json(changed=False, observation=observation)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
