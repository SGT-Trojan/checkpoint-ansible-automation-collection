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
module: cp_automation_package_state_acquire
short_description: Acquire fixed Check Point package state through Gaia API
version_added: "0.1.0"
description:
  - Runs one fixed, internal, read-only operation through the Gaia C(run-script)
    endpoint and polls its exact task identity within fixed bounds.
  - Observes C(show installer packages installed) and C(show snapshots).
  - Accepts no script, command, path, argument, or environment option.
  - Sets C(installed_packages_complete=true) only after the fixed CPUSE command
    and a strict parser for one recognized complete output format succeeds
    without warnings.
  - Live use is wired only through the lease-bound package-state role and is
    not yet certified on a firewall.
  - Gaia C(show-features) must report C(expert_api_runScript); the API user's
    role must grant C(expert_api_runscript) for C(run-script) and
    C(expert_api_misc) for C(show-task).
options:
  member_address:
    description:
      - Expected IPv4 or IPv6 address of the connected inventory member.
      - The module validates and returns it but cannot inspect the connection
        endpoint.
    type: str
    required: true
  version:
    description: Gaia API version, for example C(1.7).
    type: str
  authorization_expires_at:
    description:
      - RFC3339 UTC expiry returned by the immediately preceding live preflight.
      - Submission and every task poll stop at this deadline.
    type: str
    required: true
  timeout_seconds:
    description:
      - Polling deadline after C(run-script) returns, from 5 through 300.
      - HTTP request latency remains subject to the connection plugin timeout.
    type: int
    default: 120
  poll_interval_seconds:
    description: Delay between task polls, from 1 through 10.
    type: int
    default: 2
  max_output_bytes:
    description:
      - Maximum decoded output size.
      - Accepted values are 131072, 262144, 524288, and 1048576.
    type: int
    default: 524288
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
"""
EXAMPLES = r"""
- name: Acquire the fixed package-state observation
  sgt_trojan.checkpoint_automation.cp_automation_package_state_acquire:
    member_address: 192.0.2.10
    timeout_seconds: 120
    authorization_expires_at: "2026-08-28T14:05:00Z"
  register: package_state
"""
RETURN = r"""
observation:
  description: Normalized address, exact packages, restore bytes, task ID, and polls.
  type: dict
  returned: success
category:
  description: Stable fail-closed acquisition or parsing category.
  type: str
  returned: failure
reason:
  description: Allowlisted non-content parser branch.
  type: str
  returned: inventory format failure when available
shape:
  description: Capped sequence of allowlisted non-content line kinds.
  type: list
  elements: str
  returned: inventory format failure when available
task_id:
  description: Gaia task identity after submission.
  type: str
  returned: failure after task submission
"""

from datetime import datetime, timezone
import ipaddress
import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.package_state_acquisition import (
    PackageStateAcquisitionError,
    acquire,
)
from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.package_state_live_preflight import (
    PackageStateLivePreflightError,
    require_direct_gaia_controller,
)


def _vendor_send_request(connection, version, operation, payload):
    from ansible_collections.check_point.gaia.plugins.module_utils.checkpoint import (
        send_request,
    )

    return send_request(connection, version, operation, payload)


UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)


def _authorization_deadline(value):
    if not isinstance(value, str) or UTC_TIMESTAMP.fullmatch(value) is None:
        raise ValueError("authorization_expires_at must be an RFC3339 UTC timestamp")
    timestamp_format = (
        "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value else "%Y-%m-%dT%H:%M:%SZ"
    )
    return datetime.strptime(value, timestamp_format).replace(
        tzinfo=timezone.utc
    ).timestamp()


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "member_address": {"type": "str", "required": True},
            "version": {"type": "str"},
            "authorization_expires_at": {"type": "str", "required": True},
            "timeout_seconds": {
                "type": "int",
                "default": 120,
            },
            "poll_interval_seconds": {
                "type": "int",
                "default": 2,
            },
            "max_output_bytes": {
                "type": "int",
                "default": 524288,
            },
        },
        supports_check_mode=True,
    )
    try:
        ipaddress.ip_address(module.params["member_address"].strip())
    except ValueError:
        module.fail_json(
            msg="member_address must be an IPv4 or IPv6 address literal",
            category="ACQUISITION_INVALID",
            changed=False,
        )
    if not 5 <= module.params["timeout_seconds"] <= 300:
        module.fail_json(
            msg="timeout_seconds must be between 5 and 300",
            category="ACQUISITION_INVALID",
            changed=False,
        )
    if not 1 <= module.params["poll_interval_seconds"] <= 10:
        module.fail_json(
            msg="poll_interval_seconds must be between 1 and 10",
            category="ACQUISITION_INVALID",
            changed=False,
        )
    if module.params["max_output_bytes"] not in (
        131072,
        262144,
        524288,
        1048576,
    ):
        module.fail_json(
            msg="max_output_bytes is not an approved bound",
            category="ACQUISITION_INVALID",
            changed=False,
        )
    try:
        authorization_deadline_epoch = _authorization_deadline(
            module.params["authorization_expires_at"]
        )
    except (OverflowError, ValueError):
        module.fail_json(
            msg="authorization_expires_at must be an RFC3339 UTC timestamp",
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
        require_direct_gaia_controller()
    except PackageStateLivePreflightError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    connection = Connection(module._socket_path)

    def request(operation, payload):
        return _vendor_send_request(connection, version, operation, payload)

    try:
        observation = acquire(
            request=request,
            timeout_seconds=module.params["timeout_seconds"],
            poll_interval_seconds=module.params["poll_interval_seconds"],
            max_output_bytes=module.params["max_output_bytes"],
            authorization_deadline_epoch=authorization_deadline_epoch,
        )
    except PackageStateAcquisitionError as error:
        failure = {
            "msg": str(error),
            "category": error.category,
            "changed": False,
        }
        if error.task_id is not None:
            failure["task_id"] = error.task_id
        if error.category == "INVENTORY_FORMAT":
            if error.reason is not None:
                failure["reason"] = error.reason
            if error.shape is not None:
                failure["shape"] = list(error.shape)
        module.fail_json(**failure)
    observation["member_address"] = str(
        ipaddress.ip_address(module.params["member_address"].strip())
    )
    module.exit_json(changed=False, observation=observation)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
