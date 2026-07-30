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
module: cp_automation_readiness_acquire
short_description: Acquire fixed Check Point readiness evidence through Gaia API
version_added: "0.1.0"
description:
  - Runs one fixed, internal, read-only operation through the Gaia C(run-script)
    endpoint and polls its exact task identity within a caller-selected bound.
  - This is not a native ClusterXL facts endpoint.
  - The module accepts no script, command, path, or environment arguments.
  - The current fixed operation supports non-VSX cluster members only.
  - Gaia C(show-features) reports C(expert_api_runScript); the API user's Gaia
    role must grant C(expert_api_runscript) for C(run-script) and
    C(expert_api_misc) for C(show-task), and C(expert_api_features) for
    C(show-features).
options:
  member_address:
    description:
      - Inventory-bound IPv4 or IPv6 address of the connected member.
      - Hostnames are rejected before the Gaia operation is submitted.
    type: str
    required: true
  version:
    description: Gaia API version, for example C(1.7).
    type: str
  timeout_seconds:
    description: Total fixed-operation polling bound, from 5 through 120.
    type: int
    default: 30
  poll_interval_seconds:
    description: Delay between task polls, from 1 through 10.
    type: int
    default: 2
  max_output_bytes:
    description:
      - Maximum decoded output size.
      - Must be 32768, 65536, 131072, or 262144.
    type: int
    default: 131072
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
"""

EXAMPLES = r"""
- name: Acquire the fixed readiness observation
  sgt_trojan.checkpoint_automation.cp_automation_readiness_acquire:
    member_address: 192.0.2.10
    timeout_seconds: 30
    max_output_bytes: 131072
  register: readiness_evidence
"""

RETURN = r"""
acquisition:
  description: Validated task identity, poll count, and fixed evidence sections.
  type: dict
  returned: success
category:
  description: Stable acquisition failure category.
  type: str
  returned: failure
task_id:
  description: Gaia task identity for reconciling a post-submission failure.
  type: str
  returned: failure after task submission
"""

import ipaddress
import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.readiness_acquisition import (
    AcquisitionError,
    acquire,
)


def _vendor_send_request(connection, version, operation, payload):
    from ansible_collections.check_point.gaia.plugins.module_utils.checkpoint import (
        send_request,
    )

    return send_request(connection, version, operation, payload)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "member_address": {"type": "str", "required": True},
            "version": {"type": "str"},
            "timeout_seconds": {
                "type": "int",
                "default": 30,
            },
            "poll_interval_seconds": {
                "type": "int",
                "default": 2,
            },
            "max_output_bytes": {
                "type": "int",
                "default": 131072,
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
    if module.params["max_output_bytes"] not in (
        32768,
        65536,
        131072,
        262144,
    ):
        module.fail_json(
            msg="max_output_bytes is not an approved bound",
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
    connection = Connection(module._socket_path)

    def request(operation, payload):
        return _vendor_send_request(connection, version, operation, payload)

    try:
        result = acquire(
            request=request,
            timeout_seconds=module.params["timeout_seconds"],
            poll_interval_seconds=module.params["poll_interval_seconds"],
            max_output_bytes=module.params["max_output_bytes"],
        )
    except AcquisitionError as error:
        failure = {
            "msg": str(error),
            "category": error.category,
            "changed": False,
        }
        if error.task_id is not None:
            failure["task_id"] = error.task_id
        module.fail_json(**failure)
    module.exit_json(changed=False, acquisition=result)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
