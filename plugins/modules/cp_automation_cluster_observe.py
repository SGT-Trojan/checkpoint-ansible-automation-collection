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
module: cp_automation_cluster_observe
short_description: Parse read-only Check Point member health output
version_added: "0.1.0"
description:
  - Converts bounded command output into a structured ClusterXL observation.
  - Performs no network calls and makes no changes.
options:
  name:
    description: Expected member name.
    type: str
    required: true
  address:
    description: Expected member management address.
    type: str
    required: true
  cluster_state_output:
    description: Complete output from C(cphaprob state).
    type: str
    required: true
  cluster_interfaces_output:
    description: Complete output from C(cphaprob -a if).
    type: str
    required: true
  icap_cpwd_output:
    description: Optional complete CICAP watchdog output.
    type: str
    default: ""
  icap_listener_output:
    description: Optional bounded TCP 1344 listener output.
    type: str
    default: ""
  icap_process_output:
    description: Optional bounded c-icap process output.
    type: str
    default: ""
author:
  - SGT-Trojan contributors (@SGT-Trojan)
"""

EXAMPLES = r"""
- name: Parse previously collected member observations
  sgt_trojan.checkpoint_automation.cp_automation_cluster_observe:
    name: Member-A
    address: 192.0.2.10
    cluster_state_output: "{{ member_state_output }}"
    cluster_interfaces_output: "{{ member_interfaces_output }}"
  register: member_observation
"""

RETURN = r"""
observation:
  description: Structured member readiness evidence.
  type: dict
  returned: success
category:
  description: Stable failure category when output is rejected.
  choices:
    - OBSERVATION_INVALID
    - OBSERVATION_INCOMPLETE
    - UNSUPPORTED_TOPOLOGY
    - IDENTITY_MISMATCH
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.cluster_observations import (
    ObservationError,
    normalize_ip,
    parse_cluster_interfaces,
    parse_cluster_state,
    parse_icap_status,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "name": {"type": "str", "required": True},
            "address": {"type": "str", "required": True},
            "cluster_state_output": {"type": "str", "required": True},
            "cluster_interfaces_output": {"type": "str", "required": True},
            "icap_cpwd_output": {"type": "str", "default": ""},
            "icap_listener_output": {"type": "str", "default": ""},
            "icap_process_output": {"type": "str", "default": ""},
        },
        supports_check_mode=True,
    )
    try:
        state = parse_cluster_state(module.params["cluster_state_output"])
        interfaces = parse_cluster_interfaces(
            module.params["cluster_interfaces_output"]
        )
        supplied_icap = any(
            module.params[key]
            for key in (
                "icap_cpwd_output",
                "icap_listener_output",
                "icap_process_output",
            )
        )
        icap = (
            parse_icap_status(
                module.params["icap_cpwd_output"],
                module.params["icap_listener_output"],
                module.params["icap_process_output"],
            )
            if supplied_icap
            else None
        )
        if not module.params["name"].strip():
            raise ObservationError(
                "OBSERVATION_INVALID",
                "expected member name must not be empty",
            )
        if state["local_name"].casefold() != module.params["name"].strip().casefold():
            raise ObservationError(
                "IDENTITY_MISMATCH",
                "local ClusterXL member name does not match the expected member",
            )
        observation = {
            "name": module.params["name"].strip(),
            "address": normalize_ip(module.params["address"]),
            "cluster_state": state["local_state"],
            "cluster_members": state["members"],
            "pnotes_ok": state["pnotes_ok"],
            "interfaces_ok": interfaces["ok"],
            "required_interfaces": interfaces["required_interfaces"],
            "declared_virtual_interfaces": interfaces[
                "declared_virtual_interfaces"
            ],
            "required_secured_interfaces": interfaces[
                "required_secured_interfaces"
            ],
            "interfaces": interfaces["interfaces"],
            "virtual_interfaces": interfaces["virtual_interfaces"],
            "icap_ok": icap["ok"] if icap is not None else None,
            "icap": icap or {},
        }
    except ObservationError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    module.exit_json(changed=False, observation=observation)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
