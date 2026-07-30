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
module: cp_automation_live_preflight
short_description: Authorize one constrained live read-only discovery
version_added: "0.1.0"
description:
  - Validates a short lease, exact IP targets, credential-presence booleans,
    and check mode.
  - Performs no network requests and never accepts credential values.
options:
  lease:
    description: Short-lived runtime authorization lease.
    type: dict
    required: true
    suboptions:
      lease_id:
        description: UUIDv4 binding the lease and evidence directory.
        type: str
        required: true
      issued_at:
        description: RFC3339 UTC issuance time.
        type: str
        required: true
      expires_at:
        description: RFC3339 UTC expiry time.
        type: str
        required: true
      operation:
        description: Must be C(managed_discovery).
        type: str
        required: true
      execution_mode:
        description: Must be C(read_only).
        type: str
        required: true
      management_target:
        description: Exact leased management server IP address.
        type: str
        required: true
      member_targets:
        description: Exact leased two-member IP address set.
        type: list
        elements: str
        required: true
  management_target:
    description: Inventory-bound management server IP address.
    type: str
    required: true
  member_targets:
    description: Exact two requested member IP addresses.
    type: list
    elements: str
    required: true
  credential_presence:
    description: Computed credential-presence flags; never credential values.
    type: dict
    required: true
    suboptions:
      management_username:
        description: Whether the inventory management username is populated.
        type: bool
        required: true
      management_secret:
        description: Whether the inventory management secret is populated.
        type: bool
        required: true
  executor_check_mode:
    description: Whether the enclosing executor is running in check mode.
    type: bool
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
"""

EXAMPLES = r"""
- name: Authorize before any Check Point request
  sgt_trojan.checkpoint_automation.cp_automation_live_preflight:
    lease: "{{ checkpoint_live_lease }}"
    management_target: "{{ checkpoint_inventory_management_address }}"
    member_targets: "{{ checkpoint_target_ips }}"
    credential_presence:
      management_username: true
      management_secret: true
    executor_check_mode: "{{ ansible_check_mode }}"
"""

RETURN = r"""
authorization:
  description: Sanitized authorization with target fingerprint, never addresses.
  type: dict
  returned: success
category:
  description: Stable preflight failure category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.live_preflight import (
    LivePreflightError,
    authorize_live_readonly,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "lease": {
                "type": "dict",
                "required": True,
                "options": {
                    "lease_id": {"type": "str", "required": True},
                    "issued_at": {"type": "str", "required": True},
                    "expires_at": {"type": "str", "required": True},
                    "operation": {"type": "str", "required": True},
                    "execution_mode": {"type": "str", "required": True},
                    "management_target": {"type": "str", "required": True},
                    "member_targets": {
                        "type": "list",
                        "elements": "str",
                        "required": True,
                    },
                },
            },
            "management_target": {"type": "str", "required": True},
            "member_targets": {
                "type": "list",
                "elements": "str",
                "required": True,
            },
            "credential_presence": {
                "type": "dict",
                "required": True,
                "options": {
                    "management_username": {
                        "type": "bool",
                        "required": True,
                    },
                    "management_secret": {
                        "type": "bool",
                        "required": True,
                    },
                },
            },
            "executor_check_mode": {"type": "bool", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        authorization = authorize_live_readonly(
            lease=module.params["lease"],
            management_target=module.params["management_target"],
            member_targets=module.params["member_targets"],
            credential_presence=module.params["credential_presence"],
            check_mode=module.params["executor_check_mode"],
        )
    except LivePreflightError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    module.exit_json(changed=False, authorization=authorization)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
