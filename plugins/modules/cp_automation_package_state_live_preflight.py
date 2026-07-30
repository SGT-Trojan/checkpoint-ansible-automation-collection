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
module: cp_automation_package_state_live_preflight
short_description: Authorize one live read-only package-state observation
version_added: "0.1.0"
description:
  - Validates a short package-state lease, exact two-member target set,
    credential-presence booleans, and Ansible check mode.
  - Performs no network requests and never accepts credential values.
  - Requires the vendor plugin proxy inventory path C(/etc/ansible/hosts) to
    be absent so Gaia requests cannot be silently switched to Management API.
options:
  lease:
    description: Short-lived runtime authorization lease.
    type: dict
    required: true
    suboptions:
      lease_id:
        description: UUIDv4 binding the lease and private evidence.
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
        description: Must be C(package_state_observation).
        type: str
        required: true
      execution_mode:
        description: Must be C(read_only).
        type: str
        required: true
      tls_validation_mode:
        description:
          - Selects strict certificate validation or an explicit lab-only
            unverified session.
        type: str
        choices:
          - strict
          - lab_unverified
        required: true
      member_targets:
        description: Exact leased two-member IP address set.
        type: list
        elements: str
        required: true
  member_target:
    description: Current inventory-bound member IP address.
    type: str
    required: true
  member_targets:
    description: Exact runtime two-member IP address set.
    type: list
    elements: str
    required: true
  credential_presence:
    description: Computed Gaia credential-presence flags, never values.
    type: dict
    required: true
    suboptions:
      gaia_username:
        description: Whether the inventory Gaia username is populated.
        type: bool
        required: true
      gaia_secret:
        description: Whether the inventory Gaia secret is populated.
        type: bool
        required: true
  tls_validation_enabled:
    description: Literal effective state of HTTPAPI certificate validation.
    type: bool
    required: true
  lab_tls_exception_acknowledged:
    description:
      - Must be C(true) only with a C(lab_unverified) lease.
      - Must be C(false) with a C(strict) lease.
    type: bool
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
"""

EXAMPLES = r"""
- name: Authorize immediately before a package-state request
  sgt_trojan.checkpoint_automation.cp_automation_package_state_live_preflight:
    lease: "{{ checkpoint_package_state_live_lease }}"
    member_target: "{{ ansible_host }}"
    member_targets: "{{ checkpoint_package_state_live_member_targets }}"
    credential_presence:
      gaia_username: true
      gaia_secret: true
    tls_validation_enabled: true
    lab_tls_exception_acknowledged: false
  delegate_to: localhost
"""

RETURN = r"""
authorization:
  description:
    - Sanitized authorization with target fingerprint and TLS validation mode,
      never addresses.
  type: dict
  returned: success
category:
  description: Stable preflight failure category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.package_state_live_preflight import (
    PackageStateLivePreflightError,
    authorize_package_state_readonly,
    require_direct_gaia_controller,
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
                    "tls_validation_mode": {
                        "type": "str",
                        "choices": ["strict", "lab_unverified"],
                        "required": True,
                    },
                    "member_targets": {
                        "type": "list",
                        "elements": "str",
                        "required": True,
                    },
                },
            },
            "member_target": {"type": "str", "required": True},
            "member_targets": {
                "type": "list",
                "elements": "str",
                "required": True,
            },
            "credential_presence": {
                "type": "dict",
                "required": True,
            },
            "tls_validation_enabled": {"type": "bool", "required": True},
            "lab_tls_exception_acknowledged": {
                "type": "bool",
                "required": True,
            },
        },
        supports_check_mode=True,
    )
    try:
        require_direct_gaia_controller()
        authorization = authorize_package_state_readonly(
            lease=module.params["lease"],
            member_target=module.params["member_target"],
            member_targets=module.params["member_targets"],
            credential_presence=module.params["credential_presence"],
            tls_validation_enabled=module.params["tls_validation_enabled"],
            lab_tls_exception_acknowledged=module.params[
                "lab_tls_exception_acknowledged"
            ],
            check_mode=module.check_mode,
        )
    except PackageStateLivePreflightError as error:
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
