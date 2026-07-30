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
module: cp_automation_readiness_decide
short_description: Decide two-member Check Point cluster readiness
version_added: "0.1.0"
description:
  - Requires exactly one ACTIVE and one STANDBY member.
  - Fails closed on incomplete health, identity, ICAP, or interface evidence.
  - Performs no network calls and makes no changes.
options:
  members:
    description: Exactly two structured member observations.
    type: list
    elements: dict
    required: true
  icap_mode:
    description: Whether explicit ICAP health is required.
    type: str
    choices: [required, optional, disabled]
    default: optional
  baseline_members:
    description: Optional two-member interface identity baseline.
    type: list
    elements: dict
  expected_active:
    description: Optional member name or address that must be ACTIVE.
    type: str
    default: ""
  expected_standby:
    description: Optional member name or address that must be STANDBY.
    type: str
    default: ""
  fail_on_not_ready:
    description: Fail the Ansible task when the decision is not ready.
    type: bool
    default: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
"""

EXAMPLES = r"""
- name: Require the captured standby-first cluster shape
  sgt_trojan.checkpoint_automation.cp_automation_readiness_decide:
    members: "{{ checkpoint_member_observations }}"
    icap_mode: required
    expected_active: Member-A
    expected_standby: Member-B
  register: checkpoint_readiness
"""

RETURN = r"""
readiness:
  description: Readiness result, reasons, and active and standby identities.
  type: dict
  returned: always
category:
  description: Stable failure category when readiness is rejected.
  choices:
    - INVALID_INPUT
    - UNSUPPORTED_TOPOLOGY
    - OBSERVATION_INCOMPLETE
    - NOT_READY
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.readiness import (
    ReadinessError,
    decide_readiness,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "members": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
            "icap_mode": {
                "type": "str",
                "choices": ["required", "optional", "disabled"],
                "default": "optional",
            },
            "baseline_members": {
                "type": "list",
                "elements": "dict",
                "default": None,
            },
            "expected_active": {"type": "str", "default": ""},
            "expected_standby": {"type": "str", "default": ""},
            "fail_on_not_ready": {"type": "bool", "default": True},
        },
        supports_check_mode=True,
    )
    try:
        readiness = decide_readiness(
            module.params["members"],
            icap_mode=module.params["icap_mode"],
            baseline_members=module.params["baseline_members"],
            expected_active=module.params["expected_active"],
            expected_standby=module.params["expected_standby"],
        )
    except ReadinessError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            readiness=error.result,
            changed=False,
        )
    if not readiness["ready"] and module.params["fail_on_not_ready"]:
        module.fail_json(
            msg="cluster readiness checks failed",
            category="NOT_READY",
            readiness=readiness,
            changed=False,
        )
    module.exit_json(changed=False, readiness=readiness)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
