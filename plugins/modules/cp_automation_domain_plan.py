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
module: cp_automation_domain_plan
short_description: Plan isolated sessions for regular Check Point domains
version_added: "0.1.0"
description:
  - Builds a deterministic session plan from complete full-detail domain facts.
  - Excludes global domains and fails on incomplete or ambiguous CMA identity.
  - Performs no network calls and makes no changes.
options:
  domain_records:
    description:
      - Complete merged rows returned by full-detail domain discovery.
      - Pagination must be completed before calling this module.
    type: list
    elements: dict
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
"""

EXAMPLES = r"""
- name: Plan one isolated Management API session per regular domain
  sgt_trojan.checkpoint_automation.cp_automation_domain_plan:
    domain_records: "{{ merged_domains }}"
  register: domain_session_plan
"""

RETURN = r"""
plan:
  description: Deterministically ordered regular-domain session definitions.
  type: list
  elements: dict
  returned: success
category:
  description: Stable failure category when planning is rejected.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.domain_plan import (
    DomainPlanError,
    build_domain_plan,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "domain_records": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
        },
        supports_check_mode=True,
    )
    try:
        plan = build_domain_plan(module.params["domain_records"])
    except DomainPlanError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    module.exit_json(changed=False, plan=plan)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
