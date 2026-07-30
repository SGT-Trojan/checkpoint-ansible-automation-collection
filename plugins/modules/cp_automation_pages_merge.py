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
module: cp_automation_pages_merge
short_description: Validate and merge explicitly paged Check Point facts
version_added: "0.1.0"
description:
  - Merges complete pages returned by Check Point facts and show modules.
  - Fails on gaps, changed totals, offset or from/to mismatches, repeated pages,
    duplicate objects, or malformed rows.
  - Performs no network calls and makes no changes.
options:
  pages:
    description: Ordered page envelopes with the requested offset and raw response.
    type: list
    elements: dict
    required: true
    suboptions:
      offset:
        description: Zero-based offset used for the request.
        type: int
        required: true
      response:
        description: Raw Check Point API response for this page.
        type: dict
        required: true
  result_keys:
    description: Accepted response keys for the result list.
    type: list
    elements: str
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
"""

EXAMPLES = r"""
- name: Validate all domain pages
  sgt_trojan.checkpoint_automation.cp_automation_pages_merge:
    pages: "{{ checkpoint_domain_pages }}"
    result_keys:
      - objects
      - domains
  register: checkpoint_domains
"""

RETURN = r"""
merged:
  description: Validated result key, total, and complete object list.
  type: dict
  returned: success
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.pagination import (
    PaginationError,
    merge_pages,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "pages": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "options": {
                    "offset": {"type": "int", "required": True},
                    "response": {"type": "dict", "required": True},
                },
            },
            "result_keys": {
                "type": "list",
                "elements": "str",
                "required": True,
                "no_log": False,
            },
        },
        supports_check_mode=True,
    )
    try:
        merged = merge_pages(
            module.params["pages"],
            module.params["result_keys"],
        )
    except PaginationError as error:
        module.fail_json(
            msg=str(error),
            category="DISCOVERY_INCOMPLETE",
            changed=False,
        )
    module.exit_json(changed=False, merged=merged)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
