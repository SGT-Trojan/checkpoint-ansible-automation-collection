"""Verify the pinned Mgmt facts modules and explicit role check-mode policy."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import argparse
import ast
import json
from pathlib import Path
from typing import Iterable

import yaml


class VendorContractError(ValueError):
    """Pinned vendor source or local task policy does not match the contract."""


PINNED_VERSION = "6.9.0"
MODULE_CONTRACT = {
    "cp_mgmt_domain_facts.py": {
        "supports_check_mode": True,
        "direct_helper": "api_call_facts",
    },
    "cp_mgmt_simple_cluster_facts.py": {
        "supports_check_mode": True,
        "direct_helper": "api_call_facts",
    },
    "cp_mgmt_show_gateways_and_servers.py": {
        "supports_check_mode": False,
        "direct_helper": "api_command",
    },
}
TASK_CONTRACT = (
    (
        "roles/checkpoint_mds_domains/tasks/fetch_page.yml",
        "check_point.mgmt.cp_mgmt_domain_facts",
        True,
    ),
    (
        "roles/checkpoint_domain_inventory/tasks/fetch_clusters_page.yml",
        "check_point.mgmt.cp_mgmt_simple_cluster_facts",
        True,
    ),
    (
        "roles/checkpoint_domain_inventory/tasks/fetch_cluster_detail.yml",
        "check_point.mgmt.cp_mgmt_simple_cluster_facts",
        True,
    ),
    (
        "roles/checkpoint_domain_inventory/tasks/fetch_gateways_page.yml",
        "check_point.mgmt.cp_mgmt_show_gateways_and_servers",
        False,
    ),
)


def _main_function(tree: ast.Module, path: Path) -> ast.FunctionDef:
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    ]
    if len(functions) != 1:
        raise VendorContractError(f"{path.name} must define exactly one main")
    return functions[0]


def _ansible_module_check_mode(function: ast.FunctionDef, path: Path) -> bool:
    calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "AnsibleModule"
    ]
    if len(calls) != 1:
        raise VendorContractError(
            f"{path.name} must construct exactly one AnsibleModule"
        )
    values = [
        keyword.value
        for keyword in calls[0].keywords
        if keyword.arg == "supports_check_mode"
    ]
    if not values:
        return False
    if len(values) != 1 or not isinstance(values[0], ast.Constant):
        raise VendorContractError(
            f"{path.name} has a nonliteral supports_check_mode"
        )
    return values[0].value is True


def _statement_calls(statement: ast.stmt) -> Iterable[str]:
    for node in ast.walk(statement):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            yield node.func.id


def _has_direct_helper(function: ast.FunctionDef, helper: str) -> bool:
    for statement in function.body:
        if isinstance(statement, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
            continue
        if helper in set(_statement_calls(statement)):
            return True
    return False


def verify_vendor_sources(vendor_root: Path) -> None:
    """Verify exact pinned source behavior without importing vendor code."""

    root = vendor_root.resolve(strict=True)
    manifest_path = root / "MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        version = manifest["collection_info"]["version"]
    except (KeyError, OSError, UnicodeError, ValueError) as error:
        raise VendorContractError("cannot read vendor collection version") from error
    if version != PINNED_VERSION:
        raise VendorContractError(
            f"vendor collection must be pinned to {PINNED_VERSION}"
        )
    module_root = root / "plugins" / "modules"
    for filename, contract in MODULE_CONTRACT.items():
        path = module_root / filename
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=filename)
        except (OSError, SyntaxError, UnicodeError) as error:
            raise VendorContractError(f"cannot parse {filename}") from error
        function = _main_function(tree, path)
        actual_support = _ansible_module_check_mode(function, path)
        if actual_support is not contract["supports_check_mode"]:
            raise VendorContractError(
                f"{filename} check-mode support differs from the pinned contract"
            )
        if not _has_direct_helper(function, str(contract["direct_helper"])):
            raise VendorContractError(
                f"{filename} does not directly execute "
                f"{contract['direct_helper']} from main"
            )


def verify_task_policy(collection_root: Path) -> None:
    """Require an explicit literal check_mode at every pinned call site."""

    root = collection_root.resolve(strict=True)
    for relative, action, expected in TASK_CONTRACT:
        path = root / relative
        try:
            tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise VendorContractError(f"cannot parse {relative}") from error
        matches = [
            task
            for task in tasks
            if isinstance(task, dict) and action in task
        ]
        if len(matches) != 1:
            raise VendorContractError(
                f"{relative} must contain exactly one {action} task"
            )
        if matches[0].get("check_mode") is not expected:
            raise VendorContractError(
                f"{relative} must set check_mode to {expected}"
            )


def verify_mgmt_check_mode(vendor_root: Path, collection_root: Path) -> None:
    """Verify vendor implementation and the matching local task behavior."""

    verify_vendor_sources(vendor_root)
    verify_task_policy(collection_root)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor-root", type=Path, required=True)
    parser.add_argument(
        "--collection-root",
        type=Path,
        default=Path.cwd(),
    )
    args = parser.parse_args()
    verify_mgmt_check_mode(args.vendor_root, args.collection_root)
    print(
        "verified check_point.mgmt "
        f"{PINNED_VERSION} check-mode source and task policy"
    )


if __name__ == "__main__":
    main()
