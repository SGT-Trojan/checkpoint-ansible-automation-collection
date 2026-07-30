"""Verify the pinned Mgmt target-package module cannot certify completeness."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any

import yaml


class PackageInventoryCapabilityError(ValueError):
    """Pinned source no longer matches the fail-closed capability decision."""


PINNED_VERSION = "6.9.0"
MODULE_NAME = "cp_mgmt_show_software_packages_per_targets"
MODULE_FILENAME = f"{MODULE_NAME}.py"
COMMAND = "show-software-packages-per-targets"
DOCUMENTED_OPTIONS = frozenset({"display", "targets"})
CAPABILITY_MARKERS = frozenset(
    {
        "complete",
        "completeness",
        "count",
        "from",
        "has-more",
        "has_more",
        "limit",
        "next",
        "next-page",
        "next_page",
        "offset",
        "page",
        "page-size",
        "page_size",
        "pages",
        "task-id",
        "task_id",
        "tasks",
        "to",
        "total",
    }
)


def _constant(tree: ast.Module, name: str, path: Path) -> str:
    values = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if len(values) != 1:
        raise PackageInventoryCapabilityError(
            f"{path.name} must define one literal {name}"
        )
    return values[0]


def _main(tree: ast.Module, path: Path) -> ast.FunctionDef:
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
    ]
    if (
        len(functions) != 1
        or not isinstance(functions[0], ast.FunctionDef)
        or functions[0].name != "main"
    ):
        raise PackageInventoryCapabilityError(
            f"{path.name} must define exactly one function named main"
        )
    return functions[0]


def _literal_assignment(
    function: ast.FunctionDef,
    name: str,
    path: Path,
) -> str:
    values = [
        node.value.value
        for node in function.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if len(values) != 1:
        raise PackageInventoryCapabilityError(
            f"{path.name} must assign one literal {name}"
        )
    return values[0]


def _calls(function: ast.FunctionDef, name: str) -> list[ast.Call]:
    return [
        node
        for statement in function.body
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    ]


def _keys(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                result.add(key.lower())
            result.update(_keys(child))
    elif isinstance(value, list):
        for child in value:
            result.update(_keys(child))
    return result


def _mapping(text: str, label: str) -> dict[str, Any]:
    try:
        value = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise PackageInventoryCapabilityError(
            f"{label} must contain valid YAML"
        ) from error
    if not isinstance(value, dict):
        raise PackageInventoryCapabilityError(
            f"{label} must contain one mapping"
        )
    return value


def verify_package_inventory_capability(vendor_root: Path) -> None:
    """Verify pinned source remains insufficient to assert complete inventory."""

    root = vendor_root.resolve(strict=True)
    try:
        manifest = json.loads(
            (root / "MANIFEST.json").read_text(encoding="utf-8")
        )
        version = manifest["collection_info"]["version"]
    except (KeyError, OSError, UnicodeError, ValueError) as error:
        raise PackageInventoryCapabilityError(
            "cannot read vendor collection version"
        ) from error
    if version != PINNED_VERSION:
        raise PackageInventoryCapabilityError(
            f"vendor collection must be pinned to {PINNED_VERSION}"
        )

    path = root / "plugins" / "modules" / MODULE_FILENAME
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=MODULE_FILENAME)
    except (OSError, SyntaxError, UnicodeError) as error:
        raise PackageInventoryCapabilityError(
            f"cannot parse {MODULE_FILENAME}"
        ) from error

    documentation = _mapping(_constant(tree, "DOCUMENTATION", path), "DOCUMENTATION")
    returns = _mapping(_constant(tree, "RETURN", path), "RETURN")
    if documentation.get("module") != MODULE_NAME:
        raise PackageInventoryCapabilityError("documented module identity changed")
    options = documentation.get("options")
    if not isinstance(options, dict) or set(options) != DOCUMENTED_OPTIONS:
        raise PackageInventoryCapabilityError(
            "documented options changed; reassess inventory completeness"
        )
    if set(returns) != {MODULE_NAME}:
        raise PackageInventoryCapabilityError(
            "documented return shape changed; reassess inventory completeness"
        )
    observed_markers = (_keys(documentation) | _keys(returns)) & CAPABILITY_MARKERS
    if observed_markers:
        raise PackageInventoryCapabilityError(
            "vendor docs expose possible completeness/task markers; reassess"
        )

    function = _main(tree, path)
    if _literal_assignment(function, "command", path) != COMMAND:
        raise PackageInventoryCapabilityError("vendor command identity changed")
    api_calls = _calls(function, "api_command")
    if len(api_calls) != 1:
        raise PackageInventoryCapabilityError(
            "module must remain one direct generic api_command wrapper"
        )
    if (
        len(api_calls[0].args) < 2
        or not isinstance(api_calls[0].args[1], ast.Name)
        or api_calls[0].args[1].id != "command"
    ):
        raise PackageInventoryCapabilityError(
            "api_command must use the verified command binding"
        )
    for helper in ("api_call_facts", "api_call_facts_for_async"):
        if _calls(function, helper):
            raise PackageInventoryCapabilityError(
                "vendor helper changed; reassess inventory completeness"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor-root", type=Path, required=True)
    arguments = parser.parse_args()
    verify_package_inventory_capability(arguments.vendor_root)
    print(
        "verified check_point.mgmt "
        f"{PINNED_VERSION} {MODULE_NAME} lacks a complete inventory contract; "
        "acquisition remains blocked"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
