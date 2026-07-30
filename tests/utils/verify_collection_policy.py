"""Verify collection content contains no prohibited execution escape hatches."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
from typing import Any

import yaml


class PolicyVerificationError(ValueError):
    """Collection content violates the prohibited-action policy."""


FORBIDDEN_ANSIBLE_ACTIONS = frozenset(
    {
        "ansible.builtin.command",
        "ansible.builtin.raw",
        "ansible.builtin.script",
        "ansible.builtin.shell",
        "ansible.legacy.command",
        "ansible.legacy.raw",
        "ansible.legacy.script",
        "ansible.legacy.shell",
        "command",
        "raw",
        "script",
        "shell",
    }
)
TASK_METADATA = frozenset(
    {
        "always",
        "any_errors_fatal",
        "args",
        "async",
        "become",
        "become_exe",
        "become_flags",
        "become_method",
        "become_user",
        "block",
        "changed_when",
        "check_mode",
        "collections",
        "connection",
        "debugger",
        "delay",
        "delegate_facts",
        "delegate_to",
        "diff",
        "environment",
        "failed_when",
        "ignore_errors",
        "ignore_unreachable",
        "listen",
        "loop",
        "loop_control",
        "module_defaults",
        "name",
        "no_log",
        "notify",
        "poll",
        "register",
        "remote_user",
        "rescue",
        "retries",
        "run_once",
        "tags",
        "throttle",
        "timeout",
        "until",
        "vars",
        "when",
    }
)
PLAY_MARKERS = frozenset({"hosts", "import_playbook", "ansible.builtin.import_playbook"})
PLAY_TASK_SECTIONS = ("pre_tasks", "tasks", "post_tasks", "handlers")


def _relative(root: Path, path: Path) -> str:
    return str(path.relative_to(root))


def _action_name(task: dict[str, Any], location: str) -> str | None:
    if "action" in task or "local_action" in task:
        raise PolicyVerificationError("alternate Ansible action syntax is prohibited")
    actions = [key for key in task if key not in TASK_METADATA]
    if not actions:
        return None
    if any(not isinstance(action, str) for action in actions):
        raise PolicyVerificationError(
            f"{location}: task action keys must be strings"
        )
    if len(actions) != 1:
        raise PolicyVerificationError(
            f"{location}: task has ambiguous action keys: {sorted(actions)}"
        )
    return actions[0]


def _verify_action(action: str, location: str) -> None:
    if action in FORBIDDEN_ANSIBLE_ACTIONS:
        raise PolicyVerificationError(
            f"{location}: prohibited Ansible action {action}"
        )
    if action.startswith("checkpoint_"):
        raise PolicyVerificationError(
            f"{location}: deprecated Check Point action {action}"
        )
    parts = action.split(".")
    if (
        len(parts) == 3
        and parts[0] == "check_point"
        and parts[1] in {"mgmt", "gaia"}
        and parts[2].startswith("checkpoint_")
    ):
        raise PolicyVerificationError(
            f"{location}: deprecated Check Point action {action}"
        )


def _walk_yaml(value: object, location: str) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk_yaml(item, f"{location}[{index}]")
        return
    if not isinstance(value, dict):
        return
    if PLAY_MARKERS & set(value):
        for section in PLAY_TASK_SECTIONS:
            if section in value:
                _walk_yaml(value[section], f"{location}.{section}")
        return
    action = _action_name(value, location)
    if action is not None:
        _verify_action(action, location)
    for section in ("block", "rescue", "always"):
        if section in value:
            _walk_yaml(value[section], f"{location}.{section}")


class _PythonPolicyVisitor(ast.NodeVisitor):
    def __init__(self, location: str):
        self.location = location
        self.import_module_aliases: set[str] = set()
        self.importlib_aliases: set[str] = set()
        self.os_aliases: set[str] = set()
        self.popen_aliases: set[str] = set()
        self.system_aliases: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for name in node.names:
            if name.name == "subprocess" or name.name.startswith("subprocess."):
                raise PolicyVerificationError(
                    f"{self.location}:{node.lineno}: subprocess import is prohibited"
                )
            if name.name == "importlib":
                self.importlib_aliases.add(name.asname or name.name)
            if name.name == "os":
                self.os_aliases.add(name.asname or name.name)
            elif name.name.startswith("os.") and name.asname is None:
                self.os_aliases.add("os")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "subprocess":
            raise PolicyVerificationError(
                f"{self.location}:{node.lineno}: subprocess import is prohibited"
            )
        if node.module == "importlib":
            for name in node.names:
                if name.name == "import_module":
                    self.import_module_aliases.add(name.asname or name.name)
        if node.module == "os":
            for name in node.names:
                if name.name == "*":
                    raise PolicyVerificationError(
                        f"{self.location}:{node.lineno}: os star import is prohibited"
                    )
                if name.name == "popen":
                    self.popen_aliases.add(name.asname or name.name)
                if name.name == "system":
                    self.system_aliases.add(name.asname or name.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in self.system_aliases | self.popen_aliases
        ):
            raise PolicyVerificationError(
                f"{self.location}:{node.lineno}: OS process call is prohibited"
            )
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"popen", "system"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.os_aliases
        ):
            raise PolicyVerificationError(
                f"{self.location}:{node.lineno}: OS process call is prohibited"
            )
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "__import__"
            and _prohibited_dynamic_import(_literal_string(node.args))
        ):
            raise PolicyVerificationError(
                f"{self.location}:{node.lineno}: dynamic process-capable import is prohibited"
            )
        if (
            (
                isinstance(node.func, ast.Name)
                and node.func.id in self.import_module_aliases
            )
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.importlib_aliases
            )
        ) and _prohibited_dynamic_import(_literal_string(node.args)):
            raise PolicyVerificationError(
                f"{self.location}:{node.lineno}: dynamic process-capable import is prohibited"
            )
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in self.os_aliases
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in {"popen", "system"}
        ):
            raise PolicyVerificationError(
                f"{self.location}:{node.lineno}: dynamic OS process call is prohibited"
            )
        self.generic_visit(node)


def _literal_string(arguments: list[ast.expr]) -> str | None:
    if (
        arguments
        and isinstance(arguments[0], ast.Constant)
        and isinstance(arguments[0].value, str)
    ):
        return arguments[0].value
    return None


def _prohibited_dynamic_import(name: str | None) -> bool:
    return bool(
        name
        and (
            name == "os"
            or name.startswith("os.")
            or name == "subprocess"
            or name.startswith("subprocess.")
        )
    )


def _yaml_files(root: Path) -> list[Path]:
    return list(root.rglob("*.yml")) + list(root.rglob("*.yaml"))


def verify_collection_policy(collection_root: Path) -> tuple[int, int]:
    """Verify shipped Python and Ansible YAML, returning scanned file counts."""

    root = collection_root.resolve(strict=True)
    yaml_paths = []
    playbook_root = root / "playbooks"
    if playbook_root.is_dir():
        yaml_paths.extend(_yaml_files(playbook_root))
    roles_root = root / "roles"
    if roles_root.is_dir():
        for section in ("tasks", "handlers"):
            for role_section in roles_root.glob(f"*/{section}"):
                yaml_paths.extend(_yaml_files(role_section))
    tests_root = root / "tests"
    integration_root = tests_root / "integration"
    if integration_root.is_dir():
        yaml_paths.extend(_yaml_files(integration_root))
    yaml_paths = sorted(set(yaml_paths))
    python_root = root / "plugins"
    python_paths = sorted(python_root.rglob("*.py")) if python_root.is_dir() else []
    if tests_root.is_dir():
        python_paths = sorted(set(python_paths) | set(tests_root.rglob("*.py")))

    for path in yaml_paths:
        location = _relative(root, path)
        try:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise PolicyVerificationError(f"{location}: cannot parse YAML") from error
        _walk_yaml(value, location)

    for path in python_paths:
        location = _relative(root, path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=location)
        except (OSError, UnicodeError, SyntaxError) as error:
            raise PolicyVerificationError(
                f"{location}: cannot parse Python"
            ) from error
        _PythonPolicyVisitor(location).visit(tree)

    return len(yaml_paths), len(python_paths)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collection-root", type=Path, required=True)
    arguments = parser.parse_args()
    yaml_count, python_count = verify_collection_policy(arguments.collection_root)
    print(
        "collection policy verified: "
        f"{yaml_count} Ansible YAML files, {python_count} Python files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
