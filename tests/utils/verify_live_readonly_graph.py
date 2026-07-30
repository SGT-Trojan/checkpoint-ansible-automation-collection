"""Structurally verify the complete live read-only Ansible call graph."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

import yaml


class GraphVerificationError(ValueError):
    """The executor graph is dynamic, external, malformed, or not approved."""


APPROVED_ACTIONS = frozenset(
    {
        "ansible.builtin.add_host",
        "ansible.builtin.assert",
        "ansible.builtin.import_playbook",
        "ansible.builtin.include_role",
        "ansible.builtin.include_tasks",
        "ansible.builtin.set_fact",
        "check_point.mgmt.cp_mgmt_domain_facts",
        "check_point.mgmt.cp_mgmt_show_gateways_and_servers",
        "check_point.mgmt.cp_mgmt_simple_cluster_facts",
        "sgt_trojan.checkpoint_automation.cp_automation_domain_plan",
        "sgt_trojan.checkpoint_automation.cp_automation_live_preflight",
        "sgt_trojan.checkpoint_automation.cp_automation_pages_merge",
        "sgt_trojan.checkpoint_automation.cp_automation_target_resolve",
    }
)
REQUIRED_ACTIONS = APPROVED_ACTIONS
ENTRYPOINT = Path("playbooks/live_readonly_managed_discovery.yml")
LOCAL_ROLE_PREFIX = "sgt_trojan.checkpoint_automation."
INCLUDE_TASK_ACTIONS = frozenset(
    {
        "ansible.builtin.include_tasks",
        "ansible.builtin.import_tasks",
    }
)
INCLUDE_ROLE_ACTIONS = frozenset(
    {
        "ansible.builtin.include_role",
        "ansible.builtin.import_role",
    }
)
TASK_METADATA = frozenset(
    {
        "name",
        "args",
        "become",
        "become_flags",
        "become_method",
        "become_user",
        "changed_when",
        "check_mode",
        "connection",
        "delegate_facts",
        "delegate_to",
        "delay",
        "diff",
        "environment",
        "failed_when",
        "ignore_errors",
        "ignore_unreachable",
        "loop",
        "loop_control",
        "no_log",
        "notify",
        "poll",
        "register",
        "remote_user",
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
BLOCK_KEYS = frozenset({"block", "rescue", "always"})
PLAY_KEYS = frozenset(
    {
        "name",
        "hosts",
        "gather_facts",
        "any_errors_fatal",
        "force_handlers",
        "max_fail_percentage",
        "order",
        "pre_tasks",
        "roles",
        "serial",
        "strategy",
        "tasks",
        "post_tasks",
        "handlers",
        "tags",
        "vars",
    }
)
IMPORT_PLAY_KEYS = frozenset(
    {
        "name",
        "ansible.builtin.import_playbook",
        "tags",
        "vars",
    }
)
_DYNAMIC = re.compile(r"{{|{%|{#")
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
PAGINATION_RECURSION_GUARDS = {
    "roles/checkpoint_mds_domains/tasks/fetch_page.yml": (
        "checkpoint_domain_next_offset | int "
        "< checkpoint_domain_page_response.total | int"
    ),
    "roles/checkpoint_domain_inventory/tasks/fetch_gateways_page.yml": (
        "checkpoint_gateway_next_offset | int "
        "< checkpoint_gateway_page_response.total | int"
    ),
    "roles/checkpoint_domain_inventory/tasks/fetch_clusters_page.yml": (
        "checkpoint_cluster_next_offset | int "
        "< checkpoint_cluster_page_response.total | int"
    ),
}


@dataclass(frozen=True)
class GraphReport:
    """Sanitized structured graph result."""

    files: tuple[str, ...]
    actions: tuple[str, ...]
    action_occurrences: int


class GraphVerifier:
    """Resolve literal local Ansible edges and enumerate every action."""

    def __init__(
        self,
        collection_root: Path,
        approved_actions: frozenset[str] = APPROVED_ACTIONS,
        required_actions: frozenset[str] = REQUIRED_ACTIONS,
    ):
        self.root = collection_root.resolve(strict=True)
        self.approved_actions = approved_actions
        self.required_actions = required_actions
        self.files: set[Path] = set()
        self.active: set[Path] = set()
        self.actions: list[str] = []

    def verify(self, entrypoint: Path = ENTRYPOINT) -> GraphReport:
        """Verify one root playbook and return its complete static graph."""

        self._visit_playbook(self._inside(self.root / entrypoint, "entrypoint"))
        observed = set(self.actions)
        if observed != set(self.required_actions):
            missing = sorted(set(self.required_actions) - observed)
            unexpected = sorted(observed - set(self.required_actions))
            raise GraphVerificationError(
                f"executor action graph mismatch; missing={missing}, "
                f"unexpected={unexpected}"
            )
        return GraphReport(
            files=tuple(
                sorted(str(path.relative_to(self.root)) for path in self.files)
            ),
            actions=tuple(sorted(observed)),
            action_occurrences=len(self.actions),
        )

    def _inside(self, path: Path, label: str) -> Path:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.root)
        except (OSError, ValueError) as error:
            raise GraphVerificationError(
                f"{label} must resolve to an existing collection-local file"
            ) from error
        if not resolved.is_file():
            raise GraphVerificationError(f"{label} must resolve to a file")
        return resolved

    def _literal(self, value: object, label: str) -> str:
        if (
            not isinstance(value, str)
            or not value.strip()
            or value != value.strip()
            or _DYNAMIC.search(value)
            or _URI.match(value)
            or "\n" in value
        ):
            raise GraphVerificationError(f"{label} must be one literal local target")
        return value

    def _load(self, path: Path, expected: type) -> Any:
        try:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise GraphVerificationError(f"cannot parse {path}") from error
        if not isinstance(value, expected):
            raise GraphVerificationError(
                f"{path.relative_to(self.root)} must contain {expected.__name__}"
            )
        return value

    def _start(self, path: Path) -> bool:
        if path in self.active:
            raise GraphVerificationError("unapproved active traversal cycle")
        if path in self.files:
            return False
        self.files.add(path)
        self.active.add(path)
        return True

    def _finish(self, path: Path) -> None:
        self.active.remove(path)

    def _visit_playbook(self, path: Path) -> None:
        if not self._start(path):
            return
        plays = self._load(path, list)
        for index, play in enumerate(plays):
            if not isinstance(play, dict):
                raise GraphVerificationError(f"{path}: play {index} is not a mapping")
            if "action" in play or "local_action" in play:
                raise GraphVerificationError("alternate action syntax is prohibited")
            if "ansible.builtin.import_playbook" in play:
                unknown = set(play) - IMPORT_PLAY_KEYS
                if unknown:
                    raise GraphVerificationError(
                        f"unsupported import_playbook keys: {sorted(unknown)}"
                    )
                self._record("ansible.builtin.import_playbook")
                target = self._literal(
                    play["ansible.builtin.import_playbook"],
                    "import_playbook",
                )
                self._visit_playbook(
                    self._resolve_relative(path.parent, target, "import_playbook")
                )
                continue
            unknown = set(play) - PLAY_KEYS
            if unknown:
                raise GraphVerificationError(
                    f"unsupported play keys: {sorted(unknown)}"
                )
            self._visit_play_roles(play.get("roles", []))
            for section in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                self._visit_tasks(play.get(section, []), path)
        self._finish(path)

    def _visit_play_roles(self, roles: object) -> None:
        if not isinstance(roles, list):
            raise GraphVerificationError("play roles must be a list")
        for item in roles:
            if isinstance(item, str):
                role_name = item
            elif isinstance(item, dict):
                if "role" not in item or set(item) - {"role", "vars", "when", "tags"}:
                    raise GraphVerificationError("play role must have one literal role")
                role_name = item["role"]
            else:
                raise GraphVerificationError("play role is not literal")
            self._visit_role(self._literal(role_name, "play role"))

    def _resolve_relative(self, parent: Path, target: str, label: str) -> Path:
        target_path = Path(target)
        if target_path.is_absolute() or ".." in target_path.parts:
            raise GraphVerificationError(f"{label} cannot escape the collection")
        return self._inside(parent / target_path, label)

    def _role_name(self, value: object) -> str:
        role_name = self._literal(value, "include_role")
        if not role_name.startswith(LOCAL_ROLE_PREFIX):
            raise GraphVerificationError("external or short role names are prohibited")
        short_name = role_name[len(LOCAL_ROLE_PREFIX):]
        if not short_name or "." in short_name or "/" in short_name:
            raise GraphVerificationError("role name is malformed")
        return short_name

    def _visit_role(self, role_value: object, tasks_from: str = "main.yml") -> None:
        short_name = self._role_name(role_value)
        role_root = self.root / "roles" / short_name
        task_target = self._resolve_relative(
            role_root / "tasks",
            tasks_from,
            "role task entrypoint",
        )
        self._visit_task_file(task_target)
        handlers = role_root / "handlers" / "main.yml"
        if handlers.exists():
            self._visit_task_file(self._inside(handlers, "role handlers"))
        metadata = role_root / "meta" / "main.yml"
        if metadata.exists():
            self._visit_role_metadata(self._inside(metadata, "role metadata"))

    def _visit_role_metadata(self, path: Path) -> None:
        if not self._start(path):
            return
        metadata = self._load(path, dict)
        unknown = set(metadata) - {
            "dependencies",
            "galaxy_info",
            "allow_duplicates",
            "argument_specs",
        }
        if unknown:
            raise GraphVerificationError(
                f"unsupported role metadata keys: {sorted(unknown)}"
            )
        dependencies = metadata.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise GraphVerificationError("role dependencies must be a list")
        for dependency in dependencies:
            if isinstance(dependency, str):
                role_name = dependency
            elif isinstance(dependency, dict):
                if set(dependency) != {"role"}:
                    raise GraphVerificationError(
                        "role dependency must contain only literal role"
                    )
                role_name = dependency["role"]
            else:
                raise GraphVerificationError("role dependency is not literal")
            self._visit_role(role_name)
        self._finish(path)

    def _visit_task_file(
        self,
        path: Path,
        source: Path | None = None,
        edge_task: dict[str, Any] | None = None,
    ) -> None:
        if path in self.active:
            self._validate_recursion_edge(source, path, edge_task)
            return
        if not self._start(path):
            return
        self._visit_tasks(self._load(path, list), path)
        self._finish(path)

    def _validate_recursion_edge(
        self,
        source: Path | None,
        target: Path,
        task: dict[str, Any] | None,
    ) -> None:
        if source is None or task is None or source != target:
            raise GraphVerificationError("unapproved active traversal cycle")
        relative = str(target.relative_to(self.root))
        expected_guard = PAGINATION_RECURSION_GUARDS.get(relative)
        if expected_guard is None:
            raise GraphVerificationError("unapproved task self-recursion")
        if task.get("when") != [expected_guard]:
            raise GraphVerificationError(
                f"{relative} recursion must use its exact pagination guard"
            )

    def _visit_tasks(self, tasks: object, source: Path) -> None:
        if not isinstance(tasks, list):
            raise GraphVerificationError("task section must be a list")
        for index, task in enumerate(tasks):
            if not isinstance(task, dict):
                raise GraphVerificationError(f"{source}: task {index} is not a mapping")
            if "action" in task or "local_action" in task:
                raise GraphVerificationError("alternate action syntax is prohibited")
            block_keys = set(task) & BLOCK_KEYS
            if block_keys:
                action_keys = set(task) - TASK_METADATA - BLOCK_KEYS
                if action_keys:
                    raise GraphVerificationError("block cannot also invoke an action")
                for block_key in BLOCK_KEYS:
                    self._visit_tasks(task.get(block_key, []), source)
                continue
            action_keys = set(task) - TASK_METADATA
            if len(action_keys) != 1:
                raise GraphVerificationError(
                    f"{source}: task must have exactly one FQCN action"
                )
            action = next(iter(action_keys))
            if action not in self.approved_actions:
                raise GraphVerificationError(f"unapproved action: {action}")
            self._record(action)
            value = task[action]
            if action in INCLUDE_TASK_ACTIONS:
                target = self._include_file(value)
                self._visit_task_file(
                    self._resolve_relative(source.parent, target, action),
                    source=source,
                    edge_task=task,
                )
            elif action in INCLUDE_ROLE_ACTIONS:
                role_name, tasks_from = self._include_role(value)
                self._visit_role(role_name, tasks_from)
            elif action == "ansible.builtin.import_playbook":
                raise GraphVerificationError("import_playbook is only valid at play level")
            elif not isinstance(value, dict):
                raise GraphVerificationError(
                    f"approved action {action} must use mapping arguments"
                )

    def _include_file(self, value: object) -> str:
        if isinstance(value, str):
            return self._literal(value, "include_tasks")
        if not isinstance(value, dict) or set(value) != {"file"}:
            raise GraphVerificationError(
                "include_tasks must contain only one literal file"
            )
        return self._literal(value["file"], "include_tasks")

    def _include_role(self, value: object) -> tuple[str, str]:
        if not isinstance(value, dict) or "name" not in value:
            raise GraphVerificationError("include_role must name one literal role")
        if set(value) - {"name", "tasks_from"}:
            raise GraphVerificationError("include_role contains unsupported keys")
        role_name = self._literal(value["name"], "include_role")
        tasks_from = self._literal(value.get("tasks_from", "main.yml"), "tasks_from")
        target = Path(tasks_from)
        if target.is_absolute() or ".." in target.parts:
            raise GraphVerificationError("tasks_from cannot escape its role")
        if target.suffix == "":
            target = target.with_suffix(".yml")
        return role_name, str(target)

    def _record(self, action: str) -> None:
        self.actions.append(action)


def verify_live_graph(collection_root: Path) -> GraphReport:
    """Verify the shipped constrained executor."""

    return GraphVerifier(collection_root).verify()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--collection-root",
        type=Path,
        default=Path.cwd(),
    )
    args = parser.parse_args()
    report = verify_live_graph(args.collection_root)
    print(
        "verified live read-only graph: "
        f"{len(report.files)} files, "
        f"{len(report.actions)} actions, "
        f"{report.action_occurrences} occurrences"
    )


if __name__ == "__main__":
    main()
