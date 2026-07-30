from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = ROOT / "playbooks" / "resolve_managed_cluster.yml"
ROLE_ROOT = ROOT / "roles"


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def yaml_files() -> list[Path]:
    return [PLAYBOOK, *sorted(ROLE_ROOT.rglob("*.yml"))]


class DiscoveryOrchestrationTests(unittest.TestCase):
    def test_playbook_has_exact_four_play_workflow(self) -> None:
        plays = load_yaml(PLAYBOOK)
        self.assertEqual(len(plays), 4)
        self.assertEqual(
            [play["hosts"] for play in plays],
            [
                "checkpoint_mds_system",
                "localhost",
                "checkpoint_domain_sessions",
                "localhost",
            ],
        )

    def test_exactly_one_system_data_alias_is_required(self) -> None:
        first_play = load_yaml(PLAYBOOK)[0]
        guard = first_play["pre_tasks"][0]["ansible.builtin.assert"]
        self.assertIn(
            "groups.checkpoint_mds_system | length == 1",
            guard["that"],
        )

    def test_domain_aggregation_does_not_assume_domain_uid(self) -> None:
        inventory_role = (
            ROLE_ROOT / "checkpoint_domain_inventory" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        resolution_role = (
            ROLE_ROOT / "checkpoint_target_resolution" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("checkpoint_domain_record.uid", inventory_role)
        self.assertIn('map(attribute="name")', resolution_role)
        self.assertNotIn('map(attribute="uid")', resolution_role)

    def test_exact_supported_and_custom_fqcns_are_present(self) -> None:
        content = "\n".join(path.read_text(encoding="utf-8") for path in yaml_files())
        for fqcn in (
            "check_point.mgmt.cp_mgmt_domain_facts:",
            "check_point.mgmt.cp_mgmt_show_gateways_and_servers:",
            "check_point.mgmt.cp_mgmt_simple_cluster_facts:",
            "sgt_trojan.checkpoint_automation.cp_automation_pages_merge:",
            "sgt_trojan.checkpoint_automation.cp_automation_domain_plan:",
            "sgt_trojan.checkpoint_automation.cp_automation_target_resolve:",
        ):
            self.assertIn(fqcn, content)

    def test_forbidden_execution_paths_are_absent(self) -> None:
        content = "\n".join(path.read_text(encoding="utf-8") for path in yaml_files())
        for forbidden in (
            "domains_to_process",
            "ansible.builtin.command:",
            "ansible.builtin.shell:",
            "ansible.builtin.raw:",
            "ansible.builtin.script:",
            "run-script",
            "run_script",
        ):
            self.assertNotIn(forbidden, content)

    def test_dynamic_hosts_isolate_domain_sessions_without_secrets(self) -> None:
        plays = load_yaml(PLAYBOOK)
        add_host_tasks = [
            task
            for task in plays[1]["tasks"]
            if "ansible.builtin.add_host" in task
        ]
        domain_host = add_host_tasks[0]["ansible.builtin.add_host"]
        self.assertEqual(domain_host["name"], "{{ item.session_name }}")
        self.assertIn("checkpoint_mds_api_host", domain_host["ansible_host"])
        self.assertIn("checkpoint_mds_system", domain_host["ansible_host"])
        self.assertEqual(
            domain_host["ansible_checkpoint_domain"], "{{ item.name }}"
        )
        self.assertEqual(domain_host["checkpoint_domain_record"], "{{ item.domain }}")
        self.assertIn("checkpoint_domain_sessions", domain_host["groups"])
        self.assertIn("{{ checkpoint_api_sessions_group }}", domain_host["groups"])
        serialized = yaml.safe_dump(domain_host)
        for secret_name in (
            "ansible_user",
            "ansible_password",
            "ansible_httpapi_pass",
            "api_key",
            "api-key",
        ):
            self.assertNotIn(secret_name, serialized)

    def test_pagination_recurses_by_actual_returned_rows(self) -> None:
        cases = (
            (
                ROLE_ROOT / "checkpoint_mds_domains" / "tasks" / "fetch_page.yml",
                "checkpoint_domain_next_offset",
                "checkpoint_domain_returned_rows",
            ),
            (
                ROLE_ROOT
                / "checkpoint_domain_inventory"
                / "tasks"
                / "fetch_gateways_page.yml",
                "checkpoint_gateway_next_offset",
                "checkpoint_gateway_returned_rows",
            ),
            (
                ROLE_ROOT
                / "checkpoint_domain_inventory"
                / "tasks"
                / "fetch_clusters_page.yml",
                "checkpoint_cluster_next_offset",
                "checkpoint_cluster_returned_rows",
            ),
        )
        for path, offset, row_count in cases:
            tasks = load_yaml(path)
            content = path.read_text(encoding="utf-8")
            recursive = [
                task
                for task in tasks
                if task.get("ansible.builtin.include_tasks") == path.name
            ]
            self.assertEqual(len(recursive), 1, path)
            self.assertIn(f"{offset} | int\n      + {row_count} | int", content)
            self.assertIn("returned zero rows before", content)

    def test_cluster_detail_uid_must_exactly_match_summary(self) -> None:
        path = (
            ROLE_ROOT
            / "checkpoint_domain_inventory"
            / "tasks"
            / "fetch_cluster_detail.yml"
        )
        content = path.read_text(encoding="utf-8")
        self.assertIn(
            "checkpoint_cluster_detail_response.uid == "
            "checkpoint_cluster_summary.uid",
            content,
        )
        self.assertIn("details_level: full", content)
        self.assertIn("name: \"{{ checkpoint_cluster_summary.name }}\"", content)

    def test_vendor_check_mode_policy_is_explicit(self) -> None:
        overrides: list[tuple[Path, dict]] = []
        for path in yaml_files():
            document = load_yaml(path)
            task_lists = []
            if path == PLAYBOOK:
                task_lists.extend(play.get("tasks", []) for play in document)
            else:
                task_lists.append(document)
            for tasks in task_lists:
                for task in tasks:
                    if "check_mode" in task:
                        overrides.append((path, task))
        observed = {
            key: task["check_mode"]
            for _path, task in overrides
            for key in task
            if key.startswith("check_point.mgmt.")
        }
        self.assertEqual(
            observed,
            {
                "check_point.mgmt.cp_mgmt_domain_facts": True,
                "check_point.mgmt.cp_mgmt_show_gateways_and_servers": False,
                "check_point.mgmt.cp_mgmt_simple_cluster_facts": True,
            },
        )

    def test_every_api_session_requires_tls_and_bounded_pages(self) -> None:
        for role in ("checkpoint_mds_domains", "checkpoint_domain_inventory"):
            content = (
                ROLE_ROOT / role / "tasks" / "main.yml"
            ).read_text(encoding="utf-8")
            self.assertIn("ansible_httpapi_use_ssl | bool", content)
            self.assertIn("ansible_httpapi_validate_certs | bool", content)
            self.assertIn("checkpoint_page_size | int > 0", content)
            self.assertIn("checkpoint_page_size | int <= 500", content)

    def test_domain_concurrency_uses_coordinator_host_context(self) -> None:
        plays = load_yaml(PLAYBOOK)
        serial = plays[2]["serial"]
        self.assertIn("hostvars[groups.checkpoint_mds_system | first]", serial)
        self.assertIn("checkpoint_domain_concurrency | default(4)", serial)

    def test_registered_results_and_fail_closed_guards_are_explicit(self) -> None:
        content = "\n".join(path.read_text(encoding="utf-8") for path in yaml_files())
        for registered in (
            "register: checkpoint_domain_page_result",
            "register: checkpoint_gateway_page_result",
            "register: checkpoint_cluster_page_result",
            "register: checkpoint_cluster_detail_result",
        ):
            self.assertIn(registered, content)
        self.assertIn("Reject incomplete domain result aggregation", content)
        self.assertIn("checkpoint_expected_domain_count", content)

    def test_ci_syntax_checks_discovery_playbook_with_vendor_pins(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("ansible-galaxy collection install -r requirements.yml", workflow)
        self.assertIn("playbooks/resolve_managed_cluster.yml --syntax-check", workflow)
        self.assertIn("tests/integration/discovery_variable_scope.yml", workflow)
        self.assertIn('ansible_core: ["2.16.*", "2.21.*"]', workflow)


if __name__ == "__main__":
    unittest.main()
