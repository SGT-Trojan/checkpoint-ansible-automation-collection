from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
TASKS = (
    ROOT
    / "roles"
    / "checkpoint_package_state_acquisition"
    / "tasks"
    / "main.yml"
)
EXECUTOR = ROOT / "playbooks" / "live_readonly_package_state.yml"
GUIDE = ROOT / "docs" / "LIVE_READONLY_EXECUTOR.md"
PREFLIGHT = (
    "sgt_trojan.checkpoint_automation."
    "cp_automation_package_state_live_preflight"
)


class PackageStateLiveOrchestrationTests(unittest.TestCase):
    def test_every_network_request_is_immediately_preflighted(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        requests = (
            "check_point.gaia.cp_gaia_features_facts",
            (
                "sgt_trojan.checkpoint_automation."
                "cp_automation_package_state_acquire"
            ),
        )
        for request in requests:
            index = next(
                index
                for index, task in enumerate(tasks)
                if request in task
            )
            self.assertGreater(index, 0)
            gate = tasks[index - 1]
            self.assertIn(PREFLIGHT, gate)
            self.assertTrue(gate["no_log"])
            self.assertEqual(gate["delegate_to"], "localhost")
            self.assertEqual(gate["connection"], "ansible.builtin.local")
            self.assertFalse(gate["become"])
            self.assertNotIn("executor_check_mode", gate[PREFLIGHT])
            self.assertEqual(
                gate[PREFLIGHT]["tls_validation_enabled"],
                "{{ ansible_httpapi_validate_certs }}",
            )
            self.assertIn(
                "checkpoint_package_state_lab_tls_exception_acknowledged",
                gate[PREFLIGHT]["lab_tls_exception_acknowledged"],
            )

    def test_role_rejects_proxy_targets_and_binds_validated_expiry(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        controls = str(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("ansible_checkpoint_target is not defined", controls)
        module_name = (
            "sgt_trojan.checkpoint_automation."
            "cp_automation_package_state_acquire"
        )
        acquisition = next(task for task in tasks if module_name in task)
        arguments = acquisition[module_name]
        self.assertIn(
            "checkpoint_package_state_acquisition_authorization",
            arguments["authorization_expires_at"],
        )
        second_gate = tasks[tasks.index(acquisition) - 1]
        self.assertEqual(
            second_gate["register"],
            "checkpoint_package_state_acquisition_authorization",
        )

    def test_live_executor_derives_exact_group_and_runs_serially(self) -> None:
        plays = yaml.safe_load(EXECUTOR.read_text(encoding="utf-8"))
        self.assertEqual(len(plays), 2)
        self.assertEqual(plays[0]["hosts"], "localhost")
        self.assertFalse(plays[0]["gather_facts"])
        self.assertTrue(plays[0]["any_errors_fatal"])
        first_tasks = plays[0]["tasks"]
        conditions = str(first_tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("checkpoint_package_state_members", conditions)
        self.assertIn("length == 2", conditions)
        target_fact = first_tasks[1]["ansible.builtin.set_fact"]
        self.assertIn(
            "map(\"extract\", hostvars, \"ansible_host\")",
            str(target_fact),
        )
        self.assertTrue(first_tasks[1]["no_log"])
        self.assertFalse(first_tasks[1]["changed_when"])
        self.assertEqual(
            plays[1]["hosts"],
            "checkpoint_package_state_members",
        )
        self.assertEqual(plays[1]["serial"], 1)
        self.assertTrue(plays[1]["any_errors_fatal"])
        self.assertIn(
            "checkpoint_package_state_acquisition",
            str(plays[1]["roles"]),
        )

    def test_role_computes_presence_flags_without_passing_values(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        presence = next(
            task
            for task in tasks
            if task.get("name")
            == "Resolve Gaia credential-presence flags without copying values"
        )
        self.assertTrue(presence["no_log"])
        value = presence["ansible.builtin.set_fact"][
            "checkpoint_package_state_credential_presence"
        ]
        self.assertEqual(set(value), {"gaia_username", "gaia_secret"})
        self.assertIn("ansible_user | trim | length > 0", value["gaia_username"])
        self.assertIn("ansible_password | trim | length > 0", value["gaia_secret"])
        preflights = [task for task in tasks if PREFLIGHT in task]
        self.assertEqual(len(preflights), 2)
        for task in preflights:
            arguments = task[PREFLIGHT]
            self.assertEqual(
                arguments["credential_presence"],
                "{{ checkpoint_package_state_credential_presence }}",
            )
            self.assertNotIn("ansible_password", str(arguments))

    def test_tls_mode_documentation_keeps_lab_exception_explicit(self) -> None:
        content = GUIDE.read_text(encoding="utf-8")
        normalized = " ".join(content.split())
        for required in (
            "tls_validation_mode: strict",
            "LAB ONLY - do not use for production",
            "ansible_httpapi_validate_certs: false",
            "checkpoint_package_state_lab_tls_exception_acknowledged: true",
            "tls_validation_mode: lab_unverified",
            "Server identity and MITM protection are absent",
            "Certificate validation remains a required pending live test",
            "planned lab run will use a shorter 12-minute lease",
        ):
            self.assertIn(required, normalized)

    def test_role_requires_localhost_and_exact_two_member_lease_inputs(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        controls = str(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("checkpoint_package_state_live_lease is mapping", controls)
        self.assertIn("tls_validation_mode", controls)
        self.assertIn("strict", controls)
        self.assertIn("lab_unverified", controls)
        self.assertIn("ansible_httpapi_validate_certs is boolean", controls)
        self.assertIn("is sameas true", controls)
        self.assertIn("is sameas false", controls)
        self.assertIn(
            "checkpoint_package_state_lab_tls_exception_acknowledged",
            controls,
        )
        self.assertIn(
            "checkpoint_package_state_live_member_targets | length == 2",
            controls,
        )
        self.assertIn('hostvars["localhost"].ansible_connection', controls)
        self.assertIn('hostvars["localhost"].ansible_host', controls)


if __name__ == "__main__":
    unittest.main()
