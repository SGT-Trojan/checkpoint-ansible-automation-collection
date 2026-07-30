from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import copy
import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = (
    Path(__file__).resolve().parents[4]
    / "plugins"
    / "module_utils"
    / "deployment_agent_package.py"
)
SPEC = importlib.util.spec_from_file_location("deployment_agent_package", MODULE)
assert SPEC and SPEC.loader
binding = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = binding
SPEC.loader.exec_module(binding)

PACKAGE_NAME = "DeploymentAgent_00002771.tgz"
PACKAGE_PATH = f"/srv/checkpoint/packages/{PACKAGE_NAME}"
SHA256 = "a" * 64


def package_step() -> dict:
    return {
        "name": "update_deployment_agent",
        "action": "upgrade",
        "package_type": "deployment_agent",
        "package_name": PACKAGE_NAME,
        "target_ids": ["member-a", "member-b"],
        "requires_present": [],
        "requires_absent": [],
        "source_path": PACKAGE_PATH,
        "checksum_sha256": SHA256,
        "artifact_size": 8192,
    }


class DeploymentAgentPackageTests(unittest.TestCase):
    def bind(self, step=None, required=2771, expected=2771):
        return binding.bind_deployment_agent_package(
            package_step() if step is None else step,
            required,
            expected,
        )

    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(binding.DeploymentAgentPackageError) as caught:
            call()
        self.assertEqual(caught.exception.category, category)

    def test_exact_package_and_build_binding_passes(self) -> None:
        result = self.bind()
        self.assertEqual(result["operation"], "installer_agent_install")
        self.assertEqual(result["plan_action"], "upgrade")
        self.assertEqual(result["target_ids"], ["member-a", "member-b"])
        self.assertEqual(result["required_build"], 2771)
        self.assertEqual(result["expected_build"], 2771)
        self.assertRegex(result["binding_sha256"], r"^[0-9a-f]{64}$")

    def test_binding_digest_is_stable_and_covers_the_contract(self) -> None:
        first = self.bind()
        self.assertEqual(first, self.bind())
        changed = package_step()
        changed["target_ids"].reverse()
        self.assertNotEqual(
            first["binding_sha256"],
            self.bind(step=changed)["binding_sha256"],
        )

    def test_install_and_upgrade_map_to_the_fixed_install_operation(self) -> None:
        for action in ("install", "upgrade"):
            step = package_step()
            step["action"] = action
            with self.subTest(action=action):
                result = self.bind(step=step)
                self.assertEqual(result["operation"], "installer_agent_install")
                self.assertEqual(result["plan_action"], action)

    def test_remove_and_other_actions_fail_closed(self) -> None:
        for action in ("remove", "update", "INSTALL", "", " upgrade", 17, None):
            step = package_step()
            step["action"] = action
            with self.subTest(action=action):
                self.assert_category(
                    "ACTION_INVALID",
                    lambda step=step: self.bind(step=step),
                )

    def test_only_deployment_agent_package_type_is_accepted(self) -> None:
        for package_type in ("hotfix", "jhf", "Deployment_Agent", ""):
            step = package_step()
            step["package_type"] = package_type
            with self.subTest(package_type=package_type):
                self.assert_category(
                    "PACKAGE_TYPE_INVALID",
                    lambda step=step: self.bind(step=step),
                )

    def test_step_must_have_the_exact_normalized_shape(self) -> None:
        for mutation in ("missing", "extra"):
            step = package_step()
            if mutation == "missing":
                step.pop("artifact_size")
            else:
                step["command"] = "prohibited"
            with self.subTest(mutation=mutation):
                self.assert_category(
                    "BINDING_INVALID",
                    lambda step=step: self.bind(step=step),
                )

    def test_source_path_and_name_must_identify_one_canonical_file(self) -> None:
        for path, name in (
            ("relative/package.tgz", "package.tgz"),
            ("//srv/package.tgz", "package.tgz"),
            ("/srv/../package.tgz", "package.tgz"),
            ("/srv//package.tgz", "package.tgz"),
            ("/srv/packages/", "packages"),
            (PACKAGE_PATH, "different.tgz"),
        ):
            step = package_step()
            step["source_path"] = path
            step["package_name"] = name
            with self.subTest(path=path, name=name):
                self.assert_category(
                    "PACKAGE_IDENTITY_INVALID",
                    lambda step=step: self.bind(step=step),
                )

    def test_checksum_must_be_normalized_lowercase_sha256(self) -> None:
        for digest in ("A" * 64, "a" * 63, "g" * 64, 64):
            step = package_step()
            step["checksum_sha256"] = digest
            with self.subTest(digest=digest):
                self.assert_category(
                    "CHECKSUM_INVALID",
                    lambda step=step: self.bind(step=step),
                )

    def test_artifact_size_must_be_positive_integer(self) -> None:
        for size in (0, -1, True, 1.5, "8192"):
            step = package_step()
            step["artifact_size"] = size
            with self.subTest(size=size):
                self.assert_category(
                    "PACKAGE_IDENTITY_INVALID",
                    lambda step=step: self.bind(step=step),
                )

    def test_exactly_two_unique_normalized_targets_are_required(self) -> None:
        for targets, category in (
            ([], "TARGET_INVALID"),
            (["member-a"], "TARGET_INVALID"),
            (["member-a", "member-a"], "BINDING_AMBIGUOUS"),
            (["member-a", "member-b", "member-c"], "TARGET_INVALID"),
            (["member-a", " member-b"], "BINDING_INVALID"),
        ):
            step = package_step()
            step["target_ids"] = targets
            with self.subTest(targets=targets):
                self.assert_category(
                    category,
                    lambda step=step: self.bind(step=step),
                )

    def test_prerequisite_lists_must_remain_normalized(self) -> None:
        for field in ("requires_present", "requires_absent"):
            for value, category in (
                ("Package", "BINDING_INVALID"),
                (["Package", "Package"], "BINDING_AMBIGUOUS"),
                ([" Package"], "BINDING_INVALID"),
            ):
                step = package_step()
                step[field] = value
                with self.subTest(field=field, value=value):
                    self.assert_category(
                        category,
                        lambda step=step: self.bind(step=step),
                    )

    def test_identity_text_rejects_non_printable_characters(self) -> None:
        for field, value in (
            ("name", "update\tdeployment_agent"),
            ("package_name", "DeploymentAgent_\x1b.tgz"),
            (
                "source_path",
                "/srv/checkpoint/packages/\tDeploymentAgent_00002771.tgz",
            ),
            ("target_ids", ["member-a", "member-\x7fb"]),
            ("requires_present", ["Package\x0bName"]),
        ):
            step = package_step()
            step[field] = value
            with self.subTest(field=field):
                self.assert_category(
                    "BINDING_INVALID",
                    lambda step=step: self.bind(step=step),
                )

    def test_builds_are_numeric_bounded_and_exact_expected_is_mandatory(self) -> None:
        for required, expected in (
            (0, 2771),
            (True, 2771),
            ("2771", 2771),
            (2771, None),
            (2771, True),
            (2771, 0),
            (2771, 2770),
            (2771, binding.MAX_BUILD + 1),
        ):
            with self.subTest(required=required, expected=expected):
                self.assert_category(
                    "BUILD_INVALID",
                    lambda required=required, expected=expected: self.bind(
                        required=required,
                        expected=expected,
                    ),
                )

    def test_input_is_not_modified(self) -> None:
        step = package_step()
        original = copy.deepcopy(step)
        self.bind(step=step)
        self.assertEqual(step, original)


if __name__ == "__main__":
    unittest.main()
