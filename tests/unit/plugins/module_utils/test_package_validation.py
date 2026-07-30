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
    / "package_validation.py"
)
SPEC = importlib.util.spec_from_file_location("checkpoint_package_validation", MODULE)
assert SPEC and SPEC.loader
validation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validation
SPEC.loader.exec_module(validation)

PACKAGE_NAME = "Check_Point_package.tgz"
PACKAGE_PATH = f"/srv/packages/{PACKAGE_NAME}"
SHA256 = "a" * 64


def install_step() -> dict:
    return {
        "name": "install_current_bundle",
        "action": "install",
        "package_type": "hotfix",
        "package_name": PACKAGE_NAME,
        "source_path": PACKAGE_PATH,
        "checksum_sha256": SHA256.upper(),
        "target_ids": ["member-a", "member-b"],
        "requires_present": ["Base Image"],
        "requires_absent": ["Conflicting Bundle"],
    }


def artifact() -> dict:
    return {"path": PACKAGE_PATH, "size": 4096, "sha256": SHA256}


def targets() -> list[dict]:
    return [
        {
            "step_name": "install_current_bundle",
            "target_id": "member-a",
            "installed_packages": ["Base Image"],
            "installed_packages_complete": True,
            "restore_point_free_bytes": 80 * 1024**3,
        },
        {
            "step_name": "install_current_bundle",
            "target_id": "member-b",
            "installed_packages": ["Base Image"],
            "installed_packages_complete": True,
            "restore_point_free_bytes": 80 * 1024**3,
        },
    ]


class PackageValidationTests(unittest.TestCase):
    def validate(self, steps=None, artifacts=None, target_states=None):
        return validation.validate_package_contract(
            [install_step()] if steps is None else steps,
            [artifact()] if artifacts is None else artifacts,
            targets() if target_states is None else target_states,
        )

    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(validation.PackageValidationError) as caught:
            call()
        self.assertEqual(caught.exception.category, category)

    def test_install_identity_sha256_and_prerequisites_pass(self) -> None:
        result = self.validate()
        self.assertTrue(result["valid"])
        self.assertEqual(result["step_count"], 1)
        self.assertEqual(result["artifact_count"], 1)
        self.assertEqual(result["target_count"], 2)
        self.assertEqual(result["steps"][0]["checksum_sha256"], SHA256)
        self.assertEqual(result["steps"][0]["artifact_size"], 4096)

    def test_install_and_upgrade_require_exact_sha256(self) -> None:
        for action in ("install", "upgrade"):
            for digest in ("", "a" * 63, "g" * 64, 64):
                step = install_step()
                step["action"] = action
                step["checksum_sha256"] = digest
                with self.subTest(action=action, digest=digest):
                    self.assert_category(
                        "CHECKSUM_INVALID",
                        lambda step=step: self.validate(steps=[step]),
                    )

    def test_artifact_checksum_must_match(self) -> None:
        observed = artifact()
        observed["sha256"] = "b" * 64
        self.assert_category(
            "CHECKSUM_MISMATCH",
            lambda: self.validate(artifacts=[observed]),
        )

    def test_source_and_package_name_must_identify_same_file(self) -> None:
        step = install_step()
        step["package_name"] = "different.tgz"
        self.assert_category(
            "PACKAGE_IDENTITY_INVALID",
            lambda: self.validate(steps=[step]),
        )

    def test_source_path_is_absolute_canonical_and_bounded_to_file(self) -> None:
        for path in (
            "relative/package.tgz",
            "/srv/../package.tgz",
            "/srv//package.tgz",
            "/srv/packages/",
        ):
            step = install_step()
            step["source_path"] = path
            with self.subTest(path=path):
                self.assert_category(
                    "PACKAGE_IDENTITY_INVALID",
                    lambda step=step: self.validate(steps=[step]),
                )

    def test_artifact_must_be_exactly_present_once(self) -> None:
        self.assert_category(
            "ARTIFACT_MISSING",
            lambda: self.validate(artifacts=[]),
        )
        duplicate = [artifact(), artifact()]
        self.assert_category(
            "PACKAGE_AMBIGUOUS",
            lambda: self.validate(artifacts=duplicate),
        )

    def test_unused_artifact_is_rejected(self) -> None:
        extra = {
            "path": "/srv/packages/other.tgz",
            "size": 10,
            "sha256": "b" * 64,
        }
        self.assert_category(
            "PACKAGE_AMBIGUOUS",
            lambda: self.validate(artifacts=[artifact(), extra]),
        )

    def test_one_artifact_cannot_satisfy_multiple_steps(self) -> None:
        second = install_step()
        second["name"] = "install_again"
        self.assert_category(
            "PACKAGE_AMBIGUOUS",
            lambda: self.validate(
                steps=[install_step(), second],
                artifacts=[artifact()],
            ),
        )

    def test_artifact_size_is_positive_integer_not_boolean(self) -> None:
        for size in (0, -1, 1.5, True, "4096"):
            observed = artifact()
            observed["size"] = size
            with self.subTest(size=size):
                self.assert_category(
                    "INVALID_INPUT",
                    lambda observed=observed: self.validate(
                        artifacts=[observed]
                    ),
                )

    def test_remove_requires_explicit_package_identity_without_artifact(self) -> None:
        step = {
            "name": "remove_old_bundle",
            "action": "remove",
            "package_type": "hotfix",
            "package_name": "Old Bundle",
            "target_ids": ["member-a", "member-b"],
            "requires_present": ["Old Bundle"],
            "requires_absent": [],
        }
        state = targets()
        for target in state:
            target["step_name"] = "remove_old_bundle"
        for target in state:
            target["installed_packages"].append("Old Bundle")
        result = self.validate(
            steps=[step],
            artifacts=[],
            target_states=state,
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["artifact_count"], 0)

    def test_remove_rejects_step_name_artifact_and_checksum(self) -> None:
        base = {
            "name": "remove_old",
            "action": "remove",
            "package_type": "hotfix",
            "package_name": "remove_old",
            "target_ids": ["member-a", "member-b"],
        }
        self.assert_category(
            "PACKAGE_IDENTITY_INVALID",
            lambda: self.validate(steps=[base], artifacts=[], target_states=[]),
        )
        for field, value in (
            ("source_path", "/srv/packages/old.tgz"),
            ("checksum_sha256", SHA256),
        ):
            step = dict(base, package_name="Old Bundle")
            step[field] = value
            with self.subTest(field=field):
                self.assert_category(
                    "ACTION_INVALID",
                    lambda step=step: self.validate(
                        steps=[step],
                        artifacts=[],
                        target_states=[],
                    ),
                )

    def test_actions_are_exact_and_fail_closed(self) -> None:
        for action in ("uninstall", "INSTALL", "patch", "", None):
            step = install_step()
            step["action"] = action
            with self.subTest(action=action):
                self.assert_category(
                    "ACTION_INVALID",
                    lambda step=step: self.validate(steps=[step]),
                )

    def test_prerequisite_sets_are_exact_unique_and_disjoint(self) -> None:
        step = install_step()
        step["requires_present"] = ["Base Image", "Base Image"]
        self.assert_category(
            "PACKAGE_AMBIGUOUS",
            lambda: self.validate(steps=[step]),
        )
        step = install_step()
        step["requires_absent"] = ["Base Image"]
        self.assert_category(
            "PREREQUISITE_INVALID",
            lambda: self.validate(steps=[step]),
        )

    def test_present_and_absent_prerequisites_fail_closed(self) -> None:
        state = targets()
        state[0]["installed_packages"] = []
        self.assert_category(
            "PREREQUISITE_FAILED",
            lambda: self.validate(target_states=state),
        )
        state = targets()
        state[1]["installed_packages"].append("Conflicting Bundle")
        self.assert_category(
            "PREREQUISITE_FAILED",
            lambda: self.validate(target_states=state),
        )

    def test_prerequisites_require_target_observations(self) -> None:
        self.assert_category(
            "TARGET_MISMATCH",
            lambda: self.validate(target_states=[]),
        )

    def test_one_of_two_expected_targets_cannot_certify_step(self) -> None:
        self.assert_category(
            "TARGET_MISMATCH",
            lambda: self.validate(target_states=targets()[:1]),
        )

    def test_no_prerequisite_step_still_requires_exact_complete_targets(self) -> None:
        step = install_step()
        step["requires_present"] = []
        step["requires_absent"] = []
        self.assert_category(
            "TARGET_MISMATCH",
            lambda: self.validate(
                steps=[step],
                target_states=targets()[:1],
            ),
        )
        state = targets()
        state[0].pop("installed_packages_complete")
        self.assert_category(
            "INVENTORY_INCOMPLETE",
            lambda: self.validate(steps=[step], target_states=state),
        )

    def test_installed_package_inventory_requires_literal_complete_true(self) -> None:
        for value in (False, "true", 1, None):
            state = targets()
            if value is None:
                state[0].pop("installed_packages_complete")
            else:
                state[0]["installed_packages_complete"] = value
            with self.subTest(value=value):
                self.assert_category(
                    "INVENTORY_INCOMPLETE",
                    lambda state=state: self.validate(target_states=state),
                )

    def test_extra_target_observation_is_rejected(self) -> None:
        state = targets()
        state.append(
            {
                "step_name": "install_current_bundle",
                "target_id": "member-c",
                "installed_packages": ["Base Image"],
                "installed_packages_complete": True,
                "restore_point_free_bytes": 80 * 1024**3,
            }
        )
        self.assert_category(
            "TARGET_MISMATCH",
            lambda: self.validate(target_states=state),
        )

    def test_target_ids_are_required_nonempty_and_unique(self) -> None:
        for target_ids, category in (
            (None, "TARGET_INVALID"),
            ([], "TARGET_INVALID"),
            (["member-a", "member-a"], "PACKAGE_AMBIGUOUS"),
        ):
            step = install_step()
            if target_ids is None:
                step.pop("target_ids")
            else:
                step["target_ids"] = target_ids
            with self.subTest(target_ids=target_ids):
                self.assert_category(
                    category,
                    lambda step=step: self.validate(steps=[step]),
                )

    def test_target_and_package_identities_are_unique(self) -> None:
        state = targets()
        state[1]["target_id"] = state[0]["target_id"]
        self.assert_category(
            "PACKAGE_AMBIGUOUS",
            lambda: self.validate(target_states=state),
        )

    def test_target_observations_are_bound_to_the_exact_step(self) -> None:
        state = targets()
        state[0]["step_name"] = "different_step"
        self.assert_category(
            "TARGET_MISMATCH",
            lambda: self.validate(target_states=state),
        )
        no_prerequisites = install_step()
        no_prerequisites["requires_present"] = []
        no_prerequisites["requires_absent"] = []
        self.assert_category(
            "TARGET_MISMATCH",
            lambda: self.validate(
                steps=[no_prerequisites],
                target_states=[
                    {
                        "step_name": "unknown",
                        "target_id": "member-a",
                        "installed_packages": [],
                        "installed_packages_complete": True,
                    }
                ],
            ),
        )

    def test_package_type_is_conservative_and_exact(self) -> None:
        for package_type in ("other", "jumbo", "custom", "", None):
            step = install_step()
            step["package_type"] = package_type
            with self.subTest(package_type=package_type):
                expected = (
                    "INVALID_INPUT"
                    if package_type in ("", None)
                    else "PACKAGE_TYPE_INVALID"
                )
                self.assert_category(
                    expected,
                    lambda step=step: self.validate(steps=[step]),
                )

    def test_each_supported_non_major_package_type_is_accepted(self) -> None:
        for package_type in ("jhf", "hotfix", "deployment_agent", "wrapper"):
            step = install_step()
            step["package_type"] = package_type
            with self.subTest(package_type=package_type):
                self.assertTrue(self.validate(steps=[step])["valid"])

    def test_blink_identity_cannot_be_relabelled_non_major(self) -> None:
        for blink_name in (
            "Check_Point_Blink_image.tgz",
            "BlinkImage_R82.tgz",
            "BlinkR82.tgz",
            "package_prebLiNkpost_R82.tgz",
        ):
            blink_path = f"/srv/packages/{blink_name}"
            step = install_step()
            step.update(
                {
                    "package_type": "hotfix",
                    "package_name": blink_name,
                    "source_path": blink_path,
                }
            )
            observed = artifact()
            observed["path"] = blink_path
            with self.subTest(blink_name=blink_name):
                self.assert_category(
                    "PACKAGE_TYPE_INVALID",
                    lambda step=step, observed=observed: self.validate(
                        steps=[step],
                        artifacts=[observed],
                    ),
                )
        remove = {
            "name": "remove_blink",
            "action": "remove",
            "package_type": "wrapper",
            "package_name": "Blink image",
            "target_ids": ["member-a", "member-b"],
        }
        state = targets()
        for target in state:
            target["step_name"] = "remove_blink"
        self.assert_category(
            "PACKAGE_TYPE_INVALID",
            lambda: self.validate(
                steps=[remove],
                artifacts=[],
                target_states=state,
            ),
        )

    def test_normal_non_blink_identity_still_passes(self) -> None:
        step = install_step()
        step["package_name"] = "Check_Point_Hotfix_R82.tgz"
        step["source_path"] = "/srv/packages/Check_Point_Hotfix_R82.tgz"
        observed = artifact()
        observed["path"] = step["source_path"]
        self.assertTrue(
            self.validate(steps=[step], artifacts=[observed])["valid"]
        )
        state = targets()
        state[0]["installed_packages"] = ["Base Image", "Base Image"]
        self.assert_category(
            "PACKAGE_AMBIGUOUS",
            lambda: self.validate(target_states=state),
        )

    def test_major_upgrade_requires_capacity_on_every_target(self) -> None:
        for action in ("install", "upgrade"):
            step = install_step()
            step.update(
                {
                    "action": action,
                    "package_type": "blink",
                    "minimum_restore_point_bytes": 40 * 1024**3,
                }
            )
            with self.subTest(action=action):
                self.assertTrue(self.validate(steps=[step])["valid"])
            for available, category in (
                (None, "PREREQUISITE_INCOMPLETE"),
                (0, "PREREQUISITE_FAILED"),
                (20 * 1024**3, "PREREQUISITE_FAILED"),
            ):
                state = targets()
                state[1]["restore_point_free_bytes"] = available
                with self.subTest(action=action, available=available):
                    self.assert_category(
                        category,
                        lambda state=state, step=step: self.validate(
                            steps=[step],
                            target_states=state,
                        ),
                    )

    def test_restore_capacity_only_applies_to_major_upgrade(self) -> None:
        step = install_step()
        step["minimum_restore_point_bytes"] = 1
        self.assert_category(
            "PREREQUISITE_INVALID",
            lambda: self.validate(steps=[step]),
        )

    def test_unknown_fields_and_duplicate_step_names_are_rejected(self) -> None:
        step = install_step()
        step["command"] = "prohibited"
        self.assert_category(
            "INVALID_INPUT",
            lambda: self.validate(steps=[step]),
        )
        duplicate = [install_step(), copy.deepcopy(install_step())]
        self.assert_category(
            "PACKAGE_AMBIGUOUS",
            lambda: self.validate(steps=duplicate, artifacts=[artifact()]),
        )

    def test_identity_text_rejects_non_printable_characters(self) -> None:
        for field, value in (
            ("name", "install\tbundle"),
            ("package_name", "Check_Point_\x1bpackage.tgz"),
            ("source_path", "/srv/packages/\tCheck_Point_package.tgz"),
            ("target_ids", ["member-a", "member-\x7fb"]),
            ("requires_present", ["Base\x0bImage"]),
        ):
            step = install_step()
            step[field] = value
            with self.subTest(field=field):
                self.assert_category(
                    "INVALID_INPUT",
                    lambda step=step: self.validate(steps=[step]),
                )


if __name__ == "__main__":
    unittest.main()
