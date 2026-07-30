from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = (
    Path(__file__).resolve().parents[4]
    / "plugins"
    / "module_utils"
    / "deployment_agent.py"
)
SPEC = importlib.util.spec_from_file_location("deployment_agent", MODULE)
assert SPEC and SPEC.loader
deployment_agent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = deployment_agent
SPEC.loader.exec_module(deployment_agent)


def status(
    *,
    agent: str = "Enabled",
    build: str = "2771",
    note: str = "agent build is up to date",
) -> str:
    return (
        "Agent:              {0}\n"
        "Build number:       {1} ({2})\n"
        "Network connection: connected\n"
        "Update from cloud:  unavailable\n"
        "License:            status omitted\n"
    ).format(agent, build, note)


class DeploymentAgentParserTests(unittest.TestCase):
    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(deployment_agent.DeploymentAgentError) as caught:
            call()
        self.assertEqual(caught.exception.category, category)

    def test_parses_only_normalized_non_secret_state(self) -> None:
        self.assertEqual(
            deployment_agent.parse_status(status()),
            {
                "enabled": True,
                "build": 2771,
                "cloud_state": "current",
            },
        )

    def test_cloud_note_does_not_control_numeric_build(self) -> None:
        observation = deployment_agent.parse_status(
            status(build="2672", note="agent build is up to date")
        )
        decision = deployment_agent.decide(observation, 2771)
        self.assertFalse(decision["ready"])
        self.assertTrue(decision["requires_update"])
        self.assertIn("below the required minimum", decision["reasons"][0])

    def test_update_available_and_unknown_notes_are_bounded_states(self) -> None:
        available = deployment_agent.parse_status(
            status(note="a newer build is available")
        )
        unknown = deployment_agent.parse_status(
            status(note="status wording changed")
        )
        self.assertEqual(available["cloud_state"], "update_available")
        self.assertEqual(unknown["cloud_state"], "unknown")
        self.assertTrue(deployment_agent.decide(available, 2771)["ready"])
        self.assertTrue(deployment_agent.decide(unknown, 2771)["ready"])

    def test_disabled_agent_fails_readiness_without_requesting_update(self) -> None:
        decision = deployment_agent.decide(
            deployment_agent.parse_status(status(agent="Disabled")),
            2771,
        )
        self.assertFalse(decision["ready"])
        self.assertFalse(decision["requires_update"])
        self.assertEqual(decision["reasons"], ["Deployment Agent is disabled"])

    def test_expected_build_is_exact(self) -> None:
        observation = deployment_agent.parse_status(status(build="2772"))
        decision = deployment_agent.decide(observation, 2771, 2771)
        self.assertFalse(decision["ready"])
        self.assertFalse(decision["requires_update"])
        self.assertEqual(decision["expected_build"], 2771)
        self.assertIn("does not match", decision["reasons"][0])
        self.assertTrue(
            deployment_agent.decide(
                deployment_agent.parse_status(status()),
                2771,
                2771,
            )["ready"]
        )

    def test_duplicate_or_missing_required_fields_fail_closed(self) -> None:
        for output in (
            status() + "Build number: 2771\n",
            status() + "Agent: Enabled\n",
            status().replace("Build number:", "Build:"),
            status().replace("Agent:", "State:"),
        ):
            with self.subTest(output=output):
                self.assert_category(
                    "STATUS_AMBIGUOUS",
                    lambda output=output: deployment_agent.parse_status(output),
                )

    def test_build_and_agent_syntax_are_strict(self) -> None:
        for output in (
            status(build="0"),
            status(build="-1"),
            status(build="2771.0"),
            status(agent="enabled"),
            status(agent="Unknown"),
            status().replace("(agent build is up to date)", "(nested (note))"),
        ):
            with self.subTest(output=output):
                self.assert_category(
                    "STATUS_FORMAT",
                    lambda output=output: deployment_agent.parse_status(output),
                )

    def test_malformed_duplicate_fields_fail_closed(self) -> None:
        for output in (
            status() + "Build number: abc\n",
            status() + "Agent: Unknown\n",
        ):
            with self.subTest(output=output):
                self.assert_category(
                    "STATUS_FORMAT",
                    lambda output=output: deployment_agent.parse_status(output),
                )

    def test_input_size_line_count_line_length_and_controls_are_bounded(self) -> None:
        cases = (
            ("x" * (deployment_agent.MAX_STATUS_BYTES + 1), "STATUS_TOO_LARGE"),
            (
                "\n".join(["x"] * (deployment_agent.MAX_STATUS_LINES + 1)),
                "STATUS_TOO_LARGE",
            ),
            ("x" * (deployment_agent.MAX_LINE_LENGTH + 1), "STATUS_TOO_LARGE"),
            (status() + "\x00", "STATUS_CONTROL"),
            (status() + "\x1b", "STATUS_CONTROL"),
            (status() + "\x7f", "STATUS_CONTROL"),
            (status() + "\x85", "STATUS_CONTROL"),
            (status() + "\u2028", "STATUS_CONTROL"),
            (status() + "\ud800", "STATUS_CONTROL"),
        )
        for output, category in cases:
            with self.subTest(category=category):
                self.assert_category(
                    category,
                    lambda output=output: deployment_agent.parse_status(output),
                )

    def test_non_text_and_non_ascii_digits_fail_closed(self) -> None:
        self.assert_category(
            "STATUS_INVALID",
            lambda: deployment_agent.parse_status({"Build number": 2771}),
        )
        self.assert_category(
            "STATUS_FORMAT",
            lambda: deployment_agent.parse_status(status(build="٢٧٧١")),
        )

    def test_multibyte_input_is_bounded_by_encoded_bytes(self) -> None:
        output = status() + "\n".join(["\U0001f600" * 100] * 100)
        self.assertLess(max(len(line) for line in output.splitlines()), 1024)
        self.assertLess(len(output.splitlines()), 256)
        self.assertGreater(len(output.encode("utf-8")), 32768)
        self.assert_category(
            "STATUS_TOO_LARGE",
            lambda: deployment_agent.parse_status(output),
        )

    def test_decision_rejects_untyped_or_extra_observation_fields(self) -> None:
        valid = {
            "enabled": True,
            "build": 2771,
            "cloud_state": "current",
        }
        hostile = (
            {**valid, "extra": True},
            {**valid, "enabled": 1},
            {**valid, "build": True},
            {**valid, "build": 0},
            {**valid, "build": deployment_agent.MAX_BUILD + 1},
            {**valid, "cloud_state": "ready"},
            ["enabled", 2771],
        )
        for observation in hostile:
            with self.subTest(observation=observation):
                self.assert_category(
                    "DECISION_INVALID",
                    lambda observation=observation: deployment_agent.decide(
                        observation,
                        2771,
                    ),
                )

    def test_decision_build_bounds_fail_closed(self) -> None:
        observation = deployment_agent.parse_status(status())
        for required, expected in (
            (True, None),
            (0, None),
            ("2771", None),
            (deployment_agent.MAX_BUILD + 1, None),
            (2771, True),
            (2771, 0),
            (2771, 2672),
            (2771, deployment_agent.MAX_BUILD + 1),
        ):
            with self.subTest(required=required, expected=expected):
                self.assert_category(
                    "DECISION_INVALID",
                    lambda required=required, expected=expected: deployment_agent.decide(
                        observation,
                        required,
                        expected,
                    ),
                )


if __name__ == "__main__":
    unittest.main()
