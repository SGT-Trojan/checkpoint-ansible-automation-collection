from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = (
    Path(__file__).resolve().parents[4]
    / "plugins"
    / "module_utils"
    / "live_preflight.py"
)
SPEC = importlib.util.spec_from_file_location("checkpoint_live_preflight", MODULE)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
LEASE_ID = "63c53f94-319d-444a-8c43-ec2584bcf985"
MANAGEMENT = "192.0.2.5"
MEMBERS = ["198.51.100.10", "198.51.100.11"]


def valid_lease() -> dict:
    return {
        "lease_id": LEASE_ID,
        "issued_at": "2026-07-29T11:55:00Z",
        "expires_at": "2026-07-29T12:05:00Z",
        "operation": "managed_discovery",
        "execution_mode": "read_only",
        "management_target": MANAGEMENT,
        "member_targets": list(MEMBERS),
    }


class LivePreflightTests(unittest.TestCase):
    def authorize(self, **overrides):
        values = {
            "lease": valid_lease(),
            "management_target": MANAGEMENT,
            "member_targets": list(MEMBERS),
            "credential_presence": {
                "management_username": True,
                "management_secret": True,
            },
            "check_mode": True,
            "now": NOW,
        }
        values.update(overrides)
        return preflight.authorize_live_readonly(**values)

    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(preflight.LivePreflightError) as caught:
            call()
        self.assertEqual(caught.exception.category, category)

    def test_authorizes_sanitized_exact_read_only_execution(self) -> None:
        result = self.authorize()
        self.assertTrue(result["authorized"])
        self.assertEqual(result["target_count"], 3)
        self.assertNotIn(MANAGEMENT, str(result))
        self.assertNotIn(MEMBERS[0], str(result))

    def test_check_mode_is_mandatory(self) -> None:
        for value in (False, None, 1, "true"):
            with self.subTest(value=value):
                self.assert_category(
                    "MUTATION_BLOCKED",
                    lambda value=value: self.authorize(check_mode=value),
                )

    def test_lease_has_exact_fields_and_uuid(self) -> None:
        hostile = (
            {},
            dict(valid_lease(), extra="not allowed"),
            dict(valid_lease(), lease_id="not-a-uuid"),
            dict(
                valid_lease(),
                lease_id="63c53f94-319d-1bba-8c43-ec2584bcf985",
            ),
        )
        for lease in hostile:
            with self.subTest(lease=lease):
                self.assert_category(
                    "LEASE_INVALID",
                    lambda lease=lease: self.authorize(lease=lease),
                )

    def test_only_read_only_managed_discovery_is_allowed(self) -> None:
        for field, value in (
            ("operation", "install_package"),
            ("operation", "cluster_readiness"),
            ("execution_mode", "mutating"),
            ("execution_mode", True),
        ):
            lease = valid_lease()
            lease[field] = value
            with self.subTest(field=field, value=value):
                self.assert_category(
                    "MUTATION_BLOCKED",
                    lambda lease=lease: self.authorize(lease=lease),
                )

    def test_lease_timestamps_are_utc_ordered_and_short(self) -> None:
        cases = (
            ("issued_at", "2026-07-29T11:55:00+00:00"),
            ("issued_at", "20260729T115500Z"),
            ("issued_at", "2026-07-29T11:55:00.1234567Z"),
            ("issued_at", "not-a-time"),
            ("issued_at", "2026-07-29T12:01:00Z"),
            ("expires_at", "2026-07-29T11:54:00Z"),
            ("expires_at", "2026-07-29T12:20:01Z"),
        )
        for field, value in cases:
            lease = valid_lease()
            lease[field] = value
            with self.subTest(field=field, value=value):
                self.assert_category(
                    "LEASE_INVALID",
                    lambda lease=lease: self.authorize(lease=lease),
                )

    def test_rfc3339_fractional_seconds_are_parser_version_independent(self) -> None:
        for issued_at in (
            "2026-07-29T11:55:00.1Z",
            "2026-07-29T11:55:00.12345Z",
            "2026-07-29T11:55:00.123456Z",
        ):
            lease = valid_lease()
            lease["issued_at"] = issued_at
            with self.subTest(issued_at=issued_at):
                self.assertTrue(self.authorize(lease=lease)["authorized"])
        self.assertNotIn("fromisoformat", MODULE.read_text(encoding="utf-8"))

    def test_expired_lease_is_rejected(self) -> None:
        lease = valid_lease()
        lease["expires_at"] = "2026-07-29T12:00:00Z"
        self.assert_category(
            "LEASE_EXPIRED",
            lambda: self.authorize(lease=lease),
        )

    def test_targets_require_exact_eligible_ip_shape(self) -> None:
        hostile = (
            ("gateway.example.invalid", list(MEMBERS)),
            ("127.0.0.1", list(MEMBERS)),
            (MANAGEMENT, ["0.0.0.0", MEMBERS[1]]),
            (MANAGEMENT, ["169.254.1.1", MEMBERS[1]]),
            (MANAGEMENT, [MEMBERS[0]]),
            (MANAGEMENT, [MEMBERS[0], MEMBERS[0]]),
            (MEMBERS[0], list(MEMBERS)),
        )
        for management, members in hostile:
            with self.subTest(management=management, members=members):
                self.assert_category(
                    "TARGET_INVALID",
                    lambda management=management, members=members: self.authorize(
                        management_target=management,
                        member_targets=members,
                    ),
                )

    def test_ipv6_targets_are_normalized_before_matching(self) -> None:
        lease = valid_lease()
        lease["management_target"] = "2001:db8::5"
        lease["member_targets"] = ["2001:db8::10", "2001:db8::11"]
        result = self.authorize(
            lease=lease,
            management_target="2001:0db8:0:0:0:0:0:5",
            member_targets=["2001:0db8::11", "2001:db8::10"],
        )
        self.assertTrue(result["authorized"])

    def test_scoped_ipv6_is_rejected_and_mapped_ipv4_is_normalized(self) -> None:
        self.assert_category(
            "TARGET_INVALID",
            lambda: self.authorize(management_target="2001:db8::5%eth0"),
        )
        self.assertNotIn(".scope_id", MODULE.read_text(encoding="utf-8"))
        lease = valid_lease()
        lease["management_target"] = "::ffff:192.0.2.5"
        result = self.authorize(lease=lease)
        self.assertTrue(result["authorized"])
        self.assert_category(
            "TARGET_INVALID",
            lambda: self.authorize(
                management_target="::ffff:198.51.100.10",
            ),
        )

    def test_runtime_targets_must_exactly_match_lease(self) -> None:
        self.assert_category(
            "TARGET_MISMATCH",
            lambda: self.authorize(
                member_targets=[MEMBERS[0], "198.51.100.12"],
            ),
        )

    def test_credentials_are_presence_booleans_with_exact_keys(self) -> None:
        hostile = (
            {},
            {"management_username": True, "management_secret": False},
            {"management_username": True, "management_secret": "populated"},
            {
                "management_username": True,
                "management_secret": True,
                "credential": "must never be accepted",
            },
        )
        for value in hostile:
            with self.subTest(value=value):
                self.assert_category(
                    "CREDENTIALS_INVALID",
                    lambda value=value: self.authorize(credential_presence=value),
                )


if __name__ == "__main__":
    unittest.main()
