from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


MODULE = (
    Path(__file__).resolve().parents[4]
    / "plugins"
    / "module_utils"
    / "package_state_live_preflight.py"
)
SPEC = importlib.util.spec_from_file_location(
    "checkpoint_package_state_live_preflight",
    MODULE,
)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
LEASE_ID = "63c53f94-319d-444a-8c43-ec2584bcf985"
MEMBERS = ["198.51.100.10", "198.51.100.11"]


def valid_lease() -> dict:
    return {
        "lease_id": LEASE_ID,
        "issued_at": "2026-07-29T11:55:00Z",
        "expires_at": "2026-07-29T12:05:00Z",
        "operation": "package_state_observation",
        "execution_mode": "read_only",
        "tls_validation_mode": "strict",
        "member_targets": list(MEMBERS),
    }


class PackageStateLivePreflightTests(unittest.TestCase):
    def authorize(self, **overrides):
        values = {
            "lease": valid_lease(),
            "member_target": MEMBERS[0],
            "member_targets": list(MEMBERS),
            "credential_presence": {
                "gaia_username": True,
                "gaia_secret": True,
            },
            "tls_validation_enabled": True,
            "lab_tls_exception_acknowledged": False,
            "check_mode": True,
            "now": NOW,
        }
        values.update(overrides)
        return preflight.authorize_package_state_readonly(**values)

    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(
            preflight.PackageStateLivePreflightError
        ) as caught:
            call()
        self.assertEqual(caught.exception.category, category)

    def test_controller_proxy_inventory_must_be_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts"
            preflight.require_direct_gaia_controller(str(path))
            path.write_text("[local]\nlocalhost ansible_connection=local\n")
            self.assert_category(
                "TARGET_PROXY_UNSUPPORTED",
                lambda: preflight.require_direct_gaia_controller(str(path)),
            )
            path.unlink()
            path.mkdir()
            self.assert_category(
                "TARGET_PROXY_UNSUPPORTED",
                lambda: preflight.require_direct_gaia_controller(str(path)),
            )

    def test_authorizes_only_sanitized_two_member_observation(self) -> None:
        result = self.authorize()
        self.assertEqual(
            set(result),
            {
                "authorized",
                "lease_id",
                "operation",
                "tls_validation_mode",
                "expires_at",
                "target_count",
                "target_fingerprint",
            },
        )
        self.assertTrue(result["authorized"])
        self.assertEqual(result["target_count"], 2)
        self.assertEqual(result["operation"], "package_state_observation")
        self.assertEqual(result["tls_validation_mode"], "strict")
        self.assertNotIn(MEMBERS[0], str(result))
        self.assertNotIn(MEMBERS[1], str(result))

    def test_check_mode_and_exact_read_only_operation_are_mandatory(self) -> None:
        for value in (False, None, 1, "true"):
            with self.subTest(check_mode=value):
                self.assert_category(
                    "MUTATION_BLOCKED",
                    lambda value=value: self.authorize(check_mode=value),
                )
        for field, value in (
            ("operation", "managed_discovery"),
            ("operation", "install_package"),
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

    def test_lease_shape_uuid_and_times_fail_closed(self) -> None:
        hostile = [
            {},
            dict(valid_lease(), extra="not allowed"),
            dict(valid_lease(), lease_id="not-a-uuid"),
        ]
        for lease in hostile:
            with self.subTest(lease=lease):
                self.assert_category(
                    "LEASE_INVALID",
                    lambda lease=lease: self.authorize(lease=lease),
                )
        for field, value in (
            ("issued_at", "2026-07-29T11:55:00+00:00"),
            ("issued_at", "2026-07-29T12:01:00Z"),
            ("expires_at", "2026-07-29T11:54:00Z"),
            ("expires_at", "2026-07-29T12:20:01Z"),
        ):
            lease = valid_lease()
            lease[field] = value
            with self.subTest(field=field, value=value):
                self.assert_category(
                    "LEASE_INVALID",
                    lambda lease=lease: self.authorize(lease=lease),
                )
        lease = valid_lease()
        lease["expires_at"] = "2026-07-29T12:00:00Z"
        self.assert_category(
            "LEASE_EXPIRED",
            lambda: self.authorize(lease=lease),
        )

    def test_runtime_targets_must_exactly_match_lease_and_current_host(self) -> None:
        hostile = (
            {"member_targets": [MEMBERS[0]]},
            {"member_targets": [MEMBERS[0], MEMBERS[0]]},
            {"member_targets": [MEMBERS[0], "198.51.100.12"]},
            {"member_target": "198.51.100.12"},
            {"member_target": "127.0.0.1"},
            {"member_target": "2001:db8::1%eth0"},
        )
        for override in hostile:
            with self.subTest(override=override):
                self.assert_category(
                    (
                        "TARGET_INVALID"
                        if override.get("member_target")
                        in {"127.0.0.1", "2001:db8::1%eth0"}
                        or len(override.get("member_targets", MEMBERS)) != 2
                        or len(set(override.get("member_targets", MEMBERS))) != 2
                        else "TARGET_MISMATCH"
                    ),
                    lambda override=override: self.authorize(**override),
                )

    def test_ipv6_and_ipv4_mapped_targets_are_normalized(self) -> None:
        lease = valid_lease()
        lease["member_targets"] = ["2001:db8::10", "2001:db8::11"]
        result = self.authorize(
            lease=lease,
            member_target="2001:0db8::10",
            member_targets=["2001:0db8:0:0::11", "2001:db8::10"],
        )
        self.assertTrue(result["authorized"])
        mapped = valid_lease()
        mapped["member_targets"] = [
            "::ffff:198.51.100.10",
            "::ffff:198.51.100.11",
        ]
        self.assertTrue(self.authorize(lease=mapped)["authorized"])

    def test_tls_validation_mode_requires_exact_transport_and_ack(self) -> None:
        lab_lease = valid_lease()
        lab_lease["tls_validation_mode"] = "lab_unverified"
        lab_result = self.authorize(
            lease=lab_lease,
            tls_validation_enabled=False,
            lab_tls_exception_acknowledged=True,
        )
        self.assertEqual(lab_result["tls_validation_mode"], "lab_unverified")

        hostile = (
            {"tls_validation_enabled": False},
            {"lab_tls_exception_acknowledged": True},
            {"tls_validation_enabled": "true"},
            {"lab_tls_exception_acknowledged": "false"},
            {"tls_validation_enabled": 1},
            {"lab_tls_exception_acknowledged": 0},
            {
                "lease": lab_lease,
                "tls_validation_enabled": True,
                "lab_tls_exception_acknowledged": True,
            },
            {
                "lease": lab_lease,
                "tls_validation_enabled": False,
                "lab_tls_exception_acknowledged": False,
            },
            {
                "tls_validation_enabled": False,
                "lab_tls_exception_acknowledged": True,
            },
            {
                "lease": lab_lease,
                "tls_validation_enabled": True,
                "lab_tls_exception_acknowledged": False,
            },
        )
        for override in hostile:
            with self.subTest(override=override):
                self.assert_category(
                    "TLS_VALIDATION_INVALID",
                    lambda override=override: self.authorize(**override),
                )

        invalid_mode = valid_lease()
        invalid_mode["tls_validation_mode"] = "disabled"
        self.assert_category(
            "TLS_VALIDATION_INVALID",
            lambda: self.authorize(lease=invalid_mode),
        )

    def test_credentials_are_presence_booleans_with_exact_keys(self) -> None:
        hostile = (
            {},
            {"gaia_username": True, "gaia_secret": False},
            {"gaia_username": True, "gaia_secret": "present"},
            {"gaia_username": True, "gaia_secret": "yes"},
            {"gaia_username": True, "gaia_secret": 1},
            {
                "gaia_username": True,
                "gaia_secret": True,
                "password": "must never be accepted",
            },
        )
        for value in hostile:
            with self.subTest(value=value):
                self.assert_category(
                    "CREDENTIALS_INVALID",
                    lambda value=value: self.authorize(
                        credential_presence=value
                    ),
                )


if __name__ == "__main__":
    unittest.main()
