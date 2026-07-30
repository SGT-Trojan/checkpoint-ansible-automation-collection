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
    / "cluster_observations.py"
)
SPEC = importlib.util.spec_from_file_location("checkpoint_cluster_observations", MODULE)
assert SPEC and SPEC.loader
observations = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = observations
SPEC.loader.exec_module(observations)


def state_output(
    local_state: str = "ACTIVE",
    peer_state: str = "STANDBY",
    pnotes: str = "None",
) -> str:
    return f"""
Cluster Mode: High Availability
ID         Unique Address  Assigned Load   State      Name
1 (local) 192.0.2.10       100%            {local_state} Member-A
2         192.0.2.11       0%              {peer_state} Member-B

Active PNOTEs: {pnotes}
"""


def interface_output(
    eth0_status: str = "UP",
    eth1_status: str = "UP",
    required: int = 2,
    secured: int = 1,
) -> str:
    return f"""
Required interfaces: {required}
Required secured interfaces: {secured}

Interface Name:       Status
eth0 (S-LS)           {eth0_status}
eth1                  {eth1_status}
eth2                  non-monitored
S - sync, LS - link synchronization

Virtual cluster interfaces: 1
eth1                  192.0.2.254
"""


class ClusterObservationTests(unittest.TestCase):
    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(observations.ObservationError) as caught:
            call()
        self.assertEqual(caught.exception.category, category)

    def test_cluster_state_requires_two_rows_and_one_local(self) -> None:
        result = observations.parse_cluster_state(state_output())
        self.assertEqual(result["local_name"], "Member-A")
        self.assertEqual(result["local_state"], "ACTIVE")
        self.assertTrue(result["pnotes_ok"])
        self.assertEqual(len(result["members"]), 2)

    def test_active_pnotes_must_be_explicitly_none(self) -> None:
        result = observations.parse_cluster_state(state_output(pnotes="problem"))
        self.assertFalse(result["pnotes_ok"])

    def test_conflicting_duplicate_pnotes_are_not_clear(self) -> None:
        text = state_output() + "\nActive PNOTEs: problem\n"
        result = observations.parse_cluster_state(text)
        self.assertFalse(result["pnotes_ok"])

    def test_missing_local_marker_is_incomplete(self) -> None:
        text = state_output().replace("(local)", "")
        self.assert_category(
            "OBSERVATION_INCOMPLETE",
            lambda: observations.parse_cluster_state(text),
        )

    def test_duplicate_member_row_is_invalid(self) -> None:
        text = state_output() + (
            "\n3 192.0.2.12 0% DOWN Member-B\n"
        )
        self.assert_category(
            "OBSERVATION_INVALID",
            lambda: observations.parse_cluster_state(text),
        )

    def test_three_unique_members_are_unsupported(self) -> None:
        text = state_output() + (
            "\n3 192.0.2.12 0% STANDBY Member-C\n"
        )
        self.assert_category(
            "UNSUPPORTED_TOPOLOGY",
            lambda: observations.parse_cluster_state(text),
        )

    def test_interface_markers_are_not_misread_as_status(self) -> None:
        result = observations.parse_cluster_interfaces(interface_output())
        self.assertTrue(result["ok"])
        self.assertTrue(result["interfaces"][0]["sync"])
        self.assertEqual(result["interfaces"][0]["markers"], ["S-LS"])
        self.assertFalse(result["interfaces"][2]["monitored"])

    def test_inbound_down_is_not_accepted_as_up(self) -> None:
        result = observations.parse_cluster_interfaces(
            interface_output(eth1_status="Inbound: DOWN")
        )
        self.assertFalse(result["ok"])

    def test_required_count_is_exact_not_a_minimum(self) -> None:
        result = observations.parse_cluster_interfaces(
            interface_output(required=1)
        )
        self.assertFalse(result["ok"])

    def test_secured_count_is_exact(self) -> None:
        result = observations.parse_cluster_interfaces(
            interface_output(secured=0)
        )
        self.assertFalse(result["ok"])

    def test_missing_required_counts_is_incomplete(self) -> None:
        self.assert_category(
            "OBSERVATION_INCOMPLETE",
            lambda: observations.parse_cluster_interfaces(
                "Interface Name: Status\neth0 UP\n"
            ),
        )

    def test_virtual_interface_count_must_match(self) -> None:
        text = interface_output().replace(
            "Virtual cluster interfaces: 1",
            "Virtual cluster interfaces: 2",
        )
        self.assert_category(
            "OBSERVATION_INCOMPLETE",
            lambda: observations.parse_cluster_interfaces(text),
        )

    def test_known_terminal_envelopes_after_virtual_rows_are_accepted(self) -> None:
        for suffix in (
            "\nMember-A>\n",
            "\n[Expert@Member-A:0]#\n===== END COMMAND 171 =====\n",
        ):
            with self.subTest(suffix=suffix):
                result = observations.parse_cluster_interfaces(
                    interface_output() + suffix
                )
                self.assertTrue(result["ok"])

    def test_unknown_trailing_virtual_content_is_rejected(self) -> None:
        for suffix in (
            "\nuntrusted trailing text\n",
            "\n===== BEGIN COMMAND 172 =====\n",
            "\n===== END COMMAND 171 =====\nuntrusted trailing text\n",
        ):
            with self.subTest(suffix=suffix):
                self.assert_category(
                    "OBSERVATION_INVALID",
                    lambda: observations.parse_cluster_interfaces(
                        interface_output() + suffix
                    ),
                )

    def test_duplicate_virtual_interface_is_invalid(self) -> None:
        text = interface_output().replace(
            "Virtual cluster interfaces: 1",
            "Virtual cluster interfaces: 2",
        ) + "eth1 192.0.2.254\n"
        self.assert_category(
            "OBSERVATION_INVALID",
            lambda: observations.parse_cluster_interfaces(text),
        )

    def test_terminal_control_sequences_are_removed(self) -> None:
        text = "\x1b]0;member console\x07" + interface_output()
        result = observations.parse_cluster_interfaces(text)
        self.assertTrue(result["ok"])

    def test_duplicate_interface_is_invalid(self) -> None:
        text = interface_output().replace(
            "eth2                  non-monitored",
            "eth1                  UP",
        )
        self.assert_category(
            "OBSERVATION_INVALID",
            lambda: observations.parse_cluster_interfaces(text),
        )

    def test_unknown_interface_status_is_unhealthy(self) -> None:
        text = interface_output().replace("eth1                  UP", "not parseable")
        result = observations.parse_cluster_interfaces(text)
        self.assertFalse(result["ok"])

    def test_icap_requires_explicit_watchdog_listener_and_process(self) -> None:
        result = observations.parse_icap_status(
            "CICAP 1234 E 1",
            "LISTEN 0 128 0.0.0.0:1344 0.0.0.0:*",
            "1234 /usr/bin/c-icap -f /etc/c-icap.conf",
        )
        self.assertTrue(result["ok"])
        terminated = observations.parse_icap_status(
            "CICAP 1234 T 1",
            "LISTEN 0 128 0.0.0.0:1344 0.0.0.0:*",
            "1234 /usr/bin/c-icap -f /etc/c-icap.conf",
        )
        self.assertFalse(terminated["watchdog_ok"])
        self.assertFalse(terminated["ok"])

    def test_icap_grep_echoes_do_not_count_as_evidence(self) -> None:
        result = observations.parse_icap_status(
            "CICAP 1234 E 1",
            "grep ':1344'",
            "123 /usr/bin/grep c-icap",
        )
        self.assertFalse(result["listener_ok"])
        self.assertFalse(result["process_ok"])
        echoed_watchdog = observations.parse_icap_status(
            "echo CICAP 1234 E 1",
            "LISTEN 0 128 0.0.0.0:1344 0.0.0.0:*",
            "1234 /usr/bin/c-icap -f /etc/c-icap.conf",
        )
        self.assertFalse(echoed_watchdog["watchdog_ok"])

    def test_icap_requires_tcp_listen_state_and_executable(self) -> None:
        invalid_listeners = (
            "udp 0 0 0.0.0.0:1344 0.0.0.0:*",
            "ESTAB 0 0 192.0.2.10:1344 192.0.2.11:50000",
            "tcp 0 0 0.0.0.0:1344 0.0.0.0:* TIME_WAIT",
        )
        for listener in invalid_listeners:
            with self.subTest(listener=listener):
                result = observations.parse_icap_status(
                    "CICAP 1234 E 1",
                    listener,
                    "1234 /usr/bin/c-icap -f /etc/c-icap.conf",
                )
                self.assertFalse(result["listener_ok"])
                self.assertFalse(result["ok"])

        invalid_processes = (
            "1 /usr/bin/tail -f /var/log/c-icap/server.log",
            "2 /usr/bin/vim /etc/c-icap.conf",
            "3 /usr/bin/echo c-icap",
            "4 /usr/bin/cat /usr/sbin/c-icap",
        )
        for process in invalid_processes:
            with self.subTest(process=process):
                result = observations.parse_icap_status(
                    "CICAP 1234 E 1",
                    "LISTEN 0 128 0.0.0.0:1344 0.0.0.0:*",
                    process,
                )
                self.assertFalse(result["process_ok"])
                self.assertFalse(result["ok"])

    def test_icap_process_uses_observed_executable_position(self) -> None:
        result = observations.parse_icap_status(
            "CICAP 1234 E 1",
            "LISTEN 0 128 0.0.0.0:1344 0.0.0.0:*",
            "4 /usr/bin/cat /usr/sbin/c-icap\n"
            "1234 /usr/sbin/c-icap -f /etc/c-icap.conf",
        )
        self.assertTrue(result["process_ok"])

    def test_interface_signature_is_order_independent(self) -> None:
        parsed = observations.parse_cluster_interfaces(interface_output())
        reversed_observation = dict(parsed)
        reversed_observation["interfaces"] = list(reversed(parsed["interfaces"]))
        reversed_observation["virtual_interfaces"] = list(
            reversed(parsed["virtual_interfaces"])
        )
        self.assertEqual(
            observations.interface_signature(parsed),
            observations.interface_signature(reversed_observation),
        )

    def test_interface_signature_includes_non_monitored_interfaces(self) -> None:
        parsed = observations.parse_cluster_interfaces(interface_output())
        changed = dict(parsed)
        changed["interfaces"] = [
            row for row in parsed["interfaces"] if row["name"] != "eth2"
        ]
        self.assertNotEqual(
            observations.interface_signature(parsed),
            observations.interface_signature(changed),
        )

    def test_ip_addresses_are_normalized_and_invalid_values_fail(self) -> None:
        self.assertEqual(observations.normalize_ip("2001:0db8::10"), "2001:db8::10")
        self.assert_category(
            "OBSERVATION_INVALID",
            lambda: observations.normalize_ip("not-an-address"),
        )


if __name__ == "__main__":
    unittest.main()
