from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import errno
import hashlib
import importlib.util
import multiprocessing
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock


MODULE = (
    Path(__file__).resolve().parents[4]
    / "plugins"
    / "module_utils"
    / "artifact_observation.py"
)
SPEC = importlib.util.spec_from_file_location("checkpoint_artifact_observation", MODULE)
assert SPEC and SPEC.loader
observation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = observation
SPEC.loader.exec_module(observation)


def observe_fifo(path: str, result_connection) -> None:
    try:
        observation.observe_artifact(path)
    except observation.ArtifactObservationError as error:
        result_connection.send(error.category)
    else:
        result_connection.send("UNEXPECTED_SUCCESS")
    finally:
        result_connection.close()


class ArtifactObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "package.tgz"
        self.content = b"offline-package-fixture" * 100000
        self.path.write_bytes(self.content)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_category(self, category: str, call) -> None:
        with self.assertRaises(observation.ArtifactObservationError) as caught:
            call()
        self.assertEqual(caught.exception.category, category)

    def test_streams_exact_sha256_size_and_path_without_content(self) -> None:
        result = observation.observe_artifact(str(self.path))
        self.assertEqual(result["path"], str(self.path))
        self.assertEqual(result["size"], len(self.content))
        self.assertEqual(result["sha256"], hashlib.sha256(self.content).hexdigest())
        self.assertEqual(set(result), {"path", "size", "sha256"})
        self.assertNotIn(self.content[:20].decode(), str(result))

    def test_expected_path_must_be_one_canonical_absolute_path(self) -> None:
        hostile = (
            "",
            "relative/package.tgz",
            "//tmp/package.tgz",
            str(self.root / ".." / self.root.name / "package.tgz"),
            str(self.root) + "//package.tgz",
            str(self.path) + "/",
            str(self.path) + "\n",
        )
        for value in hostile:
            with self.subTest(value=value):
                self.assert_category(
                    "PATH_INVALID",
                    lambda value=value: observation.observe_artifact(value),
                )

    def test_final_symlink_is_rejected(self) -> None:
        linked = self.root / "linked.tgz"
        linked.symlink_to(self.path)
        self.assert_category(
            "SYMLINK_REJECTED",
            lambda: observation.observe_artifact(str(linked)),
        )

    def test_symlinked_parent_component_is_rejected(self) -> None:
        real = self.root / "real"
        real.mkdir()
        package = real / "package.tgz"
        package.write_bytes(b"package")
        linked = self.root / "linked"
        linked.symlink_to(real, target_is_directory=True)
        self.assert_category(
            "PARENT_COMPONENT_INVALID",
            lambda: observation.observe_artifact(str(linked / "package.tgz")),
        )

    def test_regular_file_parent_uses_truthful_parent_category(self) -> None:
        self.assert_category(
            "PARENT_COMPONENT_INVALID",
            lambda: observation.observe_artifact(str(self.path / "child.tgz")),
        )

    def test_transition_close_failure_closes_new_directory_descriptor(self) -> None:
        previous_fd = os.open(str(self.root), os.O_RDONLY)
        next_fd = os.open(str(self.root), os.O_RDONLY)
        original_close = os.close
        close_calls = []

        def fail_previous_close(file_descriptor):
            close_calls.append(file_descriptor)
            if file_descriptor == previous_fd:
                raise OSError(errno.EIO, "injected close failure")
            return original_close(file_descriptor)

        try:
            with mock.patch.object(
                observation.os,
                "open",
                side_effect=[previous_fd, next_fd],
            ), mock.patch.object(
                observation.os,
                "close",
                side_effect=fail_previous_close,
            ):
                self.assert_category(
                    "PARENT_COMPONENT_INVALID",
                    lambda: observation._open_expected(("parent", "package.tgz")),
                )
            self.assertEqual(close_calls, [previous_fd, next_fd])
            with self.assertRaises(OSError):
                os.fstat(next_fd)
        finally:
            original_close(previous_fd)

    def test_final_parent_close_failure_closes_new_file_descriptor(self) -> None:
        parent_fd = os.open(str(self.root), os.O_RDONLY)
        file_fd = os.open(str(self.path), os.O_RDONLY)
        original_close = os.close
        close_calls = []

        def fail_parent_close(file_descriptor):
            close_calls.append(file_descriptor)
            if file_descriptor == parent_fd:
                raise OSError(errno.EIO, "injected close failure")
            return original_close(file_descriptor)

        try:
            with mock.patch.object(
                observation.os,
                "open",
                side_effect=[parent_fd, file_fd],
            ), mock.patch.object(
                observation.os,
                "close",
                side_effect=fail_parent_close,
            ):
                self.assert_category(
                    "PARENT_COMPONENT_INVALID",
                    lambda: observation._open_expected(("package.tgz",)),
                )
            self.assertEqual(close_calls, [parent_fd, file_fd])
            with self.assertRaises(OSError):
                os.fstat(file_fd)
        finally:
            original_close(parent_fd)

    def test_missing_and_non_regular_paths_fail_closed(self) -> None:
        self.assert_category(
            "ARTIFACT_UNAVAILABLE",
            lambda: observation.observe_artifact(str(self.root / "missing.tgz")),
        )
        directory = self.root / "directory"
        directory.mkdir()
        self.assert_category(
            "NOT_REGULAR_FILE",
            lambda: observation.observe_artifact(str(directory)),
        )

    def test_empty_regular_file_is_rejected(self) -> None:
        empty = self.root / "empty.tgz"
        empty.touch()
        self.assert_category(
            "SIZE_INVALID",
            lambda: observation.observe_artifact(str(empty)),
        )

    def test_fifo_without_writer_is_rejected_without_blocking(self) -> None:
        fifo = self.root / "package.fifo"
        os.mkfifo(fifo)
        context = multiprocessing.get_context("fork")
        parent_connection, child_connection = context.Pipe(duplex=False)
        process = context.Process(
            target=observe_fifo,
            args=(str(fifo), child_connection),
        )
        process.start()
        child_connection.close()
        process.join(5)
        if process.is_alive():
            process.terminate()
            process.join()
            parent_connection.close()
            self.fail("FIFO observation blocked before regular-file validation")
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(parent_connection.recv(), "NOT_REGULAR_FILE")
        parent_connection.close()

    def test_unix_socket_and_character_device_are_rejected(self) -> None:
        socket_path = self.root / "package.socket"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(socket_path))
            self.assert_category(
                "ARTIFACT_UNAVAILABLE",
                lambda: observation.observe_artifact(str(socket_path)),
            )
        finally:
            listener.close()
        if not Path("/dev/null").exists():
            self.skipTest("character device is unavailable")
        self.assert_category(
            "NOT_REGULAR_FILE",
            lambda: observation.observe_artifact("/dev/null"),
        )

    def test_same_tick_rewrite_between_passes_is_rejected(self) -> None:
        original_hash = observation._hash_exact
        replacement = b"x" * len(self.content)
        file_fd = os.open(str(self.path), os.O_RDONLY)
        try:
            stable = observation._metadata(file_fd)
        finally:
            os.close(file_fd)
        passes = 0

        def rewrite_between_passes(file_descriptor, expected_size):
            nonlocal passes
            digest = original_hash(file_descriptor, expected_size)
            passes += 1
            if passes == 1:
                writer = os.open(str(self.path), os.O_WRONLY)
                try:
                    remaining = memoryview(replacement)
                    while remaining:
                        written = os.write(writer, remaining)
                        remaining = remaining[written:]
                finally:
                    os.close(writer)
            return digest

        with mock.patch.object(
            observation,
            "_metadata",
            return_value=stable,
        ), mock.patch.object(
            observation,
            "_hash_exact",
            side_effect=rewrite_between_passes,
        ):
            self.assert_category(
                "ARTIFACT_CHANGED",
                lambda: observation.observe_artifact(str(self.path)),
            )

    def test_two_pass_hashes_exact_actual_bytes_and_probes(self) -> None:
        file_fd = os.open(str(self.path), os.O_RDONLY)
        actual = []
        original_read = os.read

        def record_read(descriptor, size):
            chunk = original_read(descriptor, size)
            actual.append(len(chunk))
            return chunk

        try:
            with mock.patch.object(observation.os, "read", side_effect=record_read):
                first = observation._hash_exact(file_fd, len(self.content))
                second = observation._hash_exact(file_fd, len(self.content))
        finally:
            os.close(file_fd)
        self.assertEqual(first, hashlib.sha256(self.content).hexdigest())
        self.assertEqual(second, first)
        self.assertEqual(sum(actual), 2 * len(self.content))
        self.assertEqual(actual.count(0), 2)

    def test_normal_one_byte_short_reads_on_tiny_file_pass(self) -> None:
        tiny = self.root / "tiny.tgz"
        content = b"tiny"
        tiny.write_bytes(content)
        file_fd = os.open(str(tiny), os.O_RDONLY)
        original_read = os.read

        def one_byte_read(descriptor, size):
            return original_read(descriptor, min(size, 1))

        try:
            with mock.patch.object(
                observation.os,
                "read",
                side_effect=one_byte_read,
            ):
                digest = observation._hash_exact(file_fd, len(content))
        finally:
            os.close(file_fd)
        self.assertEqual(digest, hashlib.sha256(content).hexdigest())

    def test_pathological_short_reads_exhaust_call_budget_quickly(self) -> None:
        declared_size = observation.CHUNK_SIZE * 100
        calls = 0

        def one_byte_read(descriptor, size):
            nonlocal calls
            calls += 1
            return b"x"

        with mock.patch.object(observation.os, "lseek"), mock.patch.object(
            observation.os,
            "read",
            side_effect=one_byte_read,
        ):
            self.assert_category(
                "READ_BUDGET_EXHAUSTED",
                lambda: observation._hash_exact(99, declared_size),
            )
        expected_budget = (
            100 * observation.READ_CALL_FACTOR
        ) + observation.READ_CALL_SLACK
        self.assertEqual(calls, expected_budget)
        self.assertLess(calls, declared_size)

    def test_normal_full_reads_stay_within_derived_call_budget(self) -> None:
        file_fd = os.open(str(self.path), os.O_RDONLY)
        calls = 0
        original_read = os.read

        def count_read(descriptor, size):
            nonlocal calls
            calls += 1
            return original_read(descriptor, size)

        try:
            with mock.patch.object(
                observation.os,
                "read",
                side_effect=count_read,
            ):
                digest = observation._hash_exact(file_fd, len(self.content))
        finally:
            os.close(file_fd)
        minimum_calls = (
            len(self.content) + observation.CHUNK_SIZE - 1
        ) // observation.CHUNK_SIZE
        self.assertEqual(calls, minimum_calls + 1)
        self.assertEqual(digest, hashlib.sha256(self.content).hexdigest())

    def test_growth_is_rejected_by_one_byte_probe(self) -> None:
        initial_size = len(self.content)
        original_read = os.read
        read_count = 0

        def append_before_probe(file_descriptor, size):
            nonlocal read_count
            read_count += 1
            if size == 1:
                writer = os.open(str(self.path), os.O_WRONLY | os.O_APPEND)
                try:
                    os.write(writer, b"x")
                finally:
                    os.close(writer)
            return original_read(file_descriptor, size)

        file_fd = os.open(str(self.path), os.O_RDONLY)
        try:
            with mock.patch.object(
                observation.os,
                "read",
                side_effect=append_before_probe,
            ):
                self.assert_category(
                    "ARTIFACT_CHANGED",
                    lambda: observation._hash_exact(file_fd, initial_size),
                )
        finally:
            os.close(file_fd)
        self.assertGreater(read_count, 1)

    def test_descriptor_size_mtime_or_ctime_race_is_rejected(self) -> None:
        file_fd = os.open(str(self.path), os.O_RDONLY)
        try:
            metadata = observation._metadata(file_fd)
        finally:
            os.close(file_fd)
        changed_size = (
            metadata[0],
            metadata[1],
            metadata[2],
            metadata[3] + 1,
            metadata[4],
            metadata[5],
        )
        for changed in (
            changed_size,
            (
                metadata[0],
                metadata[1],
                metadata[2],
                metadata[3],
                metadata[4] + 1,
                metadata[5],
            ),
            (
                metadata[0],
                metadata[1],
                metadata[2],
                metadata[3],
                metadata[4],
                metadata[5] + 1,
            ),
        ):
            with self.subTest(changed=changed), mock.patch.object(
                observation,
                "_metadata",
                side_effect=[metadata, changed],
            ):
                self.assert_category(
                    "ARTIFACT_CHANGED",
                    lambda: observation.observe_artifact(str(self.path)),
                )

    def test_path_replacement_identity_race_is_rejected(self) -> None:
        file_fd = os.open(str(self.path), os.O_RDONLY)
        try:
            metadata = observation._metadata(file_fd)
        finally:
            os.close(file_fd)
        replacement = (
            metadata[0],
            metadata[1] + 1,
            metadata[2],
            metadata[3],
            metadata[4],
            metadata[5],
        )
        with mock.patch.object(
            observation,
            "_metadata",
            side_effect=[metadata, metadata, metadata, replacement],
        ):
            self.assert_category(
                "ARTIFACT_CHANGED",
                lambda: observation.observe_artifact(str(self.path)),
            )

    def test_path_reopen_ctime_drift_is_rejected(self) -> None:
        file_fd = os.open(str(self.path), os.O_RDONLY)
        try:
            metadata = observation._metadata(file_fd)
        finally:
            os.close(file_fd)
        changed_ctime = metadata[:-1] + (metadata[-1] + 1,)
        with mock.patch.object(
            observation,
            "_metadata",
            side_effect=[metadata, metadata, metadata, changed_ctime],
        ):
            self.assert_category(
                "ARTIFACT_CHANGED",
                lambda: observation.observe_artifact(str(self.path)),
            )

    def test_reopen_failure_is_reported_without_success(self) -> None:
        file_fd = os.open(str(self.path), os.O_RDONLY)
        with mock.patch.object(
            observation,
            "_open_expected",
            side_effect=[
                file_fd,
                observation.ArtifactObservationError(
                    "ARTIFACT_UNAVAILABLE",
                    "expected artifact is unavailable",
                ),
            ],
        ):
            self.assert_category(
                "ARTIFACT_UNAVAILABLE",
                lambda: observation.observe_artifact(str(self.path)),
            )

    def test_unsupported_platform_fails_with_stable_category(self) -> None:
        with mock.patch.object(observation, "PLATFORM_SUPPORTED", False):
            self.assert_category(
                "PLATFORM_UNSUPPORTED",
                lambda: observation.observe_artifact(str(self.path)),
            )

    def test_source_uses_nofollow_regular_fstat_and_bounded_reads(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', source)
        self.assertIn('getattr(os, "O_NONBLOCK", 0)', source)
        self.assertIn("os.fstat", source)
        self.assertIn("st_ctime_ns", source)
        self.assertIn("stat.S_ISREG", source)
        self.assertIn("os.read(file_fd, requested)", source)
        self.assertIn("os.read(file_fd, 1)", source)
        self.assertIn("READ_CALL_FACTOR", source)
        self.assertIn("READ_CALL_SLACK", source)
        self.assertEqual(observation.CHUNK_SIZE, 1024 * 1024)
        for prohibited in ("subprocess", "os.system", "Path.read_bytes"):
            self.assertNotIn(prohibited, source)


if __name__ == "__main__":
    unittest.main()
