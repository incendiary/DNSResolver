"""
Tests for OutputManager.

Covers: output-dir creation, the evidence-dir-vs-file branch in _create,
explicit create/write failures, and evidence file layout when evidence=True.
"""

import os
from unittest.mock import patch

import pytest

from classes.custom_exceptions import OutputWriteError
from classes.environment_manager import EnvironmentManager
from classes.output_manager import OutputManager, write_sorted_atomic
from classes.records import CspMatch, Dangling, NsTakeover, Resolution, Unresolved


def test_output_dir_created(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000")
    assert os.path.isdir(om.output_dir)


def test_standard_files_created_as_files(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000")
    for path in om.output_files["standard"].values():
        assert os.path.isfile(path)


def test_evidence_dir_created_as_directory_not_file(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000", evidence=True)
    evidence_path = om.output_files["evidence"]["dns"]
    assert os.path.isdir(evidence_path)
    assert not os.path.isfile(evidence_path)


def test_no_evidence_key_when_evidence_disabled(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000", evidence=False)
    assert "evidence" not in om.output_files


def test_create_write_error_is_raised(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000")
    target = str(tmp_path / "some_file.txt")
    with (
        patch("builtins.open", side_effect=OSError("disk full")),
        pytest.raises(OutputWriteError, match="Unable to create"),
    ):
        om._create(target)


def test_create_logs_error_on_failure(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000")
    with patch("builtins.open", side_effect=OSError("disk full")):
        with patch.object(om._logger, "error") as mock_error:
            with pytest.raises(OutputWriteError):
                om._create(str(tmp_path / "some_file.txt"))
            mock_error.assert_called_once()


@pytest.mark.asyncio
async def test_write_to_file_error_is_raised(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000")
    target = str(tmp_path / "out.txt")
    with patch("builtins.open", side_effect=OSError("boom")):
        with patch.object(om._logger, "error") as mock_error:
            with pytest.raises(OutputWriteError) as raised:
                await om.write_to_file(target, "some content")
            mock_error.assert_called_once()
    assert str(raised.value) == f"Failed to write required output {target}: boom"


@pytest.mark.asyncio
async def test_write_to_file_unwritable_path_raises(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000")
    target = str(tmp_path / "missing_dir" / "out.txt")
    with pytest.raises(OutputWriteError, match="Failed to write required output"):
        await om.write_to_file(target, "some content")


@pytest.mark.asyncio
async def test_write_to_file_success_writes_content(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000")
    target = str(tmp_path / "out.txt")
    await om.write_to_file(target, "hello")
    with open(target, "r", encoding="utf-8") as f:
        assert f.read() == "hello\n"


def test_write_sorted_atomic_sorts_and_leaves_no_temporary(tmp_path):
    path = tmp_path / "out.txt"
    path.write_text("stale\n")
    write_sorted_atomic(str(path), ["b|2", "WILDCARD|z", "a|1", "b|1"])
    assert path.read_text() == "WILDCARD|z\na|1\nb|1\nb|2\n"
    assert os.listdir(tmp_path) == ["out.txt"]


def test_write_sorted_atomic_keeps_original_when_replace_fails(tmp_path):
    path = tmp_path / "out.txt"
    path.write_text("original\n")
    with patch("classes.output_manager.os.replace", side_effect=OSError("boom")):
        with pytest.raises(OutputWriteError):
            write_sorted_atomic(str(path), ["b", "a"])
    assert path.read_text() == "original\n"


def test_sort_pipe_files_orders_by_line_whatever_the_write_order(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000")
    env = EnvironmentManager.__new__(EnvironmentManager)
    env.output_files = om.output_files
    # Completion order differs from sorted order, and from record kind order.
    env.records = [
        Resolution("z.example.com", ("192.0.2.2",)),
        Dangling("z.example.com", "t", "c", "r", "e", 1, "z -> t"),
        Resolution("a.example.com", ("192.0.2.1",)),
        Unresolved("m.example.com", "NXDOMAIN"),
        NsTakeover("z.example.com", "ns.example.com"),
        CspMatch("z.example.com", "1", "aws", "r", "s", "p", "g"),
        Unresolved("b.example.com", "NXDOMAIN"),
        CspMatch("a.example.com", "1", "aws", "r", "s", "p", "g"),
        Dangling("a.example.com", "t", "c", "r", "e", 1, "a -> t"),
    ]
    standard = om.output_files["standard"]

    def read(key):
        with open(standard[key], encoding="utf-8") as handle:
            return handle.read().splitlines()

    env.sort_pipe_files()
    first = {key: read(key) for key in ("resolved", "csp", "takeover", "unresolved")}
    env.sort_pipe_files()  # stable: a second pass changes nothing
    assert {key: read(key) for key in first} == first
    assert first["resolved"] == ["a.example.com|192.0.2.1", "z.example.com|192.0.2.2"]
    assert first["unresolved"] == [
        "DNS resolution error for b.example.com: NXDOMAIN",
        "DNS resolution error for m.example.com: NXDOMAIN",
    ]
    assert first["takeover"] == [
        "DANGLING|a.example.com|t|c|r|e|1|a -> t",
        "DANGLING|z.example.com|t|c|r|e|1|z -> t",
        "NS_TAKEOVER|z.example.com|ns.example.com",
    ]
    assert [line.split("|")[0] for line in first["csp"]] == [
        "a.example.com",
        "z.example.com",
    ]
