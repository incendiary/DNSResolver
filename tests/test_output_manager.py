"""
Tests for OutputManager.

Covers: output-dir creation, the evidence-dir-vs-file branch in _create,
explicit create/write failures, and evidence file layout when evidence=True.
"""

import os
from unittest.mock import patch

import pytest

from classes.custom_exceptions import OutputWriteError
from classes.output_manager import OutputManager


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
    with patch("classes.output_manager.aiofiles.open", side_effect=OSError("boom")):
        with patch.object(om._logger, "error") as mock_error:
            with pytest.raises(OutputWriteError, match="Failed to write"):
                await om.write_to_file(target, "some content")
            mock_error.assert_called_once()


@pytest.mark.asyncio
async def test_write_to_file_success_writes_content(tmp_path):
    om = OutputManager(str(tmp_path), "20260101_000000")
    target = str(tmp_path / "out.txt")
    await om.write_to_file(target, "hello")
    with open(target, "r", encoding="utf-8") as f:
        assert f.read() == "hello\n"
