"""
Tests for EvidenceCollector.

Subprocess calls (dig, nslookup, which/where) are mocked so no real
system tools are required.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from classes.evidence_collector import EvidenceCollector


@pytest.fixture
def collector(mock_env_manager):
    return EvidenceCollector(mock_env_manager)


def _make_process(stdout=b"output", stderr=b""):
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc


# ---------------------------------------------------------------------------
# check_tools_availability
# ---------------------------------------------------------------------------


def test_check_tools_finds_dig_on_unix():
    with (
        patch("classes.evidence_collector.platform.system", return_value="Linux"),
        patch("classes.evidence_collector.subprocess.run") as mock_run,
    ):
        mock_run.return_value.returncode = 0
        nslookup, dig = EvidenceCollector.check_tools_availability()

    assert dig is True
    assert nslookup is True


def test_check_tools_missing_on_unix():
    with (
        patch("classes.evidence_collector.platform.system", return_value="Linux"),
        patch("classes.evidence_collector.subprocess.run") as mock_run,
    ):
        mock_run.return_value.returncode = 1
        nslookup, dig = EvidenceCollector.check_tools_availability()

    assert dig is False
    assert nslookup is False


def test_check_tools_on_windows():
    with (
        patch("classes.evidence_collector.platform.system", return_value="Windows"),
        patch("classes.evidence_collector.subprocess.run") as mock_run,
    ):
        mock_run.return_value.returncode = 0
        nslookup, dig = EvidenceCollector.check_tools_availability()

    assert nslookup is True


# ---------------------------------------------------------------------------
# save_and_log_dns_result
# ---------------------------------------------------------------------------


async def test_save_and_log_dns_result_writes_file(
    collector, mock_env_manager, tmp_path
):
    proc = _make_process(stdout=b"dns output", stderr=b"")
    evidence_dir = str(tmp_path)

    await collector.save_and_log_dns_result(
        proc, "example.com", "8.8.8.8", "dangling", evidence_dir, "dig"
    )

    mock_env_manager.write_to_file.assert_called_once()
    path, content = mock_env_manager.write_to_file.call_args[0]
    assert "example.com" in path
    assert "dns output" in content


# ---------------------------------------------------------------------------
# perform_nslookup
# ---------------------------------------------------------------------------


async def test_perform_nslookup_spawns_subprocess(collector, tmp_path):
    proc = _make_process()
    with patch(
        "classes.evidence_collector.asyncio.create_subprocess_exec", return_value=proc
    ) as mock_exec:
        await collector.perform_nslookup(
            "example.com", "8.8.8.8", "dangling", str(tmp_path)
        )

    args = mock_exec.call_args[0]
    assert args[0] == "nslookup"
    assert "example.com" in args


async def test_perform_nslookup_raises_on_failure(collector, tmp_path):
    with patch(
        "classes.evidence_collector.asyncio.create_subprocess_exec",
        side_effect=OSError("not found"),
    ):
        with pytest.raises(OSError):
            await collector.perform_nslookup(
                "example.com", "8.8.8.8", "dangling", str(tmp_path)
            )


# ---------------------------------------------------------------------------
# perform_dig
# ---------------------------------------------------------------------------


async def test_perform_dig_spawns_subprocess(collector, tmp_path):
    proc = _make_process()
    with patch(
        "classes.evidence_collector.asyncio.create_subprocess_exec", return_value=proc
    ) as mock_exec:
        await collector.perform_dig("example.com", "8.8.8.8", "dangling", str(tmp_path))

    args = mock_exec.call_args[0]
    assert args[0] == "dig"
    assert "example.com" in args


# ---------------------------------------------------------------------------
# perform_dns_evidence — platform dispatch
# ---------------------------------------------------------------------------


async def test_perform_dns_evidence_uses_dig_on_unix_when_available(
    collector, tmp_path
):
    collector.perform_dig = AsyncMock()
    collector.perform_nslookup = AsyncMock()

    with (
        patch("classes.evidence_collector.platform.system", return_value="Linux"),
        patch.object(
            EvidenceCollector, "check_tools_availability", return_value=(True, True)
        ),
    ):
        await collector.perform_dns_evidence(
            "example.com", "8.8.8.8", "dangling", str(tmp_path)
        )

    collector.perform_dig.assert_called_once()
    collector.perform_nslookup.assert_not_called()


async def test_perform_dns_evidence_falls_back_to_nslookup_when_no_dig(
    collector, tmp_path
):
    collector.perform_dig = AsyncMock()
    collector.perform_nslookup = AsyncMock()

    with (
        patch("classes.evidence_collector.platform.system", return_value="Linux"),
        patch.object(
            EvidenceCollector, "check_tools_availability", return_value=(True, False)
        ),
    ):
        await collector.perform_dns_evidence(
            "example.com", "8.8.8.8", "dangling", str(tmp_path)
        )

    collector.perform_nslookup.assert_called_once()
    collector.perform_dig.assert_not_called()


async def test_perform_dns_evidence_uses_nslookup_on_windows(collector, tmp_path):
    collector.perform_nslookup = AsyncMock()

    with (
        patch("classes.evidence_collector.platform.system", return_value="Windows"),
        patch.object(
            EvidenceCollector, "check_tools_availability", return_value=(True, False)
        ),
    ):
        await collector.perform_dns_evidence(
            "example.com", "8.8.8.8", "dangling", str(tmp_path)
        )

    collector.perform_nslookup.assert_called_once()


async def test_perform_dns_evidence_logs_error_when_no_tools(
    collector, mock_env_manager, tmp_path
):
    with (
        patch("classes.evidence_collector.platform.system", return_value="Linux"),
        patch.object(
            EvidenceCollector, "check_tools_availability", return_value=(False, False)
        ),
    ):
        await collector.perform_dns_evidence(
            "example.com", "8.8.8.8", "dangling", str(tmp_path)
        )

    mock_env_manager.log_error.assert_called_once()
