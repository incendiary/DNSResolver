"""
Tests for process_domain_async.

This is the top-level orchestrator for a single domain — it wires together
DNS resolution and CSP checks.  We mock dns_handler and the CSP check
function so each test focuses on the orchestration logic.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from imports.domain_processor import process_domain_async


@pytest.fixture
def dns_handler():
    """A mock DNSHandler with a controllable resolve_domain_async."""
    handler = MagicMock()
    handler.resolve_domain_async = AsyncMock(return_value=(True, ["1.2.3.4"]))
    # Default to "no wildcard" so these tests exercise the ordinary path.
    handler.wildcard_detector.is_wildcard_resolution = AsyncMock(return_value=False)
    return handler


@pytest.fixture
def pbar():
    return MagicMock()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_returns_success_and_ips_on_resolution(
    mock_env_manager, csp_ips, dns_handler, pbar
):
    with patch("imports.domain_processor.perform_csp_checks"):
        success, ips, dangling = await process_domain_async(
            "example.com", mock_env_manager, pbar, csp_ips, dns_handler
        )

    assert success is True
    assert "1.2.3.4" in ips


async def test_pbar_is_updated_after_processing(
    mock_env_manager, csp_ips, dns_handler, pbar
):
    with patch("imports.domain_processor.perform_csp_checks"):
        await process_domain_async(
            "example.com", mock_env_manager, pbar, csp_ips, dns_handler
        )

    pbar.update.assert_called_once_with(1)


async def test_csp_checks_called_on_success(
    mock_env_manager, csp_ips, dns_handler, pbar
):
    with patch("imports.domain_processor.perform_csp_checks") as mock_csp:
        await process_domain_async(
            "example.com", mock_env_manager, pbar, csp_ips, dns_handler
        )

    mock_csp.assert_called_once()


async def test_dangling_domains_returned(mock_env_manager, csp_ips, pbar):
    """
    Dangling domains discovered during resolution must come back as the
    third return value so main_async can aggregate them.
    """
    handler = MagicMock()
    handler.wildcard_detector.is_wildcard_resolution = AsyncMock(return_value=False)
    handler.resolve_domain_async = AsyncMock(return_value=(True, ["1.2.3.4"]))

    with patch("imports.domain_processor.perform_csp_checks"):

        async def resolve_with_dangling(ctx):
            ctx.add_dangling_domain_to_domains("cname-target.s3.amazonaws.com")
            return True, ["1.2.3.4"]

        handler.resolve_domain_async = resolve_with_dangling

        _success, _ips, dangling = await process_domain_async(
            "example.com", mock_env_manager, pbar, csp_ips, handler
        )

    assert "cname-target.s3.amazonaws.com" in dangling


# ---------------------------------------------------------------------------
# Failure path
# ---------------------------------------------------------------------------


async def test_csp_checks_not_called_on_failure(mock_env_manager, csp_ips, pbar):
    handler = MagicMock()
    handler.wildcard_detector.is_wildcard_resolution = AsyncMock(return_value=False)
    handler.resolve_domain_async = AsyncMock(return_value=(False, []))

    with patch("imports.domain_processor.perform_csp_checks") as mock_csp:
        await process_domain_async(
            "example.com", mock_env_manager, pbar, csp_ips, handler
        )

    mock_csp.assert_not_called()


async def test_returns_failure_and_empty_ips_on_failure(
    mock_env_manager, csp_ips, pbar
):
    handler = MagicMock()
    handler.wildcard_detector.is_wildcard_resolution = AsyncMock(return_value=False)
    handler.resolve_domain_async = AsyncMock(return_value=(False, []))

    with patch("imports.domain_processor.perform_csp_checks"):
        success, ips, dangling = await process_domain_async(
            "fail.example.com", mock_env_manager, pbar, csp_ips, handler
        )

    assert success is False
    assert ips == []


async def test_wildcard_resolution_is_marked_in_output(
    mock_env_manager, csp_ips, dns_handler, pbar
):
    """
    A domain resolving only to its zone's wildcard addresses is written with a
    WILDCARD| prefix, so a catch-all answer can be told from a real host.
    """
    dns_handler.wildcard_detector.is_wildcard_resolution = AsyncMock(return_value=True)

    with patch("imports.domain_processor.perform_csp_checks"):
        await process_domain_async(
            "ghost.example.com", mock_env_manager, pbar, csp_ips, dns_handler
        )

    written = [c[0][1] for c in mock_env_manager.write_to_file.call_args_list]
    assert any(ln.startswith("WILDCARD|ghost.example.com|") for ln in written)


async def test_ordinary_resolution_is_not_prefixed(
    mock_env_manager, csp_ips, dns_handler, pbar
):
    """Non-wildcard output keeps its original format — no regression for parsers."""
    with patch("imports.domain_processor.perform_csp_checks"):
        await process_domain_async(
            "real.example.com", mock_env_manager, pbar, csp_ips, dns_handler
        )

    written = [c[0][1] for c in mock_env_manager.write_to_file.call_args_list]
    assert any(ln == "real.example.com|1.2.3.4" for ln in written)
    assert not any(ln.startswith("WILDCARD|") for ln in written)
