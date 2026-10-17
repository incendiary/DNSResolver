"""Tests for DNSHandler: resolution, error handling, constructor and categorisation."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiodns
import dns.exception
import dns.resolver
import pytest

from classes.dns_constants import (
    NO_DATA,
    NXDOMAIN,
    SERVFAIL,
    TIMEOUT,
    is_dns_error_present,
)
from classes.dns_handler import DNSHandler
from classes.domain_categoriser import DomainCategoriser

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_nxdomain():
    """Create a DNSError that looks like an NXDOMAIN response."""
    return aiodns.error.DNSError(NXDOMAIN, "Domain not found")


def make_servfail():
    return aiodns.error.DNSError(SERVFAIL, "Server failure")


def make_timeout():
    return aiodns.error.DNSError(TIMEOUT, "Query timed out")


def make_nodata():
    return aiodns.error.DNSError(NO_DATA, "No records of this type")


def dns_answer(ip):
    """A fake DNS answer object with a .host attribute."""
    answer = MagicMock()
    answer.host = ip
    return answer


def make_error(code):
    return aiodns.error.DNSError(code, "test error")


def test_is_dns_error_present_matches_correct_code():
    error = make_nxdomain()
    assert is_dns_error_present(error, [NXDOMAIN]) is True


def test_is_dns_error_present_no_match():
    error = make_timeout()
    assert is_dns_error_present(error, [NXDOMAIN, SERVFAIL]) is False


async def test_resolve_domain_async_success_returns_ips(handler, domain_context):
    """When aiodns resolves successfully we get (True, [ip, ...])."""
    handler.aiodns_resolver.query = AsyncMock(
        return_value=[dns_answer("1.2.3.4"), dns_answer("5.6.7.8")]
    )
    # Stub out takeover checks so this test stays focused on resolution
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)

    success, ips = await handler.resolve_domain_async(domain_context)

    assert success is True
    assert "1.2.3.4" in ips
    assert "5.6.7.8" in ips


async def test_resolve_domain_async_exhausted_retries_returns_false(
    handler, domain_context
):
    """When every attempt fails the handler reports failure."""
    handler.aiodns_resolver.query = AsyncMock(side_effect=make_nxdomain())
    handler.handle_domain_resolution_errors = AsyncMock(return_value=(False, []))

    success, ips = await handler.resolve_domain_async(domain_context)

    assert success is False
    assert ips == []


async def test_resolve_domain_async_makes_single_attempt(
    handler, domain_context, mock_env_manager
):
    """
    resolve_domain_async makes exactly one DNS query per record type per call.
    Retry orchestration is the responsibility of the outer run() loop,
    not the handler itself.
    """
    handler.aiodns_resolver.query = AsyncMock(side_effect=make_nxdomain())
    handler.handle_domain_resolution_errors = AsyncMock(return_value=(False, []))

    await handler.resolve_domain_async(domain_context)

    # A and AAAA are each queried exactly once — no retry loop in the handler.
    record_types = [c.args[1] for c in handler.aiodns_resolver.query.call_args_list]
    assert sorted(record_types) == ["A", "AAAA"]


async def test_resolve_domain_async_aaaa_only_host_is_resolved(handler, domain_context):
    """
    A host with only AAAA records must be reported as resolved with its IPv6
    addresses — previously the A-record NODATA alone marked it unresolved.
    """

    async def query_side_effect(domain, record_type):
        if record_type == "AAAA":
            return [dns_answer("2606:4700::1111")]
        raise make_nodata()  # no A record

    handler.aiodns_resolver.query = AsyncMock(side_effect=query_side_effect)
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)

    success, ips = await handler.resolve_domain_async(domain_context)

    assert success is True
    assert ips == ["2606:4700::1111"]


async def test_resolve_domain_async_mixed_a_and_aaaa_captures_both(
    handler, domain_context
):
    """A dual-stack host yields IPv4 first, then IPv6, in one flat list."""

    async def query_side_effect(domain, record_type):
        if record_type == "A":
            return [dns_answer("1.2.3.4")]
        return [dns_answer("2606:4700::1111"), dns_answer("2606:4700::2222")]

    handler.aiodns_resolver.query = AsyncMock(side_effect=query_side_effect)
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)

    success, ips = await handler.resolve_domain_async(domain_context)

    assert success is True
    assert ips == ["1.2.3.4", "2606:4700::1111", "2606:4700::2222"]


async def test_resolve_domain_async_a_only_host_unaffected_by_aaaa_failure(
    handler, domain_context
):
    """An IPv4-only host stays resolved even though the AAAA query fails."""

    async def query_side_effect(domain, record_type):
        if record_type == "A":
            return [dns_answer("1.2.3.4")]
        raise make_nodata()  # no AAAA record

    handler.aiodns_resolver.query = AsyncMock(side_effect=query_side_effect)
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)

    success, ips = await handler.resolve_domain_async(domain_context)

    assert success is True
    assert ips == ["1.2.3.4"]


async def test_resolve_domain_async_both_families_failing_uses_a_error(
    handler, domain_context
):
    """
    When both A and AAAA fail the domain is unresolved, and the A error is the
    one handed to the error path so NXDOMAIN takeover handling is preserved.
    """
    handler.aiodns_resolver.query = AsyncMock(side_effect=make_nxdomain())
    handler.handle_domain_resolution_errors = AsyncMock(return_value=(False, []))

    success, ips = await handler.resolve_domain_async(domain_context)

    assert success is False
    assert ips == []
    passed_error = handler.handle_domain_resolution_errors.call_args.args[2]
    assert is_dns_error_present(passed_error, [NXDOMAIN])


async def test_resolve_domain_async_non_dns_error_propagates(handler, domain_context):
    """A non-DNS fault must not be swallowed by the gather()."""
    handler.aiodns_resolver.query = AsyncMock(side_effect=RuntimeError("boom"))

    with pytest.raises(RuntimeError, match="boom"):
        await handler.resolve_domain_async(domain_context)


async def test_log_and_write_dns_error_writes_to_unresolved(handler, mock_env_manager):
    error = Exception("timeout")
    await handler.log_and_write_dns_error("fail.example.com", error)

    mock_env_manager.write_to_file.assert_called_once()
    path, content = mock_env_manager.write_to_file.call_args[0]
    assert "unresolved" in path
    assert "fail.example.com" in content


async def test_log_and_write_dns_error_includes_additional_message(
    handler, mock_env_manager
):
    error = Exception("servfail")
    await handler.log_and_write_dns_error(
        "fail.example.com", error, "Could not contact DNS servers"
    )

    _path, content = mock_env_manager.write_to_file.call_args[0]
    assert "Could not contact DNS servers" in content


def test_constructor_applies_timeout_and_all_nameservers(mock_env_manager):
    mock_env_manager.timeout = 7
    mock_env_manager.nameservers = [" 192.0.2.53 ", "198.51.100.53"]

    with (
        patch("classes.dns_handler.aiodns.DNSResolver") as aiodns_resolver_class,
        patch("classes.dns_handler.dns.resolver.Resolver") as dns_resolver_class,
        patch("classes.takeover_detector.EvidenceCollector"),
    ):
        handler = DNSHandler(mock_env_manager)

    expected_nameservers = ["192.0.2.53", "198.51.100.53"]
    aiodns_resolver_class.assert_called_once_with(
        timeout=7, nameservers=expected_nameservers
    )
    assert handler.dnspython_resolver is dns_resolver_class.return_value
    assert handler.dnspython_resolver.timeout == 7
    assert handler.dnspython_resolver.lifetime == 7
    assert handler.dnspython_resolver.nameservers == expected_nameservers


async def test_nxdomain_with_takeover_returns_true(handler, domain_context):
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=True)
    error = make_error(NXDOMAIN)

    result = await handler.handle_domain_resolution_errors(
        domain_context, "example.com", error, final_retry=False
    )

    assert result == (True, [])


async def test_dnspython_success_preserves_addresses(handler, domain_context):
    """When aiodns fails, fallback addresses remain available to the pipeline."""
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)
    handler.dnspython_resolver.resolve = MagicMock(
        side_effect=[["192.0.2.10"], ["2001:db8::10"]]
    )
    error = make_error(NXDOMAIN)

    result = await handler.handle_domain_resolution_errors(
        domain_context, "example.com", error, final_retry=True
    )

    assert result == (True, ["192.0.2.10", "2001:db8::10"])
    record_types = [
        call.args[1] for call in handler.dnspython_resolver.resolve.call_args_list
    ]
    assert sorted(record_types) == ["A", "AAAA"]
    handler.takeover_detector.handle_takeover_checks.assert_not_called()
    domain_context.env_manager.write_to_file.assert_not_called()


async def test_dnspython_noanswer_returns_false(handler, domain_context):
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)
    handler.dnspython_resolver.resolve = MagicMock(side_effect=dns.resolver.NoAnswer)
    error = make_error(NXDOMAIN)

    result = await handler.handle_domain_resolution_errors(
        domain_context, "example.com", error, final_retry=False
    )

    assert result == (False, [])


async def test_dnspython_nxdomain_runs_takeover_check(handler, domain_context):
    """A dnspython NXDOMAIN also triggers a takeover check."""
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)
    handler.dnspython_resolver.resolve = MagicMock(side_effect=dns.resolver.NXDOMAIN)
    error = make_error(NXDOMAIN)

    await handler.handle_domain_resolution_errors(
        domain_context, "example.com", error, final_retry=False
    )

    assert handler.takeover_detector.handle_takeover_checks.call_count == 1


async def test_nonfinal_failure_does_not_write_unresolved(
    handler, domain_context, mock_env_manager
):
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)
    handler.dnspython_resolver.resolve = MagicMock(side_effect=dns.exception.Timeout)

    result = await handler.handle_domain_resolution_errors(
        domain_context, "example.com", make_error(TIMEOUT), final_retry=False
    )

    assert result == (False, [])
    mock_env_manager.write_to_file.assert_not_called()


async def test_servfail_final_retry_logs_contact_message(
    handler, domain_context, mock_env_manager
):
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)
    handler.dnspython_resolver.resolve = MagicMock(side_effect=dns.resolver.NoAnswer)
    error = make_error(SERVFAIL)

    await handler.handle_domain_resolution_errors(
        domain_context, "example.com", error, final_retry=True
    )

    calls = [str(c) for c in mock_env_manager.write_to_file.call_args_list]
    assert any("Could not contact DNS servers" in c for c in calls)


async def test_non_servfail_final_retry_logs_without_extra_message(
    handler, domain_context, mock_env_manager
):
    handler.takeover_detector.handle_takeover_checks = AsyncMock(return_value=False)
    handler.dnspython_resolver.resolve = MagicMock(side_effect=dns.resolver.NoAnswer)
    error = make_error(NXDOMAIN)

    await handler.handle_domain_resolution_errors(
        domain_context, "example.com", error, final_retry=True
    )

    mock_env_manager.write_to_file.assert_called_once()
    _, content = mock_env_manager.write_to_file.call_args[0]
    assert "Could not contact DNS servers" not in content


def test_categorise_domain_matches_known_pattern():
    patterns = {
        "heroku": {
            "regex": r"\.herokuapp\.com\.",
            "recommendation": "Remove if dangling",
            "evidence": "https://devcenter.heroku.com",
        }
    }
    category, recommendation, _ = DomainCategoriser.categorise_domain(
        "myapp.herokuapp.com.", patterns
    )
    assert category == "heroku"
    assert recommendation == "Remove if dangling"


def test_categorise_domain_returns_unknown_when_no_match():
    category, recommendation, evidence = DomainCategoriser.categorise_domain(
        "example.com",
        {
            "heroku": {
                "regex": r"\.herokuapp\.com\.",
                "recommendation": "",
                "evidence": "",
            }
        },
    )
    assert category == "unknown"
    assert recommendation == "Unclassified"
    assert evidence == "N/A"
