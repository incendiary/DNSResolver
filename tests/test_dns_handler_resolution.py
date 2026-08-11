"""
Tests for the harder-to-reach dns_handler paths:

  - handle_domain_resolution_errors (dnspython fallback, SERVFAIL logging)
  - check_dangling_cname_async (CNAME chain, A/AAAA/MX success, NO_DATA, TIMEOUT)
  - categorise_domain (match and no-match)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import aiodns
import dns.exception
import dns.resolver
import pytest

from classes.dns_constants import NO_DATA, NXDOMAIN, SERVFAIL, TIMEOUT
from classes.dns_handler import DNSHandler
from classes.domain_categoriser import DomainCategoriser


def make_error(code):
    return aiodns.error.DNSError(code, "test error")


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


@pytest.fixture
async def handler(mock_env_manager):
    with (
        patch("classes.dns_handler.aiodns.DNSResolver"),
        patch("classes.dns_handler.dns.resolver.Resolver"),
        patch("classes.takeover_detector.EvidenceCollector"),
    ):
        h = DNSHandler(mock_env_manager)
    # TakeoverDetector holds the resolver by reference from construction time,
    # so reassign both to the same mock to keep them in sync.
    mock_aiodns = AsyncMock()
    h.aiodns_resolver = mock_aiodns
    h.dnspython_resolver = MagicMock()
    h.takeover_detector.aiodns_resolver = mock_aiodns
    return h


@pytest.fixture
def domain_context(mock_env_manager, csp_ips):
    from classes.domain_processing_context import DomainProcessingContext

    ctx = DomainProcessingContext(mock_env_manager, csp_ips)
    ctx.set_domain("example.com")
    return ctx


# ---------------------------------------------------------------------------
# handle_domain_resolution_errors
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# check_dangling_cname_async
# ---------------------------------------------------------------------------


async def test_cname_chain_dangling_returns_true(handler, domain_context):
    """CNAME → target → all records NXDOMAIN → dangling."""
    cname_result = MagicMock()
    cname_result.cname = "target.example.com"

    async def query_side_effect(domain, record_type):
        if record_type == "CNAME" and domain == "example.com":
            return cname_result
        raise make_error(NXDOMAIN)

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "example.com"
    )

    assert result is True


async def test_cname_target_without_trailing_dot_is_normalised(handler, domain_context):
    """aiodns returns CNAME targets without trailing dot; the normalisation must add one
    so that regex patterns ending with \\. match correctly."""
    received_targets = []
    cname_result = MagicMock()
    cname_result.cname = (
        "gbe8q5o.impervadns.net"  # no trailing dot — as aiodns returns it
    )

    async def query_side_effect(domain, record_type):
        if record_type == "CNAME" and domain == "example.com":
            return cname_result
        if domain != "example.com":
            received_targets.append(domain)
        raise make_error(NXDOMAIN)

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "example.com"
    )

    # The recursive call must use the normalised form with trailing dot
    assert any(t == "gbe8q5o.impervadns.net." for t in received_targets)


async def test_a_record_exists_not_dangling(handler, domain_context):
    """If the A record resolves, the domain is not dangling."""

    async def query_side_effect(domain, record_type):
        if record_type == "CNAME":
            raise make_error(NXDOMAIN)
        if record_type == "A":
            return [MagicMock()]  # success
        raise make_error(NXDOMAIN)

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "example.com"
    )

    assert result is False


async def test_no_data_on_a_continues_to_next_record(handler, domain_context):
    """NO_DATA on A should continue checking AAAA/MX, not short-circuit."""
    call_log = []

    async def query_side_effect(domain, record_type):
        call_log.append(record_type)
        if record_type == "CNAME":
            raise make_error(NXDOMAIN)
        if record_type == "A":
            raise make_error(NO_DATA)
        if record_type == "AAAA":
            return [MagicMock()]  # not dangling once AAAA succeeds
        raise make_error(NXDOMAIN)

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "example.com"
    )

    assert "AAAA" in call_log
    assert result is False


async def test_timeout_on_record_returns_false(handler, domain_context):
    """A TIMEOUT should be treated as 'not dangling' (inconclusive)."""

    async def query_side_effect(domain, record_type):
        if record_type == "CNAME":
            raise make_error(NXDOMAIN)
        raise make_error(TIMEOUT)

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "example.com"
    )

    assert result is False


async def test_cname_non_nxdomain_error_returns_false(handler, domain_context):
    """A non-NXDOMAIN error on the CNAME query means we can't conclude dangling."""

    async def query_side_effect(domain, record_type):
        raise make_error(SERVFAIL)

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "example.com"
    )

    assert result is False


# ---------------------------------------------------------------------------
# categorise_domain
# ---------------------------------------------------------------------------


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
