"""
Tests for DNSHandler.

Two new ideas appear here:

1. Mocking network calls — instead of making real DNS queries we replace
   aiodns.DNSResolver with a fake object whose responses we control.
   This keeps tests fast, deterministic, and runnable offline.

2. Async tests — any `async def test_*` function is run inside an asyncio
   event loop automatically (configured via asyncio_mode = auto in pytest.ini).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import aiodns
import pytest

from classes.dns_constants import NO_DATA, NXDOMAIN, SERVFAIL, TIMEOUT, is_dns_error_present
from classes.dns_handler import DNSHandler

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


# ---------------------------------------------------------------------------
# Fixture: a DNSHandler with all external dependencies replaced by mocks
# ---------------------------------------------------------------------------


@pytest.fixture
async def handler(mock_env_manager):
    """
    Build a DNSHandler without touching the network.

    The fixture is async so it runs inside an event loop — required because
    aiodns.DNSResolver() calls asyncio.get_event_loop() in its __init__.
    We patch both it and EvidenceCollector so no real I/O happens, then
    replace the resolvers with controllable AsyncMock / MagicMock objects.
    """
    with (
        patch("classes.dns_handler.aiodns.DNSResolver"),
        patch("classes.takeover_detector.EvidenceCollector"),
    ):
        h = DNSHandler(mock_env_manager)

    # Replace with controllable fakes. TakeoverDetector was constructed with
    # the original aiodns resolver reference, so reassign both to the same mock.
    mock_aiodns = AsyncMock()
    h.aiodns_resolver = mock_aiodns
    h.dnspython_resolver = MagicMock()
    h.takeover_detector.aiodns_resolver = mock_aiodns
    return h


@pytest.fixture
def domain_context(mock_env_manager, csp_ips):
    """A minimal DomainProcessingContext."""
    from classes.domain_processing_context import DomainProcessingContext

    ctx = DomainProcessingContext(mock_env_manager, csp_ips)
    ctx.set_domain("example.com")
    return ctx


# ---------------------------------------------------------------------------
# is_dns_error_present
# ---------------------------------------------------------------------------


def test_is_dns_error_present_matches_correct_code():
    error = make_nxdomain()
    assert is_dns_error_present(error, [NXDOMAIN]) is True


def test_is_dns_error_present_no_match():
    error = make_timeout()
    assert is_dns_error_present(error, [NXDOMAIN, SERVFAIL]) is False


# ---------------------------------------------------------------------------
# resolve_domain_async — happy path
# ---------------------------------------------------------------------------


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
    resolve_domain_async makes exactly one DNS query per call.
    Retry orchestration is the responsibility of the outer run() loop,
    not the handler itself.
    """
    handler.aiodns_resolver.query = AsyncMock(side_effect=make_nxdomain())
    handler.handle_domain_resolution_errors = AsyncMock(return_value=(False, []))

    await handler.resolve_domain_async(domain_context)

    assert handler.aiodns_resolver.query.call_count == 1


# ---------------------------------------------------------------------------
# check_dangling_cname_async
# ---------------------------------------------------------------------------


async def test_check_dangling_cname_not_dangling_has_a_record(handler, domain_context):
    """
    If the CNAME target resolves to an A record the domain is not dangling.

    We set up query() to:
      - raise NXDOMAIN for CNAME (no CNAME record, proceed to A/AAAA/MX check)
      - return a real answer for A (domain still alive → not dangling)
    """

    async def query_side_effect(domain, record_type):
        if record_type == "CNAME":
            raise make_nxdomain()
        if record_type == "A":
            return [dns_answer("1.2.3.4")]
        raise make_nxdomain()

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "target.example.com"
    )

    assert result is False


async def test_check_dangling_cname_is_dangling_no_records(
    handler, domain_context, mock_env_manager
):
    """
    When A, AAAA, MX, and NS all return NXDOMAIN the domain is dangling.
    The handler should write to the dangling file and return True.
    """
    handler.takeover_detector.aiodns_resolver.query = AsyncMock(
        side_effect=make_nxdomain()
    )

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "gone.example.com"
    )

    assert result is True
    # Verify the result was written to the dangling output file
    mock_env_manager.write_to_file.assert_called_once()
    call_args = mock_env_manager.write_to_file.call_args
    assert "/tmp/test_takeover.txt" in call_args[0]


async def test_check_dangling_cname_timeout_is_not_dangling(handler, domain_context):
    """
    A timeout on A/AAAA/MX means we can't confirm the domain is gone.
    We conservatively return False to avoid false positives.
    """

    async def query_side_effect(domain, record_type):
        if record_type == "CNAME":
            raise make_nxdomain()
        raise make_timeout()  # all other record types time out

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "slow.example.com"
    )

    assert result is False
