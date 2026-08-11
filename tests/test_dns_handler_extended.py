"""
Additional DNSHandler tests — covering the paths not reached by the
existing test_dns_handler.py:

  - check_ns_takeover
  - handle_takeover_checks
  - log_and_write_dns_error
  - collect_evidence (evidence disabled / enabled paths)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import aiodns
import pytest

from classes.dns_constants import NXDOMAIN, SERVFAIL
from classes.dns_handler import DNSHandler

# ---------------------------------------------------------------------------
# Shared helpers (duplicated from test_dns_handler.py for clarity)
# ---------------------------------------------------------------------------


def make_nxdomain():
    return aiodns.error.DNSError(NXDOMAIN, "Domain not found")


def make_servfail():
    return aiodns.error.DNSError(SERVFAIL, "Server failure")


def dns_answer(value, attr="host"):
    a = MagicMock()
    setattr(a, attr, value)
    return a


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
# log_and_write_dns_error
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# collect_evidence
# ---------------------------------------------------------------------------


async def test_collect_evidence_skipped_when_disabled(handler, mock_env_manager):
    mock_env_manager.evidence = False
    output_files = mock_env_manager.output_files

    await handler.takeover_detector.collect_evidence(
        "example.com", "dangling", output_files
    )

    handler.takeover_detector.evidence_collector.perform_dns_evidence.assert_not_called()


async def test_collect_evidence_called_per_nameserver(handler, mock_env_manager):
    mock_env_manager.evidence = True
    mock_env_manager.nameservers = ["8.8.8.8", "1.1.1.1"]
    handler.takeover_detector.evidence_collector.perform_dns_evidence = AsyncMock()
    output_files = mock_env_manager.output_files

    await handler.takeover_detector.collect_evidence(
        "example.com", "dangling", output_files
    )

    assert (
        handler.takeover_detector.evidence_collector.perform_dns_evidence.call_count
        == 2
    )


# ---------------------------------------------------------------------------
# check_ns_takeover
# ---------------------------------------------------------------------------


async def test_check_ns_takeover_returns_false_when_ns_resolves(
    handler, domain_context
):
    """If the NS record for the domain resolves fine there is no takeover risk."""
    ns_record = dns_answer("ns1.example.com", attr="host")
    # NS query succeeds, A query for ns1 also succeeds
    handler.takeover_detector.aiodns_resolver.query = AsyncMock(
        return_value=[ns_record]
    )

    result = await handler.takeover_detector.check_ns_takeover(
        domain_context, "example.com"
    )

    assert result is False


async def test_check_ns_takeover_returns_true_when_ns_is_nxdomain(
    handler, domain_context, mock_env_manager
):
    """If the nameserver itself is NXDOMAIN, a takeover may be possible."""
    ns_record = dns_answer("ns1.orphaned.com", attr="host")

    async def query_side_effect(domain, record_type):
        if record_type == "NS":
            return [ns_record]
        raise make_nxdomain()  # A lookup for the NS host fails

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    result = await handler.takeover_detector.check_ns_takeover(
        domain_context, "orphaned.example.com"
    )

    assert result is True
    mock_env_manager.write_to_file.assert_called_once()
    path, content = mock_env_manager.write_to_file.call_args[0]
    assert "takeover" in path


async def test_check_ns_takeover_returns_false_when_no_ns_records(
    handler, domain_context
):
    """NXDOMAIN on the NS query itself means no NS records — no takeover."""
    handler.takeover_detector.aiodns_resolver.query = AsyncMock(
        side_effect=make_nxdomain()
    )

    result = await handler.takeover_detector.check_ns_takeover(
        domain_context, "example.com"
    )

    assert result is False


# ---------------------------------------------------------------------------
# handle_takeover_checks
# ---------------------------------------------------------------------------


async def test_handle_takeover_checks_adds_dangling_domain_when_dangling(
    handler, domain_context
):
    handler.takeover_detector.check_dangling_cname_async = AsyncMock(return_value=True)
    handler.takeover_detector.check_ns_takeover = AsyncMock(return_value=False)

    await handler.takeover_detector.handle_takeover_checks(
        domain_context, "cname-target.example.com"
    )

    assert "cname-target.example.com" in domain_context.dangling_domains


async def test_handle_takeover_checks_adds_domain_when_ns_takeover(
    handler, domain_context
):
    handler.takeover_detector.check_dangling_cname_async = AsyncMock(return_value=False)
    handler.takeover_detector.check_ns_takeover = AsyncMock(return_value=True)

    await handler.takeover_detector.handle_takeover_checks(
        domain_context, "ns-vuln.example.com"
    )

    assert "ns-vuln.example.com" in domain_context.dangling_domains


async def test_handle_takeover_checks_returns_true_when_either_detected(
    handler, domain_context
):
    handler.takeover_detector.check_dangling_cname_async = AsyncMock(return_value=False)
    handler.takeover_detector.check_ns_takeover = AsyncMock(return_value=True)

    result = await handler.takeover_detector.handle_takeover_checks(
        domain_context, "example.com"
    )

    assert result is True


async def test_handle_takeover_checks_returns_false_when_neither_detected(
    handler, domain_context
):
    handler.takeover_detector.check_dangling_cname_async = AsyncMock(return_value=False)
    handler.takeover_detector.check_ns_takeover = AsyncMock(return_value=False)

    result = await handler.takeover_detector.handle_takeover_checks(
        domain_context, "example.com"
    )

    assert result is False
    assert len(domain_context.dangling_domains) == 0
