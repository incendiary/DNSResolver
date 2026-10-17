"""Tests for TakeoverDetector: dangling CNAME, NS takeover and evidence collection."""

from unittest.mock import AsyncMock, MagicMock

import aiodns

from classes.dns_constants import NO_DATA, NXDOMAIN, SERVFAIL, TIMEOUT


def make_nxdomain():
    return aiodns.error.DNSError(NXDOMAIN, "Domain not found")


def make_timeout():
    return aiodns.error.DNSError(TIMEOUT, "Query timed out")


def make_error(code):
    return aiodns.error.DNSError(code, "test error")


def dns_answer(value, attr="host"):
    a = MagicMock()
    setattr(a, attr, value)
    return a


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
    A domain with a CNAME whose target has no A, AAAA, MX or NS record is
    dangling. The handler should write to the takeover file and return True.

    The CNAME is required: without one there is nothing to dangle, which is
    covered by test_check_dangling_cname_nxdomain_without_cname_is_not_a_candidate.
    """

    async def query_side_effect(domain, record_type):
        if record_type == "CNAME" and domain == "gone.example.com":
            cname = MagicMock()
            cname.cname = "unclaimed.example.net"
            return cname
        raise make_nxdomain()

    handler.takeover_detector.aiodns_resolver.query = query_side_effect

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "gone.example.com"
    )

    assert result is True
    # Verify the result was written to the dangling output file
    mock_env_manager.write_to_file.assert_called_once()
    call_args = mock_env_manager.write_to_file.call_args
    assert "/tmp/test_takeover.txt" in call_args[0]


async def test_check_dangling_cname_self_referential_classified_as_misconfiguration(
    handler, domain_context, mock_env_manager
):
    """
    A CNAME pointing to itself is a misconfiguration, not a takeover risk.
    It should be written with category 'self_referential', not 'unknown'.
    """

    async def query_side_effect(domain, record_type):
        if record_type == "CNAME":
            cname = MagicMock()
            # Target resolves back to the original domain (self-referential)
            cname.cname = "example.com"
            return cname
        raise make_nxdomain()

    handler.takeover_detector.aiodns_resolver.query = query_side_effect
    domain_context.set_domain("example.com")

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "example.com"
    )

    assert result is True
    call_args = mock_env_manager.write_to_file.call_args
    written_line = call_args[0][1]
    assert "self_referential" in written_line
    assert "points to itself" in written_line


async def test_check_dangling_cname_nxdomain_without_cname_is_not_a_candidate(
    handler, domain_context, mock_env_manager
):
    """
    A name that does not exist and has no CNAME is not a takeover candidate.

    Nothing is dangling: there is no CNAME pointing at an unclaimed resource,
    the name is simply absent from DNS. Reporting it as a candidate is a false
    positive that buries real findings, so no takeover line may be written.
    The caller still records the domain as unresolved.
    """
    handler.takeover_detector.aiodns_resolver.query = AsyncMock(
        side_effect=make_nxdomain()
    )
    domain_context.set_domain("dead.example.com")

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "dead.example.com"
    )

    assert result is False
    mock_env_manager.write_to_file.assert_not_called()


async def test_check_dangling_cname_real_dangling_cname_still_flagged(
    handler, domain_context, mock_env_manager
):
    """
    The complement of the test above: a domain whose CNAME target does not
    resolve is still reported as a takeover candidate. This guards against the
    no-CNAME fix suppressing genuine findings.
    """

    async def query_side_effect(domain, record_type):
        if record_type == "CNAME" and domain == "live.example.com":
            cname = MagicMock()
            cname.cname = "gone.cloudapp.net"
            return cname
        raise make_nxdomain()

    handler.takeover_detector.aiodns_resolver.query = query_side_effect
    domain_context.set_domain("live.example.com")

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "live.example.com"
    )

    assert result is True
    written_line = mock_env_manager.write_to_file.call_args[0][1]
    assert written_line.startswith("DANGLING|")
    assert "gone.cloudapp.net" in written_line


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
    assert content == ("NS_TAKEOVER|example.com|orphaned.example.com|ns1.orphaned.com")


async def test_delegated_name_without_address_records_has_no_nameserver(
    handler, domain_context, mock_env_manager
):
    """NS records but no A, AAAA or MX: no nameserver is implicated (`-`)."""

    async def query_side_effect(domain, record_type):
        if record_type == "NS":
            return [dns_answer("ns1.example.net", attr="host")]
        raise make_nxdomain()

    handler.takeover_detector.aiodns_resolver.query = query_side_effect
    domain_context.set_domain("deleg.example.com")

    result = await handler.takeover_detector.check_dangling_cname_async(
        domain_context, "deleg.example.com"
    )

    assert result is False
    path, content = mock_env_manager.write_to_file.call_args[0]
    assert content == "NS_TAKEOVER|deleg.example.com|deleg.example.com|-"


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
