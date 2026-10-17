"""Each record's .pipe() is the exact line its output file has always held."""

from classes.records import CspMatch, Dangling, NsTakeover, Resolution, Unresolved


def test_resolution_pipe_lists_ips_in_order():
    assert (
        Resolution("a.example.com", ("192.0.2.1", "2001:db8::1")).pipe()
        == "a.example.com|192.0.2.1|2001:db8::1"
    )


def test_resolution_pipe_carries_wildcard_prefix():
    assert (
        Resolution("a.example.com", ("192.0.2.1",), "WILDCARD").pipe()
        == "WILDCARD|a.example.com|192.0.2.1"
    )
    assert (
        Resolution("a.example.com", ("192.0.2.1",), "WILDCARD_ZONE").pipe()
        == "WILDCARD_ZONE|a.example.com|192.0.2.1"
    )


def test_csp_match_pipe():
    match = CspMatch(
        "a.example.com", "192.0.2.1", "aws", "eu-west-2", "EC2", "192.0.2.0/24", "bg"
    )
    assert match.pipe() == "a.example.com|192.0.2.1|aws|eu-west-2|EC2|192.0.2.0/24|bg"


def test_csp_match_pipe_carries_wildcard_prefix():
    match = CspMatch(
        "a.example.com",
        "192.0.2.1",
        "gcp",
        "r",
        "s",
        "192.0.2.0/24",
        "unknown",
        "WILDCARD_ZONE",
    )
    assert match.pipe() == (
        "WILDCARD_ZONE|a.example.com|192.0.2.1|gcp|r|s|192.0.2.0/24|unknown"
    )


def test_equal_csp_matches_are_one_set_member():
    fields = ("a.example.com", "192.0.2.1", "aws", "r", "s", "192.0.2.0/24", "bg")
    assert len({CspMatch(*fields), CspMatch(*fields)}) == 1
    assert len({CspMatch(*fields), CspMatch(*fields, "WILDCARD")}) == 2


def test_dangling_pipe():
    record = Dangling(
        "a.example.com",
        "old.s3.amazonaws.com.",
        "s3",
        "Delete the CNAME",
        "https://example.com/e",
        1,
        "a.example.com -> old.s3.amazonaws.com",
    )
    assert record.pipe() == (
        "DANGLING|a.example.com|old.s3.amazonaws.com.|s3|Delete the CNAME"
        "|https://example.com/e|1|a.example.com -> old.s3.amazonaws.com"
    )


def test_ns_takeover_pipe():
    assert (
        NsTakeover("a.example.com", "ns.example.net").pipe()
        == "NS_TAKEOVER|a.example.com|ns.example.net"
    )


def test_unresolved_pipe_without_and_with_additional():
    plain = Unresolved("a.example.com", "(4, 'Domain name not found')")
    assert plain.reason == "(4, 'Domain name not found')"
    assert plain.pipe() == (
        "DNS resolution error for a.example.com: (4, 'Domain name not found')"
    )

    more = Unresolved("a.example.com", "(2, 'x')", "Could not contact DNS servers")
    assert more.reason == "(2, 'x')|Could not contact DNS servers"
    assert more.pipe() == (
        "DNS resolution error for a.example.com: (2, 'x')|Could not contact DNS servers"
    )
