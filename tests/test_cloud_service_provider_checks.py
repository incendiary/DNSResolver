"""
Tests for cloud_service_provider_checks.

This module is pure Python (ipaddress + file I/O) so it's very testable.
`tmp_path` is a built-in pytest fixture that provides a fresh temporary
directory for each test — perfect for functions that write output files.
"""

import ipaddress

import pytest

from classes.domain_processing_context import DomainProcessingContext
from imports.cloud_service_provider_checks import (
    get_ip_matches,
    get_vendor_ips,
    is_ip_version,
    log_and_write,
    match_ip_with_vendors,
    merge_matches,
    parse_network,
    perform_csp_checks,
)

# ---------------------------------------------------------------------------
# Fixture: a domain context pre-loaded with test IP ranges
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx(mock_env_manager, csp_ips):
    context = DomainProcessingContext(mock_env_manager, csp_ips)
    context.set_domain("example.com")
    return context


# ---------------------------------------------------------------------------
# is_ip_version
# ---------------------------------------------------------------------------


def test_is_ip_version_ipv4_correct():
    assert is_ip_version("34.1.2.3", 4) is True


def test_is_ip_version_ipv4_rejected_for_v6():
    assert is_ip_version("34.1.2.3", 6) is False


def test_is_ip_version_ipv6_correct():
    assert is_ip_version("2600:1900::1", 6) is True


def test_is_ip_version_ipv6_rejected_for_v4():
    assert is_ip_version("2600:1900::1", 4) is False


# ---------------------------------------------------------------------------
# get_vendor_ips
# ---------------------------------------------------------------------------


def test_get_vendor_ips_ipv4_returns_correct_ranges(ctx, csp_ips):
    result = get_vendor_ips(ctx, ip_version=4)
    assert result["gcp"] == csp_ips.get_gcp_ipv4()
    assert result["aws"] == csp_ips.get_aws_ipv4()
    assert result["azure"] == csp_ips.get_azure_ipv4()


def test_get_vendor_ips_ipv6_returns_correct_ranges(ctx, csp_ips):
    result = get_vendor_ips(ctx, ip_version=6)
    assert result["gcp"] == csp_ips.get_gcp_ipv6()
    assert result["aws"] == csp_ips.get_aws_ipv6()
    assert result["azure"] == csp_ips.get_azure_ipv6()


def test_get_vendor_ips_unknown_version_returns_empty(ctx):
    assert get_vendor_ips(ctx, ip_version=99) == {}


# ---------------------------------------------------------------------------
# match_ip_with_vendors
# ---------------------------------------------------------------------------


def test_match_ip_with_vendors_records_match(ctx):
    ip_obj = ipaddress.IPv4Address("34.1.2.3")
    vendor_ips = {"gcp": ["34.0.0.0/8"], "aws": [], "azure": []}
    matches = {"gcp": {}, "aws": {}, "azure": {}}

    match_ip_with_vendors(ip_obj, vendor_ips, ctx, matches)

    assert "34.1.2.3" in matches["gcp"]
    # The matched prefix is retained — it is the key to region and service.
    assert matches["gcp"]["34.1.2.3"] == "34.0.0.0/8"
    assert matches["aws"] == {}


def test_match_ip_with_vendors_no_match(ctx):
    ip_obj = ipaddress.IPv4Address("1.2.3.4")
    vendor_ips = {"gcp": ["34.0.0.0/8"]}
    matches = {"gcp": {}}

    match_ip_with_vendors(ip_obj, vendor_ips, ctx, matches)

    assert matches["gcp"] == {}


def test_match_ip_with_vendors_ignores_invalid_range(ctx):
    """A bad CIDR string should not crash — it's logged and skipped."""
    ip_obj = ipaddress.IPv4Address("1.2.3.4")
    vendor_ips = {"gcp": ["not-a-valid-cidr"]}
    matches = {"gcp": {}}

    match_ip_with_vendors(ip_obj, vendor_ips, ctx, matches)

    assert matches["gcp"] == {}


# ---------------------------------------------------------------------------
# merge_matches
# ---------------------------------------------------------------------------


def test_merge_matches_combines_ipv4_and_ipv6():
    """Both families merge, each address keeping the prefix it matched."""
    v4 = {"gcp": {"1.2.3.4": "1.2.0.0/16"}, "aws": {}}
    v6 = {"gcp": {"::1": "::/64"}, "aws": {}}
    vendor_context = {"gcp": [], "aws": []}

    result = merge_matches(v4, v6, vendor_context)

    assert result["gcp"] == {"1.2.3.4": "1.2.0.0/16", "::1": "::/64"}
    assert result["aws"] == {}


def test_merge_matches_empty_sets():
    v4 = {"gcp": {}}
    v6 = {"gcp": {}}
    result = merge_matches(v4, v6, {"gcp": []})
    assert result["gcp"] == {}


# ---------------------------------------------------------------------------
# get_ip_matches
# ---------------------------------------------------------------------------


def test_get_ip_matches_finds_gcp_ipv4(ctx, csp_ips):
    # 34.1.2.3 falls in GCP's 34.0.0.0/8 range (from conftest)
    result = get_ip_matches(["34.1.2.3"], get_vendor_ips(ctx, 4), ctx, ip_version=4)
    assert result["gcp"]["34.1.2.3"] == "34.0.0.0/8"


def test_get_ip_matches_skips_wrong_ip_version(ctx):
    # An IPv6 address should be skipped when looking for IPv4 matches
    result = get_ip_matches(["2600:1900::1"], get_vendor_ips(ctx, 4), ctx, ip_version=4)
    assert all(len(m) == 0 for m in result.values())


# ---------------------------------------------------------------------------
# log_and_write  (uses tmp_path for real file I/O)
# ---------------------------------------------------------------------------


def test_log_and_write_creates_entry(tmp_path, ctx):
    out_file = tmp_path / "csp.txt"
    out_file.touch()
    output_files = {"standard": {"csp": str(out_file)}}

    result = log_and_write(
        "gcp", {"34.1.2.3": "34.0.0.0/8"}, "example.com", output_files, ctx, set()
    )

    assert result is True
    # One handoff record per address: domain|ip|provider|region|service|prefix.
    # Region and service are what make the match actionable downstream.
    assert (
        out_file.read_text().strip()
        == "example.com|34.1.2.3|gcp|europe-west2|Google Cloud|34.0.0.0/8|unknown"
    )


def test_log_and_write_no_duplicate_entries(tmp_path, ctx):
    """Writing the same match twice should not produce duplicate lines."""
    out_file = tmp_path / "csp.txt"
    out_file.touch()
    output_files = {"standard": {"csp": str(out_file)}}
    written_lines = set()

    first = log_and_write(
        "gcp",
        {"34.1.2.3": "34.0.0.0/8"},
        "example.com",
        output_files,
        ctx,
        written_lines,
    )
    second = log_and_write(
        "gcp",
        {"34.1.2.3": "34.0.0.0/8"},
        "example.com",
        output_files,
        ctx,
        written_lines,
    )

    assert first is True
    assert second is False
    lines = [ln for ln in out_file.read_text().splitlines() if ln]
    assert len(lines) == 1


def test_log_and_write_no_full_file_read(tmp_path, ctx, monkeypatch):
    """log_and_write must not open the output file for reading — only append."""
    out_file = tmp_path / "csp.txt"
    out_file.touch()
    output_files = {"standard": {"csp": str(out_file)}}
    written_lines = set()

    real_open = open

    def guarded_open(file, mode="r", *args, **kwargs):
        if "r" in mode and "a" not in mode and "w" not in mode:
            raise AssertionError("log_and_write must not read the output file")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", guarded_open)

    log_and_write(
        "gcp",
        {"34.1.2.3": "34.0.0.0/8"},
        "example.com",
        output_files,
        ctx,
        written_lines,
    )

    assert "example.com|34.1.2.3|gcp|" in out_file.read_text()


def test_log_and_write_substring_line_not_suppressed(tmp_path, ctx):
    """A different line that happens to be a substring of an existing line
    must NOT be treated as a duplicate (the old file.read()-substring check
    would have falsely deduped this)."""
    out_file = tmp_path / "csp.txt"
    out_file.touch()
    output_files = {"standard": {"csp": str(out_file)}}
    written_lines = set()

    # "example.com|34.1.2.3|..." contains "ple.com|34.1.2.3|..." as a substring
    # (example.com = exam + ple.com), but they are different domains/lines.
    first = log_and_write(
        "gcp",
        {"34.1.2.3": "34.0.0.0/8"},
        "example.com",
        output_files,
        ctx,
        written_lines,
    )
    second = log_and_write(
        "gcp", {"34.1.2.3": "34.0.0.0/8"}, "ple.com", output_files, ctx, written_lines
    )

    assert first is True
    assert second is True
    lines = [ln for ln in out_file.read_text().splitlines() if ln]
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# perform_csp_checks  (end-to-end through the module)
# ---------------------------------------------------------------------------


def test_perform_csp_checks_matches_gcp_ip(tmp_path, mock_env_manager, ctx):
    csp_file = tmp_path / "csp.txt"
    csp_file.touch()
    mock_env_manager.output_files = {
        "standard": {
            "csp": str(csp_file),
        }
    }

    result = perform_csp_checks(ctx, mock_env_manager, ["34.1.2.3"])

    assert result is True
    assert "example.com" in csp_file.read_text()


def test_perform_csp_checks_no_match_returns_false(tmp_path, mock_env_manager, ctx):
    csp_file = tmp_path / "csp.txt"
    csp_file.touch()
    mock_env_manager.output_files = {
        "standard": {
            "csp": str(csp_file),
        }
    }

    result = perform_csp_checks(
        ctx, mock_env_manager, ["192.0.2.1"]
    )  # TEST-NET, no match

    assert result is False


def test_perform_csp_checks_dedupes_across_calls_on_same_env_manager(tmp_path, ctx):
    """The run-scoped written-lines set must live on env_manager and persist
    across multiple perform_csp_checks calls (one per domain in a real run),
    so the same match for the same domain is only written once."""

    class RealishEnvManager:
        """A plain object (not a MagicMock) so hasattr() behaves normally —
        MagicMock auto-creates attributes, which would hide a missing
        lazy-init of _csp_written_lines."""

        def __init__(self, output_files):
            self.output_files = output_files

    csp_file = tmp_path / "csp.txt"
    csp_file.touch()
    env_manager = RealishEnvManager({"standard": {"csp": str(csp_file)}})

    assert not hasattr(env_manager, "_csp_written_lines")

    first = perform_csp_checks(ctx, env_manager, ["34.1.2.3"])
    assert hasattr(env_manager, "_csp_written_lines")
    second = perform_csp_checks(ctx, env_manager, ["34.1.2.3"])

    assert first is True
    assert second is False  # same domain + same match already logged
    lines = [ln for ln in csp_file.read_text().splitlines() if ln]
    assert len(lines) == 1


# ---------------------------------------------------------------------------
# parse_network — CIDR parsed once and reused (C1)
# ---------------------------------------------------------------------------


def test_parse_network_equivalence_ip_inside_and_outside_range(ctx):
    """A known IP INSIDE a known vendor CIDR, and a known IP outside all
    ranges, must produce the exact same match result as naive per-IP
    ipaddress.ip_network() parsing would."""
    vendor_ips = {"gcp": ["34.0.0.0/8"], "aws": ["10.0.0.0/8"], "azure": []}

    inside_ip = ipaddress.IPv4Address("34.1.2.3")
    outside_ip = ipaddress.IPv4Address("8.8.8.8")

    matches = {"gcp": {}, "aws": {}, "azure": {}}
    match_ip_with_vendors(inside_ip, vendor_ips, ctx, matches)
    match_ip_with_vendors(outside_ip, vendor_ips, ctx, matches)

    assert matches == {"gcp": {"34.1.2.3": "34.0.0.0/8"}, "aws": {}, "azure": {}}


def test_parse_network_is_memoised_across_calls():
    """Each distinct CIDR string should only be parsed once, no matter how
    many times match_ip_with_vendors/get_ip_matches is invoked against it."""
    parse_network.cache_clear()
    cidr = "203.0.113.0/24"

    parse_network(cidr)
    hits_before = parse_network.cache_info().hits
    misses_before = parse_network.cache_info().misses

    # Call it many more times, as would happen across many resolved IPs.
    for _ in range(50):
        parse_network(cidr)

    info = parse_network.cache_info()
    assert misses_before == 1
    assert info.misses == 1  # never re-parsed
    assert info.hits == hits_before + 50


def test_match_ip_with_vendors_reuses_cached_network(ctx):
    """Matching several IPs against the same vendor CIDR list should not
    re-parse the CIDR strings for each IP."""
    parse_network.cache_clear()
    vendor_ips = {"gcp": ["34.0.0.0/8", "35.0.0.0/8"], "aws": [], "azure": []}
    matches = {"gcp": {}, "aws": {}, "azure": {}}

    ips = [ipaddress.IPv4Address(f"34.1.2.{i}") for i in range(10)]
    for ip in ips:
        match_ip_with_vendors(ip, vendor_ips, ctx, matches)

    info = parse_network.cache_info()
    # Only the 2 distinct CIDR strings should ever be parsed (misses == 2),
    # regardless of how many IPs (10) were checked against them.
    assert info.misses == 2
    assert info.hits == 10 * 2 - 2


def test_handoff_record_carries_region_and_service_end_to_end(
    tmp_path, mock_env_manager, ctx
):
    """
    The whole point of the CSP output: a downstream tool must be able to read
    where an address is allocated from and what it belongs to, without going
    back to the provider's range files.
    """
    out_file = tmp_path / "csp.txt"
    out_file.touch()
    mock_env_manager.output_files = {"standard": {"csp": str(out_file)}}

    # 3.1.2.3 falls in AWS 3.0.0.0/8, published as eu-west-2 / EC2 in conftest.
    perform_csp_checks(ctx, mock_env_manager, ["3.1.2.3"])

    line = out_file.read_text().strip()
    assert line == "example.com|3.1.2.3|aws|eu-west-2|EC2|3.0.0.0/8|eu-west-2"

    domain, ip, provider, region, service, prefix, border = line.split("|")
    assert (provider, region, service) == ("aws", "eu-west-2", "EC2")
    # The border group is the boundary an Elastic IP is allocated from.
    assert border == "eu-west-2"


def test_each_matched_address_gets_its_own_record(tmp_path, mock_env_manager, ctx):
    """
    One line per address, not one line per domain with a list. Addresses in the
    same provider can sit in different regions, and a consumer acts per address.
    """
    out_file = tmp_path / "csp.txt"
    out_file.touch()
    mock_env_manager.output_files = {"standard": {"csp": str(out_file)}}

    # 3.x -> eu-west-2/EC2, 52.x -> us-east-1/AMAZON (both AWS, different regions)
    perform_csp_checks(ctx, mock_env_manager, ["3.1.2.3", "52.1.2.3"])

    lines = sorted(ln for ln in out_file.read_text().splitlines() if ln)
    assert lines == [
        "example.com|3.1.2.3|aws|eu-west-2|EC2|3.0.0.0/8|eu-west-2",
        "example.com|52.1.2.3|aws|us-east-1|AMAZON|52.0.0.0/8|us-east-1",
    ]


# ---------------------------------------------------------------------------
# Wildcard resolutions in cloud space
#
# A catch-all address belongs to the hosting platform and is in active use, so
# it is the opposite of a claimable target. Unmarked, a single wildcarded zone
# emits one cloud record per enumerated subdomain and buries the real findings.
# ---------------------------------------------------------------------------


def test_wildcard_cloud_match_is_marked(tmp_path, mock_env_manager, ctx):
    out_file = tmp_path / "csp.txt"
    out_file.touch()
    mock_env_manager.output_files = {"standard": {"csp": str(out_file)}}

    perform_csp_checks(ctx, mock_env_manager, ["3.1.2.3"], is_wildcard=True)

    line = out_file.read_text().strip()
    assert line.startswith("WILDCARD|")
    # The record is still complete — marked, not degraded.
    assert line == "WILDCARD|example.com|3.1.2.3|aws|eu-west-2|EC2|3.0.0.0/8|eu-west-2"


def test_ordinary_cloud_match_is_not_marked(tmp_path, mock_env_manager, ctx):
    """A real host's cloud match must keep its existing shape."""
    out_file = tmp_path / "csp.txt"
    out_file.touch()
    mock_env_manager.output_files = {"standard": {"csp": str(out_file)}}

    perform_csp_checks(ctx, mock_env_manager, ["3.1.2.3"], is_wildcard=False)

    assert not out_file.read_text().startswith("WILDCARD|")


def test_wildcard_defaults_to_false_for_existing_callers(
    tmp_path, mock_env_manager, ctx
):
    """Omitting the flag must not silently mark everything as a wildcard."""
    out_file = tmp_path / "csp.txt"
    out_file.touch()
    mock_env_manager.output_files = {"standard": {"csp": str(out_file)}}

    perform_csp_checks(ctx, mock_env_manager, ["3.1.2.3"])

    assert not out_file.read_text().startswith("WILDCARD|")
