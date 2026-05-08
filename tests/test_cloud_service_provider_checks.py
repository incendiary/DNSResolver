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
    matches = {"gcp": set(), "aws": set(), "azure": set()}

    match_ip_with_vendors(ip_obj, vendor_ips, ctx, matches)

    assert "34.1.2.3" in matches["gcp"]
    assert matches["aws"] == set()


def test_match_ip_with_vendors_no_match(ctx):
    ip_obj = ipaddress.IPv4Address("1.2.3.4")
    vendor_ips = {"gcp": ["34.0.0.0/8"]}
    matches = {"gcp": set()}

    match_ip_with_vendors(ip_obj, vendor_ips, ctx, matches)

    assert matches["gcp"] == set()


def test_match_ip_with_vendors_ignores_invalid_range(ctx):
    """A bad CIDR string should not crash — it's logged and skipped."""
    ip_obj = ipaddress.IPv4Address("1.2.3.4")
    vendor_ips = {"gcp": ["not-a-valid-cidr"]}
    matches = {"gcp": set()}

    match_ip_with_vendors(ip_obj, vendor_ips, ctx, matches)

    assert matches["gcp"] == set()


# ---------------------------------------------------------------------------
# merge_matches
# ---------------------------------------------------------------------------


def test_merge_matches_combines_ipv4_and_ipv6():
    v4 = {"gcp": {"1.2.3.4"}, "aws": set()}
    v6 = {"gcp": {"::1"}, "aws": set()}
    vendor_context = {"gcp": [], "aws": []}

    result = merge_matches(v4, v6, vendor_context)

    assert set(result["gcp"]) == {"1.2.3.4", "::1"}
    assert result["aws"] == []


def test_merge_matches_empty_sets():
    v4 = {"gcp": set()}
    v6 = {"gcp": set()}
    result = merge_matches(v4, v6, {"gcp": []})
    assert result["gcp"] == []


# ---------------------------------------------------------------------------
# get_ip_matches
# ---------------------------------------------------------------------------


def test_get_ip_matches_finds_gcp_ipv4(ctx, csp_ips):
    # 34.1.2.3 falls in GCP's 34.0.0.0/8 range (from conftest)
    result = get_ip_matches(["34.1.2.3"], get_vendor_ips(ctx, 4), ctx, ip_version=4)
    assert "34.1.2.3" in result["gcp"]


def test_get_ip_matches_skips_wrong_ip_version(ctx):
    # An IPv6 address should be skipped when looking for IPv4 matches
    result = get_ip_matches(["2600:1900::1"], get_vendor_ips(ctx, 4), ctx, ip_version=4)
    assert all(len(s) == 0 for s in result.values())


# ---------------------------------------------------------------------------
# log_and_write  (uses tmp_path for real file I/O)
# ---------------------------------------------------------------------------


def test_log_and_write_creates_entry(tmp_path, ctx):
    out_file = tmp_path / "gcp.txt"
    out_file.touch()
    output_files = {"standard": {"gcp": str(out_file)}}

    result = log_and_write("gcp", ["34.1.2.3"], "example.com", output_files, ctx)

    assert result is True
    assert "example.com resolved to gcp IPs" in out_file.read_text()


def test_log_and_write_no_duplicate_entries(tmp_path, ctx):
    """Writing the same match twice should not produce duplicate lines."""
    out_file = tmp_path / "gcp.txt"
    out_file.touch()
    output_files = {"standard": {"gcp": str(out_file)}}

    log_and_write("gcp", ["34.1.2.3"], "example.com", output_files, ctx)
    log_and_write("gcp", ["34.1.2.3"], "example.com", output_files, ctx)

    lines = [ln for ln in out_file.read_text().splitlines() if ln]
    assert len(lines) == 1


def test_log_and_write_empty_ips_returns_false(tmp_path, ctx):
    out_file = tmp_path / "gcp.txt"
    out_file.touch()
    output_files = {"standard": {"gcp": str(out_file)}}

    result = log_and_write("gcp", [], "example.com", output_files, ctx)

    assert result is False


# ---------------------------------------------------------------------------
# perform_csp_checks  (end-to-end through the module)
# ---------------------------------------------------------------------------


def test_perform_csp_checks_matches_gcp_ip(tmp_path, mock_env_manager, ctx):
    gcp_file = tmp_path / "gcp.txt"
    gcp_file.touch()
    aws_file = tmp_path / "aws.txt"
    aws_file.touch()
    azure_file = tmp_path / "azure.txt"
    azure_file.touch()
    mock_env_manager.get_output_files.return_value = {
        "standard": {
            "gcp": str(gcp_file),
            "aws": str(aws_file),
            "azure": str(azure_file),
        }
    }

    result = perform_csp_checks(ctx, mock_env_manager, ["34.1.2.3"])

    assert result is True
    assert "example.com" in gcp_file.read_text()


def test_perform_csp_checks_no_match_returns_false(tmp_path, mock_env_manager, ctx):
    for vendor in ("gcp", "aws", "azure"):
        (tmp_path / f"{vendor}.txt").touch()
    mock_env_manager.get_output_files.return_value = {
        "standard": {
            "gcp": str(tmp_path / "gcp.txt"),
            "aws": str(tmp_path / "aws.txt"),
            "azure": str(tmp_path / "azure.txt"),
        }
    }

    result = perform_csp_checks(
        ctx, mock_env_manager, ["192.0.2.1"]
    )  # TEST-NET, no match

    assert result is False
