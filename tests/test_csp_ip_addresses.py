"""
Tests for CSPIPAddresses.

This is the simplest test file — no mocking, no async, just plain
assert statements.  A good place to start if you've never written tests.

Each test function is independent.  pytest discovers them automatically
because their names start with "test_".
"""

from classes.csp_ip_addresses import CSPIPAddresses

# Reuse the same test data across all tests in this file
GCP_IPV4 = ["34.0.0.0/8", "35.0.0.0/8"]
GCP_IPV6 = ["2600:1900::/35"]
AWS_IPV4 = ["3.0.0.0/8"]
AWS_IPV6 = ["2600:1f00::/25"]
AZURE_IPV4 = ["13.0.0.0/8"]
AZURE_IPV6 = ["2603:1000::/24"]


def make_csp():
    return CSPIPAddresses(
        GCP_IPV4, GCP_IPV6, AWS_IPV4, AWS_IPV6, AZURE_IPV4, AZURE_IPV6
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_stores_all_ranges_on_construction():
    """All six IP range lists are stored correctly."""
    csp = make_csp()
    assert csp.get_gcp_ipv4() == GCP_IPV4
    assert csp.get_gcp_ipv6() == GCP_IPV6
    assert csp.get_aws_ipv4() == AWS_IPV4
    assert csp.get_aws_ipv6() == AWS_IPV6
    assert csp.get_azure_ipv4() == AZURE_IPV4
    assert csp.get_azure_ipv6() == AZURE_IPV6


# ---------------------------------------------------------------------------
# Individual getters — each test is narrow so a failure points to one thing
# ---------------------------------------------------------------------------


def test_gcp_ipv4_is_distinct_from_gcp_ipv6():
    """IPv4 and IPv6 getters must not be swapped (this caught a real bug)."""
    csp = make_csp()
    assert csp.get_gcp_ipv4() != csp.get_gcp_ipv6()


def test_accepts_empty_ranges():
    """CSPIPAddresses should work fine when a provider has no ranges."""
    csp = CSPIPAddresses([], [], [], [], [], [])
    assert csp.get_gcp_ipv4() == []
    assert csp.get_aws_ipv6() == []


def test_ranges_are_returned_by_reference():
    """Getters return the original list, not a copy — mutations are visible."""
    original = ["10.0.0.0/8"]
    csp = CSPIPAddresses(original, [], [], [], [], [])
    csp.get_gcp_ipv4().append("192.168.0.0/16")
    assert len(original) == 2
