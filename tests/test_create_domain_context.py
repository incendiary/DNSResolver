"""
Tests for create_domain_context factory.

The factory is a thin wrapper around DomainProcessingContext.__init__ that
also sets the domain and wires up the shared sets.  These tests verify that
wiring is correct — in particular that the passed-in sets are used by
reference (mutations in the context are visible to the caller).
"""

from imports.create_domain_context import create_domain_context


def test_domain_is_set(mock_env_manager, csp_ips):
    ctx = create_domain_context("example.com", mock_env_manager, set(), set(), csp_ips)
    assert ctx.get_domain() == "example.com"


def test_csp_ip_addresses_stored(mock_env_manager, csp_ips):
    ctx = create_domain_context("example.com", mock_env_manager, set(), set(), csp_ips)
    assert ctx.get_csp_ip_addresses() is csp_ips


def test_dangling_domains_is_the_passed_set(mock_env_manager, csp_ips):
    """
    The factory stores the exact set object, not a copy.
    This matters because main_async aggregates dangling domains by
    reading domain_context.dangling_domains after the coroutine finishes.
    """
    dangling = set()
    ctx = create_domain_context(
        "example.com", mock_env_manager, dangling, set(), csp_ips
    )
    ctx.add_dangling_domain_to_domains("leaked.example.com")
    assert "leaked.example.com" in dangling


def test_failed_domains_is_the_passed_set(mock_env_manager, csp_ips):
    failed = set()
    ctx = create_domain_context("example.com", mock_env_manager, set(), failed, csp_ips)
    ctx.failed_domains.add("broken.example.com")
    assert "broken.example.com" in failed
