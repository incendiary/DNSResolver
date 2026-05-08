"""
Tests for DomainProcessingContext.

Introduces pytest fixtures — the `mock_env_manager` and `csp_ips` fixtures
are defined in conftest.py and injected automatically by pytest when a test
function lists them as parameters.
"""

import pytest

from classes.domain_processing_context import DomainProcessingContext

# ---------------------------------------------------------------------------
# Fixture: a fresh context for each test
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx(mock_env_manager, csp_ips):
    """A DomainProcessingContext wired up with fake dependencies."""
    context = DomainProcessingContext(mock_env_manager, csp_ips)
    context.set_domain("example.com")
    return context


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------


def test_dangling_domains_starts_empty(ctx):
    assert ctx.dangling_domains == set()


def test_failed_domains_starts_empty(ctx):
    assert ctx.failed_domains == set()


def test_domain_is_set_correctly(ctx):
    assert ctx.get_domain() == "example.com"


def test_csp_ip_addresses_stored(ctx, csp_ips):
    assert ctx.get_csp_ip_addresses() is csp_ips


# ---------------------------------------------------------------------------
# Dangling domain tracking
# ---------------------------------------------------------------------------


def test_add_dangling_domain(ctx):
    ctx.add_dangling_domain_to_domains("cname-target.example.com")
    assert "cname-target.example.com" in ctx.dangling_domains


def test_add_multiple_dangling_domains(ctx):
    ctx.add_dangling_domain_to_domains("a.example.com")
    ctx.add_dangling_domain_to_domains("b.example.com")
    assert ctx.dangling_domains == {"a.example.com", "b.example.com"}


def test_add_duplicate_dangling_domain_is_idempotent(ctx):
    """Sets deduplicate automatically — adding the same domain twice is fine."""
    ctx.add_dangling_domain_to_domains("dup.example.com")
    ctx.add_dangling_domain_to_domains("dup.example.com")
    assert len(ctx.dangling_domains) == 1


# ---------------------------------------------------------------------------
# Resolver creation
# ---------------------------------------------------------------------------


def test_resolver_is_none_before_create(ctx):
    assert ctx.get_resolver() is None


def test_create_resolver_produces_resolver(ctx):
    ctx.create_resolver()
    assert ctx.get_resolver() is not None


# ---------------------------------------------------------------------------
# Setters and secondary getters
# ---------------------------------------------------------------------------


def test_set_current_domain(ctx):
    ctx.set_current_domain("sub.example.com")
    assert ctx.get_current_domain() == "sub.example.com"


def test_set_dangling_domains_replaces_set(ctx):
    new_set = {"already-dangling.com"}
    ctx.set_dangling_domains(new_set)
    assert ctx.get_dangling_domains() is new_set


def test_set_failed_domains_replaces_set(ctx):
    new_set = {"broken.example.com"}
    ctx.set_failed_domains(new_set)
    assert ctx.get_failed_domains() is new_set


def test_get_domain_returns_set_value(ctx):
    ctx.set_domain("other.example.com")
    assert ctx.get_domain() == "other.example.com"
