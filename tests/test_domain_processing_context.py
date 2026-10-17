"""Tests for DomainProcessingContext."""

import pytest

from classes.domain_processing_context import DomainProcessingContext


@pytest.fixture
def ctx(mock_env_manager, catalogues):
    context = DomainProcessingContext(mock_env_manager, catalogues)
    context.set_domain("example.com")
    return context


def test_dangling_domains_starts_empty(ctx):
    assert ctx.dangling_domains == set()


def test_domain_is_set_correctly(ctx):
    assert ctx.get_domain() == "example.com"


def test_catalogues_stored(ctx, catalogues):
    assert ctx.get_catalogues() is catalogues


def test_add_dangling_domain(ctx):
    ctx.add_dangling_domain_to_domains("cname-target.example.com")
    assert "cname-target.example.com" in ctx.dangling_domains


def test_add_multiple_dangling_domains(ctx):
    ctx.add_dangling_domain_to_domains("a.example.com")
    ctx.add_dangling_domain_to_domains("b.example.com")
    assert ctx.dangling_domains == {"a.example.com", "b.example.com"}


def test_add_duplicate_dangling_domain_is_idempotent(ctx):
    ctx.add_dangling_domain_to_domains("dup.example.com")
    ctx.add_dangling_domain_to_domains("dup.example.com")
    assert len(ctx.dangling_domains) == 1


def test_get_domain_returns_set_value(ctx):
    ctx.set_domain("other.example.com")
    assert ctx.get_domain() == "other.example.com"
