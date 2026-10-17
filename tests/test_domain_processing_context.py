"""Tests for DomainProcessingContext."""

import pytest

from classes.domain_processing_context import DomainProcessingContext


@pytest.fixture
def ctx(mock_env_manager, catalogues):
    context = DomainProcessingContext(mock_env_manager, catalogues)
    context.set_domain("example.com")
    return context


def test_domain_is_set_correctly(ctx):
    assert ctx.get_domain() == "example.com"


def test_catalogues_stored(ctx, catalogues):
    assert ctx.get_catalogues() is catalogues


def test_get_domain_returns_set_value(ctx):
    ctx.set_domain("other.example.com")
    assert ctx.get_domain() == "other.example.com"
