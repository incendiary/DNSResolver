"""
Tests for WildcardDetector.

A zone serving `*.example.com` answers for every name under it, so an enumerated
list yields thousands of "resolved" domains that are not real hosts. These tests
pin down when that is detected, when it is not, and that detection costs one
probe per zone rather than one per domain.

All DNS is mocked — no test performs a real query.
"""

from unittest.mock import AsyncMock, MagicMock

import aiodns
import pytest

from classes.dns_constants import NXDOMAIN
from classes.wildcard_detector import WildcardDetector


def dns_answer(ip):
    answer = MagicMock()
    answer.host = ip
    return answer


def make_nxdomain():
    return aiodns.error.DNSError(NXDOMAIN, "Domain not found")


@pytest.fixture
def env_manager():
    env = MagicMock()
    env.log_info = MagicMock()
    return env


# ---------------------------------------------------------------------------
# parent_zone
# ---------------------------------------------------------------------------


def test_parent_zone_strips_leftmost_label():
    assert WildcardDetector.parent_zone("foo.example.com") == "example.com"


def test_parent_zone_of_deep_name_targets_nearest_zone():
    """`a.b.example.com` is covered by `*.b.example.com`, not `*.example.com`."""
    assert WildcardDetector.parent_zone("a.b.example.com") == "b.example.com"


def test_parent_zone_none_for_apex():
    """A name with no subdomain cannot be covered by a wildcard in its own zone."""
    assert WildcardDetector.parent_zone("example.com") is None


def test_parent_zone_tolerates_trailing_dot():
    assert WildcardDetector.parent_zone("foo.example.com.") == "example.com"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


async def test_wildcard_detected_when_random_labels_resolve(env_manager):
    """Every random probe resolving means the zone answers for anything."""
    resolver = MagicMock()
    resolver.query = AsyncMock(return_value=[dns_answer("192.0.2.1")])
    detector = WildcardDetector(resolver, env_manager)

    ips = await detector.wildcard_ips("anything.example.com")

    assert ips == frozenset({"192.0.2.1"})


async def test_no_wildcard_when_random_label_does_not_resolve(env_manager):
    """The normal case: a random name is absent, so there is no wildcard."""
    resolver = MagicMock()
    resolver.query = AsyncMock(side_effect=make_nxdomain())
    detector = WildcardDetector(resolver, env_manager)

    ips = await detector.wildcard_ips("real.example.com")

    assert ips == frozenset()


async def test_apex_domain_is_never_probed(env_manager):
    """A name with no subdomain needs no probe at all."""
    resolver = MagicMock()
    resolver.query = AsyncMock(return_value=[dns_answer("192.0.2.1")])
    detector = WildcardDetector(resolver, env_manager)

    ips = await detector.wildcard_ips("example.com")

    assert ips == frozenset()
    resolver.query.assert_not_called()


async def test_zone_probed_once_and_cached_across_domains(env_manager):
    """
    The cost guarantee: many domains in one zone trigger a single probe round,
    not one per domain.
    """
    resolver = MagicMock()
    resolver.query = AsyncMock(return_value=[dns_answer("192.0.2.1")])
    detector = WildcardDetector(resolver, env_manager, probe_count=2)

    for name in ("a.example.com", "b.example.com", "c.example.com"):
        await detector.wildcard_ips(name)

    # One probe round (A + AAAA per label) despite three domains in the zone.
    assert resolver.query.call_count == 4


async def test_probes_use_random_labels(env_manager):
    """Probe names must be unlikely to exist, or detection is meaningless."""
    resolver = MagicMock()
    resolver.query = AsyncMock(return_value=[dns_answer("192.0.2.1")])
    detector = WildcardDetector(resolver, env_manager, probe_count=2)

    await detector.wildcard_ips("host.example.com")

    probed = [call.args[0] for call in resolver.query.call_args_list]
    assert len(set(probed)) == 2, "each probe should use a distinct random label"
    for name in probed:
        assert name.endswith(".example.com")
        label = name.split(".")[0]
        assert len(label) >= 16, "label should be long enough not to collide"


# ---------------------------------------------------------------------------
# is_wildcard_resolution
# ---------------------------------------------------------------------------


async def test_resolution_matching_wildcard_is_flagged(env_manager):
    resolver = MagicMock()
    resolver.query = AsyncMock(return_value=[dns_answer("192.0.2.1")])
    detector = WildcardDetector(resolver, env_manager)

    assert await detector.is_wildcard_resolution("ghost.example.com", ["192.0.2.1"])


async def test_real_host_with_distinct_ip_is_not_flagged(env_manager):
    """A host answering with its own address is real, even in a wildcarded zone."""
    resolver = MagicMock()
    resolver.query = AsyncMock(return_value=[dns_answer("192.0.2.1")])
    detector = WildcardDetector(resolver, env_manager)

    assert not await detector.is_wildcard_resolution(
        "real.example.com", ["203.0.113.9"]
    )


async def test_host_sharing_one_wildcard_ip_but_not_all_is_not_flagged(env_manager):
    """
    Only a resolution wholly contained in the wildcard set is a catch-all answer.
    Extra addresses mean a genuine host.
    """
    resolver = MagicMock()
    resolver.query = AsyncMock(return_value=[dns_answer("192.0.2.1")])
    detector = WildcardDetector(resolver, env_manager)

    flagged = await detector.is_wildcard_resolution(
        "real.example.com", ["192.0.2.1", "203.0.113.9"]
    )

    assert flagged is False


async def test_non_wildcard_zone_never_flags(env_manager):
    """The no-wildcard path must leave ordinary scans completely untouched."""
    resolver = MagicMock()
    resolver.query = AsyncMock(side_effect=make_nxdomain())
    detector = WildcardDetector(resolver, env_manager)

    assert not await detector.is_wildcard_resolution("host.example.com", ["192.0.2.1"])


async def test_empty_resolution_is_not_flagged(env_manager):
    resolver = MagicMock()
    resolver.query = AsyncMock(return_value=[dns_answer("192.0.2.1")])
    detector = WildcardDetector(resolver, env_manager)

    assert not await detector.is_wildcard_resolution("host.example.com", [])


async def test_wildcard_set_includes_both_address_families(env_manager):
    """
    Resolution records A and AAAA, so the wildcard set must as well. A dual-stack
    catch-all whose IPv6 addresses were missing from the set would never match,
    and the wildcard would go undetected.
    """

    async def query_side_effect(domain, record_type):
        if record_type == "A":
            return [dns_answer("185.199.108.153")]
        return [dns_answer("2606:50c0:8000::153")]

    resolver = MagicMock()
    resolver.query = AsyncMock(side_effect=query_side_effect)
    detector = WildcardDetector(resolver, env_manager, probe_count=1)

    flagged = await detector.is_wildcard_resolution(
        "ghost.example.com", ["185.199.108.153", "2606:50c0:8000::153"]
    )

    assert flagged is True


async def test_zone_without_aaaa_still_detected(env_manager):
    """A wildcard zone serving only IPv4 is normal and must still be detected."""

    async def query_side_effect(domain, record_type):
        if record_type == "A":
            return [dns_answer("192.0.2.1")]
        raise make_nxdomain()

    resolver = MagicMock()
    resolver.query = AsyncMock(side_effect=query_side_effect)
    detector = WildcardDetector(resolver, env_manager, probe_count=1)

    assert await detector.is_wildcard_resolution("ghost.example.com", ["192.0.2.1"])
