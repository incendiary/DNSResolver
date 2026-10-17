"""
Shared test fixtures.

A fixture is a reusable piece of setup that pytest injects into any test
function that names it as a parameter.  Putting them here in conftest.py
makes them available to every test file automatically.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from classes.dns_handler import DNSHandler
from imports.cloud_ip_ranges import ProviderCatalogue

# ---------------------------------------------------------------------------
# IP range data
# ---------------------------------------------------------------------------

GCP_IPV4 = ["34.0.0.0/8", "35.0.0.0/8"]
GCP_IPV6 = ["2600:1900::/35"]
AWS_IPV4 = ["3.0.0.0/8", "52.0.0.0/8"]
AWS_IPV6 = ["2600:1f00::/25"]
AZURE_IPV4 = ["13.0.0.0/8", "20.0.0.0/8"]
AZURE_IPV6 = ["2603:1000::/24"]

# CIDR -> (region, service), as the providers publish it. A match is only
# actionable downstream if the consumer knows where the address is allocated
# from and what it belongs to.
# CIDR -> (region, service, network_border_group). Only AWS publishes a border
# group; it is the boundary an Elastic IP is actually allocated from.
CSP_METADATA = {
    "gcp": {
        "34.0.0.0/8": [("europe-west2", "Google Cloud", "unknown")],
        "35.0.0.0/8": [("us-central1", "Google Cloud", "unknown")],
        "2600:1900::/35": [("europe-west2", "Google Cloud", "unknown")],
    },
    "aws": {
        "3.0.0.0/8": [("eu-west-2", "EC2", "eu-west-2")],
        "52.0.0.0/8": [("us-east-1", "AMAZON", "us-east-1")],
        "2600:1f00::/25": [("eu-west-2", "EC2", "eu-west-2")],
    },
    "azure": {
        "13.0.0.0/8": [("uksouth", "AzureCloud", "unknown")],
        "20.0.0.0/8": [("global", "AzureCloud", "unknown")],
        "2603:1000::/24": [("uksouth", "AzureCloud", "unknown")],
    },
}


def make_catalogue(provider, ipv4=(), ipv6=(), metadata=None):
    return ProviderCatalogue(
        provider=provider,
        ipv4_ranges=list(ipv4),
        ipv6_ranges=list(ipv6),
        metadata=metadata or {},
        status="live",
        usable=True,
        source_url="https://example.com",
        retrieved_at=None,
        snapshot_id=None,
    )


@pytest.fixture
def catalogues():
    """Provider catalogues populated with test ranges, in run order."""
    return {
        "gcp": make_catalogue("gcp", GCP_IPV4, GCP_IPV6, CSP_METADATA["gcp"]),
        "aws": make_catalogue("aws", AWS_IPV4, AWS_IPV6, CSP_METADATA["aws"]),
        "azure": make_catalogue("azure", AZURE_IPV4, AZURE_IPV6, CSP_METADATA["azure"]),
    }


# ---------------------------------------------------------------------------
# Fake environment manager
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_env_manager():
    """
    A MagicMock that stands in for EnvironmentManager.

    MagicMock automatically creates attributes on demand, so you only
    need to configure the return values your code actually reads.
    AsyncMock is used for methods that are awaited inside async functions.
    """
    env = MagicMock()

    # DNS / resolver config — direct attribute access (no getters)
    env.nameservers = ["8.8.8.8"]
    env.retries = 2
    env.timeout = 5
    env.evidence = False

    # Output files the handler writes results to
    env.output_files = {
        "standard": {
            "takeover": "/tmp/test_takeover.txt",
            "csp": "/tmp/test_csp.txt",
            "unresolved": "/tmp/test_unresolved.txt",
            "resolved": "/tmp/test_resolved.txt",
        },
        "evidence": {"dns": "/tmp/test_evidence/dns"},
    }

    # Domain categorisation patterns (empty → every domain is "unknown")
    env.patterns = {}

    # write_to_file is async, so it needs AsyncMock not MagicMock
    env.write_to_file = AsyncMock()

    # Structured records appended beside every write
    env.records = []
    env._csp_written = set()

    # log_* are sync fire-and-forget calls — plain MagicMock is fine
    env.log_info = MagicMock()
    env.log_error = MagicMock()

    return env


# ---------------------------------------------------------------------------
# DNS handler and per-domain context
# ---------------------------------------------------------------------------


@pytest.fixture
async def handler(mock_env_manager):
    """
    Build a DNSHandler without touching the network.

    The fixture is async so it runs inside an event loop — required because
    aiodns.DNSResolver() calls asyncio.get_event_loop() in its __init__.
    We patch both it and EvidenceCollector so no real I/O happens, then
    replace the resolvers with controllable AsyncMock / MagicMock objects.
    """
    with (
        patch("classes.dns_handler.aiodns.DNSResolver"),
        patch("classes.dns_handler.dns.resolver.Resolver"),
        patch("classes.takeover_detector.EvidenceCollector"),
    ):
        h = DNSHandler(mock_env_manager)

    # Replace with controllable fakes. TakeoverDetector was constructed with
    # the original aiodns resolver reference, so reassign both to the same mock.
    mock_aiodns = AsyncMock()
    h.aiodns_resolver = mock_aiodns
    h.dnspython_resolver = MagicMock()
    h.takeover_detector.aiodns_resolver = mock_aiodns
    return h


@pytest.fixture
def domain_context(mock_env_manager, catalogues):
    """A minimal DomainProcessingContext."""
    from classes.domain_processing_context import DomainProcessingContext

    ctx = DomainProcessingContext(mock_env_manager, catalogues)
    ctx.set_domain("example.com")
    return ctx
