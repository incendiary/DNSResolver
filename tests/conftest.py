"""
Shared test fixtures.

A fixture is a reusable piece of setup that pytest injects into any test
function that names it as a parameter.  Putting them here in conftest.py
makes them available to every test file automatically.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from classes.csp_ip_addresses import CSPIPAddresses

# ---------------------------------------------------------------------------
# IP range data
# ---------------------------------------------------------------------------

GCP_IPV4 = ["34.0.0.0/8", "35.0.0.0/8"]
GCP_IPV6 = ["2600:1900::/35"]
AWS_IPV4 = ["3.0.0.0/8", "52.0.0.0/8"]
AWS_IPV6 = ["2600:1f00::/25"]
AZURE_IPV4 = ["13.0.0.0/8", "20.0.0.0/8"]
AZURE_IPV6 = ["2603:1000::/24"]


@pytest.fixture
def csp_ips():
    """A real CSPIPAddresses instance populated with test ranges."""
    return CSPIPAddresses(
        GCP_IPV4, GCP_IPV6, AWS_IPV4, AWS_IPV6, AZURE_IPV4, AZURE_IPV6
    )


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

    # DNS / resolver config
    env.get_random_nameserver.return_value = None
    env.get_resolvers.return_value = ["8.8.8.8"]
    env.get_retries.return_value = 2
    env.get_timeout.return_value = 5
    env.get_evidence.return_value = False

    # Output files the handler writes results to
    env.get_output_files.return_value = {
        "standard": {
            "dangling": "/tmp/test_dangling.txt",
            "ns_takeover": "/tmp/test_ns_takeover.txt",
            "unresolved": "/tmp/test_unresolved.txt",
            "resolved": "/tmp/test_resolved.txt",
        },
        "evidence": {"dns": "/tmp/test_evidence/dns"},
    }

    # Domain categorisation patterns (empty → every domain is "unknown")
    env.get_patterns.return_value = {}

    # write_to_file is async, so it needs AsyncMock not MagicMock
    env.write_to_file = AsyncMock()

    # log_* are sync fire-and-forget calls — plain MagicMock is fine
    env.log_info = MagicMock()
    env.log_error = MagicMock()

    return env
