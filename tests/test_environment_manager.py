"""
Tests for EnvironmentManager.

Constructing EnvironmentManager parses CLI args via ConfigResolver (argparse
reading sys.argv) and reads config.json, then calls fetch_external_ip() to
hit https://ifconfig.io/ip over the network. To keep this hermetic we patch
sys.argv (as tests/test_config_resolver.py does) and patch
classes.environment_manager.fetch_external_ip so no real HTTP call is made.

Methods that don't require a live object (is_valid_domain, clean_domains)
are exercised directly on the class/instance without full construction.
"""

import json
from unittest.mock import patch

import pytest

from classes.environment_manager import EnvironmentManager

# ---------------------------------------------------------------------------
# is_valid_domain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("a.example.com", True),
        ("not_a_domain", False),
        ("123", False),
        ("", False),
        ("-lead.com", False),
        ("a" * 64 + ".com", False),  # label over 63 chars
    ],
)
def test_is_valid_domain(domain, expected):
    assert EnvironmentManager.is_valid_domain(domain) is expected


# ---------------------------------------------------------------------------
# clean_domains
# ---------------------------------------------------------------------------


def test_clean_domains_filters_blanks_and_invalids():
    mgr = EnvironmentManager.__new__(EnvironmentManager)
    domains = ["a.example.com", "", "not_a_domain", "b.example.org", None, "123"]
    result = mgr.clean_domains(domains)
    assert result == ["a.example.com", "b.example.org"]


# ---------------------------------------------------------------------------
# load_patterns
# ---------------------------------------------------------------------------


def test_load_patterns_valid_config(tmp_path):
    config = {"domain_categorisation": {"github": {"regex": r"\.github\.io\."}}}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))

    mgr = EnvironmentManager.__new__(EnvironmentManager)
    mgr._config_file = str(config_file)
    mgr.load_patterns()

    assert mgr.patterns == {"github": {"regex": r"\.github\.io\."}}


def test_load_patterns_missing_file(tmp_path):
    mgr = EnvironmentManager.__new__(EnvironmentManager)
    mgr._config_file = str(tmp_path / "nonexistent.json")
    mgr.load_patterns()

    assert mgr.patterns == {}


def test_load_patterns_malformed_json(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text("{not valid json")

    mgr = EnvironmentManager.__new__(EnvironmentManager)
    mgr._config_file = str(config_file)
    mgr.load_patterns()

    assert mgr.patterns == {}


# ---------------------------------------------------------------------------
# get_random_nameserver
# ---------------------------------------------------------------------------


def test_get_random_nameserver_returns_one_of_configured():
    mgr = EnvironmentManager.__new__(EnvironmentManager)
    mgr.nameservers = ["8.8.8.8", "1.1.1.1"]
    result = mgr.get_random_nameserver()
    assert result in mgr.nameservers


def test_get_random_nameserver_none_when_unset():
    mgr = EnvironmentManager.__new__(EnvironmentManager)
    mgr.nameservers = None
    assert mgr.get_random_nameserver() is None


# ---------------------------------------------------------------------------
# set_domains
# ---------------------------------------------------------------------------


def test_set_domains_reads_and_dedupes_and_validates(tmp_path):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text(
        "a.example.com\n"
        "a.example.com\n"  # duplicate
        "not_a_domain\n"  # invalid
        "b.example.org\n"
        "\n"  # blank
    )

    mgr = EnvironmentManager.__new__(EnvironmentManager)
    mgr.domains_file = str(domains_file)
    mgr.set_domains()

    assert mgr.domains == {"a.example.com", "b.example.org"}


# ---------------------------------------------------------------------------
# Full construction, hermetic
# ---------------------------------------------------------------------------


def _construct(tmp_path, extra_argv=None):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("a.example.com\n")

    config = {
        "config": {
            "output_dir": str(tmp_path / "output"),
            "max_threads": 2,
            "timeout": 1,
            "retries": 1,
        },
        "domain_categorisation": {},
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))

    fake_argv = ["resolver.py", str(domains_file), "--config-file", str(config_file)]
    fake_argv += extra_argv or []

    with (
        patch("sys.argv", fake_argv),
        patch(
            "classes.environment_manager.fetch_external_ip",
            return_value="203.0.113.5",
        ),
    ):
        return EnvironmentManager()


def test_construction_uses_mocked_external_ip_no_network(tmp_path):
    mgr = _construct(tmp_path)
    assert mgr.environment_info["external_ip"] == "203.0.113.5"
    assert isinstance(mgr.environment_info["run_in_docker"], bool)


def test_construction_populates_patterns_and_config(tmp_path):
    mgr = _construct(tmp_path)
    assert mgr.patterns == {}
    assert mgr.max_threads == 2
    assert mgr.timeout == 1
    assert mgr.retries == 1
