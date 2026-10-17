"""
Golden end-to-end characterisation test.

Runs resolver.run() over fixed, fully mocked inputs and compares every output
file byte for byte with the checked-in files in tests/golden/expected/. Any
change to a record format, a JSON document or the console summary fails here.

Regenerate after an intentional format change, then read the diff:

    UPDATE_GOLDEN=1 .venv/bin/pytest tests/test_golden_run.py
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import aiodns
import dns.resolver

import resolver
from classes.dns_constants import NO_DATA, NXDOMAIN
from classes.environment_manager import EnvironmentManager
from imports.cloud_ip_ranges import ProviderCatalogue
from version import __version__

GOLDEN = Path(__file__).parent / "golden"
STAMP = "20260101_000000"

# Pipe files are named with the run timestamp; the clock is fixed, so mapping
# the expected name to the real one is the only normalisation needed.
PIPE_FILES = {
    "resolution_results.txt": f"resolution_results_{STAMP}.txt",
    "unresolved_results.txt": f"unresolved_results_{STAMP}.txt",
    "csp_matches.txt": f"csp_matches_{STAMP}.txt",
    "takeover_candidates.txt": f"takeover_candidates_{STAMP}.txt",
}
JSON_FILES = [
    "allocator-targets-v1.json",
    "dns-observations-v1.json",
    "run-manifest-v1.json",
    "provider_catalogues.json",
]


def _catalogue(provider, ipv4, ipv6, metadata):
    return ProviderCatalogue(
        provider,
        ipv4,
        ipv6,
        metadata,
        "complete",
        True,
        f"https://example.com/{provider}.json",
        "2026-01-01T00:00:00Z",
        f"{provider}-1",
    )


CATALOGUES = {
    "aws": _catalogue(
        "aws",
        ["198.18.0.0/24", "198.18.1.0/24"],
        ["2001:db8:a::/48"],
        {
            "198.18.0.0/24": [("eu-west-2", "EC2", "eu-west-2")],
            "198.18.1.0/24": [("eu-west-2", "EC2", "eu-west-2")],
            "2001:db8:a::/48": [("eu-west-2", "EC2", "eu-west-2")],
        },
    ),
    "gcp": _catalogue(
        "gcp",
        ["198.51.100.0/24", "198.18.1.0/25"],
        ["2001:db8:b::/48"],
        {
            "198.51.100.0/24": [("europe-west2", "Google Cloud", "unknown")],
            "198.18.1.0/25": [("europe-west2", "Google Cloud", "unknown")],
            "2001:db8:b::/48": [("europe-west2", "Google Cloud", "unknown")],
        },
    ),
    "azure": _catalogue(
        "azure",
        ["203.0.113.0/24"],
        [],
        {
            "203.0.113.0/24": [
                ("uksouth", "AzureCloud", "unknown"),
                ("ukwest", "AzureCloud", "unknown"),
            ]
        },
    ),
}

# name -> rtype -> list of addresses | CNAME target string | error code.
# A name present here but lacking the queried type answers NO_DATA; an absent
# name answers NXDOMAIN unless a wildcard rule covers it.
DNS = {
    "aws.example.com": {"A": ["198.18.0.10"]},
    "gcp.example.com": {"A": ["198.51.100.20"], "AAAA": ["2001:db8:b::20"]},
    "azure.example.com": {"A": ["203.0.113.30"]},
    "v6.example.com": {"AAAA": ["2001:db8:a::1"]},
    "host2.rot.example.com": {"A": ["198.18.0.61"]},
    "dangle.example.com": {
        "CNAME": "old-bucket.s3.amazonaws.com",
        "A": NXDOMAIN,
        "AAAA": NXDOMAIN,
    },
    "nstake.example.com": {"A": ["192.0.2.80"], "NS": ["ns1.deadns.example.net"]},
    "shared-a.example.com": {"A": ["198.51.100.77"]},
    "shared-b.example.com": {"A": ["198.51.100.77"]},
    # One address inside both an AWS and a GCP prefix: pins provider order.
    "multi.example.com": {"A": ["198.18.1.5"]},
}
# Catch-all zones. wild: probes and hosts all get one address (WILDCARD).
# rot: probes get .60 but host2 resolves to .61, which was not sampled
# (WILDCARD_ZONE).
WILDCARDS = {
    "wild.example.com": {"A": ["198.18.0.50"]},
    "rot.example.com": {"A": ["198.18.0.60"]},
}


class _Answer:
    def __init__(self, value):
        self.host = value
        self.cname = value


class FakeAiodns:
    async def query(self, name, rtype):
        name = name.rstrip(".")
        records = DNS.get(name)
        if records is None:
            records = WILDCARDS.get(name.partition(".")[2])
        if records is None:
            raise aiodns.error.DNSError(NXDOMAIN, "Domain name not found")
        value = records.get(rtype)
        if value is None:
            raise aiodns.error.DNSError(NO_DATA, "No data")
        if isinstance(value, int):
            raise aiodns.error.DNSError(value, "Domain name not found")
        if rtype == "CNAME":
            return _Answer(value)
        return [_Answer(item) for item in value]


class FakeDnspython:
    """Second opinion: agrees with every aiodns failure, never rescues one."""

    def resolve(self, name, rtype):
        raise dns.resolver.NXDOMAIN()


def _ordered_domains(self):
    # Production uses a set, whose order varies per process. One worker plus
    # file order makes the write order, and so every output byte, reproducible.
    with open(self.domains_file, encoding="utf-8") as handle:
        self.domains = self.clean_domains(handle.read().splitlines())


def _compare(name, actual, expected_path):
    if os.environ.get("UPDATE_GOLDEN"):
        expected_path.write_text(actual, encoding="utf-8")
    assert actual == expected_path.read_text(encoding="utf-8"), name


async def test_golden_run(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)  # setup_logger writes dnsresolver.log to cwd
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "resolver.py",
            str(GOLDEN / "domains.txt"),
            "--config-file",
            str(GOLDEN / "config.json"),
            "--output-dir",
            str(tmp_path / "out"),
            "--retries",
            "1",
            "--max-threads",
            "1",
            "--timeout",
            "5",
        ],
    )
    labels = iter(range(1, 1000))
    timestamps = iter(["2026-01-01T00:00:00Z", "2026-01-01T00:00:05Z"])

    with (
        patch("classes.dns_handler.aiodns.DNSResolver", return_value=FakeAiodns()),
        patch(
            "classes.dns_handler.dns.resolver.Resolver", return_value=FakeDnspython()
        ),
        patch("resolver.fetch_aws_ip_ranges", return_value=CATALOGUES["aws"]),
        patch("resolver.fetch_google_cloud_ip_ranges", return_value=CATALOGUES["gcp"]),
        patch("resolver.fetch_azure_ip_ranges", return_value=CATALOGUES["azure"]),
        patch(
            "classes.environment_manager.fetch_external_ip", return_value="192.0.2.1"
        ),
        patch("classes.environment_manager.datetime") as clock,
        patch("resolver.uuid4", return_value=UUID(int=1)),
        patch(
            "classes.wildcard_detector.uuid.uuid4",
            side_effect=lambda: UUID(int=next(labels)),
        ),
        patch("resolver._timestamp", side_effect=lambda _value: next(timestamps)),
        patch.object(EnvironmentManager, "set_domains", _ordered_domains),
    ):
        clock.now.return_value.strftime.return_value = STAMP
        env_manager = EnvironmentManager()
        capsys.readouterr()  # discard the banner and effective configuration
        await resolver.run(env_manager)

    output_dir = Path(env_manager.output_dir)
    expected = GOLDEN / "expected"
    for expected_name, actual_name in PIPE_FILES.items():
        _compare(
            expected_name,
            (output_dir / actual_name).read_text(encoding="utf-8"),
            expected / expected_name,
        )
    for name in JSON_FILES:
        _compare(name, (output_dir / name).read_text(encoding="utf-8"), expected / name)

    summary = (
        capsys.readouterr()
        .out.replace(str(output_dir), "<OUTPUT_DIR>")
        .replace(f"v{__version__}", "v<VERSION>")
    )
    _compare("console summary", summary, expected / "console_summary.txt")
