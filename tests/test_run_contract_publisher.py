import json
from pathlib import Path
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from classes.custom_exceptions import OutputWriteError
from classes.run_contract import publish_dns_observations, publish_run_manifest
from imports.cloud_ip_ranges import ProviderCatalogue

REPO_ROOT = Path(__file__).resolve().parents[1]
OBSERVATION_SCHEMA = json.loads(
    (REPO_ROOT / "contracts" / "dns-observations-v1.schema.json").read_text()
)
MANIFEST_SCHEMA = json.loads(
    (REPO_ROOT / "contracts" / "run-manifest-v1.schema.json").read_text()
)


def _output_files(tmp_path):
    files = {
        "resolved": (
            "WILDCARD|wild.example.com|192.0.2.10\n"
            "WILDCARD_ZONE|rotating.example.com|192.0.2.20|2001:db8::20\n"
            "ordinary.example.com|192.0.2.30\n"
        ),
        "unresolved": (
            "DNS resolution error for missing.example.com: query timed out\n"
        ),
        "takeover": (
            "DANGLING|old.example.com|missing.example.net|unknown|Review it|N/A|1|old.example.com -> missing.example.net\n"
            "NS_TAKEOVER|delegated.example.com|ns1.missing.example.net\n"
        ),
        "csp": "",
    }
    paths = {}
    for name, content in files.items():
        path = tmp_path / f"{name}.txt"
        path.write_text(content, encoding="utf-8")
        paths[name] = str(path)
    return {"standard": paths}


def _catalogue(provider, usable=True):
    return ProviderCatalogue(
        provider=provider,
        ipv4_ranges=["192.0.2.0/24"] if usable else [],
        ipv6_ranges=[],
        metadata={},
        status="complete" if usable else "failed",
        usable=usable,
        source_url=f"https://example.com/{provider}.json",
        retrieved_at="2026-01-01T00:00:00Z" if usable else None,
        snapshot_id=f"{provider}-1" if usable else None,
        error=None if usable else "catalogue unavailable",
    )


def test_observation_publisher_retains_every_excluded_kind(tmp_path):
    observations = publish_dns_observations(
        _output_files(tmp_path),
        tmp_path,
        provider_failures={"gcp": "catalogue unavailable"},
        hostnames=["ordinary.example.com"],
    )

    Draft202012Validator(OBSERVATION_SCHEMA, format_checker=FormatChecker()).validate(
        observations
    )
    assert {item["kind"] for item in observations} == {
        "wildcard",
        "wildcard_zone",
        "dangling_cname",
        "ns_takeover",
        "unresolved",
        "provider_catalog_incomplete",
    }
    rotating = next(
        item for item in observations if item["hostname"] == "rotating.example.com"
    )
    assert rotating["ips"] == ["192.0.2.20", "2001:db8::20"]
    assert all(item["actionability"] == "excluded" for item in observations)
    assert (
        json.loads((tmp_path / "dns-observations-v1.json").read_text()) == observations
    )


@pytest.mark.parametrize("status", ["complete", "incomplete", "failed"])
def test_manifest_publisher_matches_checked_contract(tmp_path, status):
    catalogues = {
        provider: _catalogue(
            provider, usable=not (status == "incomplete" and provider == "gcp")
        )
        for provider in ("aws", "gcp", "azure")
    }

    manifest = publish_run_manifest(
        tmp_path,
        run_id=f"{status}-run",
        status=status,
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:01:00Z",
        catalogues=catalogues,
    )

    Draft202012Validator(MANIFEST_SCHEMA, format_checker=FormatChecker()).validate(
        manifest
    )
    expected_target = "allocator-targets-v1.json" if status == "complete" else None
    assert manifest["outputs"]["actionable_targets"] == expected_target
    assert manifest["outputs"]["observations"] == "dns-observations-v1.json"


def test_observation_publication_failure_removes_stale_and_temporary_files(tmp_path):
    destination = tmp_path / "dns-observations-v1.json"
    temporary = tmp_path / "dns-observations-v1.json.tmp"
    destination.write_text('[{"stale": true}]', encoding="utf-8")

    with (
        patch("classes.run_contract.os.replace", side_effect=OSError("read only")),
        pytest.raises(OutputWriteError),
    ):
        publish_dns_observations(_output_files(tmp_path), tmp_path)

    assert not destination.exists()
    assert not temporary.exists()
