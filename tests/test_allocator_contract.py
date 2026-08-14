import ipaddress
import json
import re
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from imports.cloud_ip_ranges import MAX_CACHE_AGE

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = REPO_ROOT / "contracts"
EXAMPLE_DIR = CONTRACT_DIR / "examples"
DOC_PATH = REPO_ROOT / "docs" / "ALLOCATOR-CONTRACT.md"
README_PATH = REPO_ROOT / "README.md"
EXTERNAL_ACCEPTANCE_PATH = REPO_ROOT / "docs" / "EXTERNAL-ACCEPTANCE.md"


SCHEMA_EXAMPLES = {
    "allocator-targets-v1.schema.json": [
        "allocator-targets-v1.aws.json",
        "allocator-targets-v1.multicloud.json",
    ],
    "dns-observations-v1.schema.json": ["dns-observations-v1.json"],
    "run-manifest-v1.schema.json": [
        "run-manifest-v1.complete.json",
        "run-manifest-v1.incomplete.json",
    ],
}


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("schema_name", SCHEMA_EXAMPLES)
def test_contract_schema_is_valid(schema_name):
    Draft202012Validator.check_schema(load_json(CONTRACT_DIR / schema_name))


@pytest.mark.parametrize(
    ("schema_name", "example_name"),
    [
        (schema_name, example_name)
        for schema_name, examples in SCHEMA_EXAMPLES.items()
        for example_name in examples
    ],
)
def test_contract_example_matches_schema(schema_name, example_name):
    schema = load_json(CONTRACT_DIR / schema_name)
    example = load_json(EXAMPLE_DIR / example_name)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(example)


@pytest.mark.parametrize(
    "example_name",
    ["allocator-targets-v1.aws.json", "allocator-targets-v1.multicloud.json"],
)
def test_target_addresses_and_prefixes_are_valid(example_name):
    for target in load_json(EXAMPLE_DIR / example_name):
        address = ipaddress.ip_address(target["ip"])
        expected_record_type = "A" if address.version == 4 else "AAAA"
        assert target["dns_record_type"] == expected_record_type
        assert all(
            address in ipaddress.ip_network(prefix) for prefix in target["prefixes"]
        )


def test_aws_example_matches_current_strike_consumer_surface():
    findings = load_json(EXAMPLE_DIR / "allocator-targets-v1.aws.json")

    # This is the exact projection used by the current STRIKE CloudClaim loader.
    projected = [
        {
            "region": item.get("region", ""),
            "ip": item.get("ip", ""),
            "hostname": item.get("hostname", ""),
        }
        for item in findings
        if item.get("region", "") and item.get("ip", "")
    ]

    assert projected == [
        {
            "region": "ap-southeast-1",
            "ip": "192.0.2.10",
            "hostname": "api.example.com",
        }
    ]
    assert {item["provider"] for item in findings} == {"aws"}


def test_multicloud_example_requires_provider_aware_routing():
    findings = load_json(EXAMPLE_DIR / "allocator-targets-v1.multicloud.json")
    by_provider = {provider: [] for provider in ("aws", "gcp", "azure")}
    for item in findings:
        by_provider[item["provider"]].append(item)

    assert all(by_provider.values())
    assert {item["region"] for item in by_provider["aws"]} == {"ap-southeast-1"}
    assert {item["region"] for item in by_provider["gcp"]} == {"asia-southeast1"}
    assert {item["region"] for item in by_provider["azure"]} == {"southeastasia"}


@pytest.mark.parametrize(
    ("schema_name", "marker"),
    [
        ("allocator-targets-v1.schema.json", "allocator-targets-v1"),
        ("dns-observations-v1.schema.json", "dns-observations-v1"),
        ("run-manifest-v1.schema.json", "run-manifest-v1"),
    ],
)
def test_documented_field_table_matches_schema(schema_name, marker):
    schema = load_json(CONTRACT_DIR / schema_name)
    properties = (
        schema["items"]["properties"]
        if schema["type"] == "array"
        else schema["properties"]
    )
    document = DOC_PATH.read_text(encoding="utf-8")
    match = re.search(
        rf"<!-- schema-fields: {re.escape(marker)} -->(.*?)<!-- /schema-fields -->",
        document,
        re.DOTALL,
    )
    assert match, f"Missing documented field table for {marker}"
    documented = set(re.findall(r"^\| `([^`]+)` \|", match.group(1), re.MULTILINE))
    assert documented == set(properties)


def test_documented_catalogue_freshness_matches_implementation():
    aws_hours = int(MAX_CACHE_AGE["aws"].total_seconds() / 3600)
    gcp_hours = int(MAX_CACHE_AGE["gcp"].total_seconds() / 3600)
    azure_days = MAX_CACHE_AGE["azure"].days
    assert aws_hours == gcp_hours

    for path in (DOC_PATH, README_PATH):
        document = " ".join(path.read_text(encoding="utf-8").split())
        assert f"AWS and GCP snapshots remain usable for {aws_hours} hours" in document
        assert f"Azure snapshots remain usable for {azure_days} days" in document


def test_complete_manifest_requires_all_provider_catalogues_to_be_usable():
    manifest = load_json(EXAMPLE_DIR / "run-manifest-v1.complete.json")
    assert manifest["status"] == "complete"
    assert manifest["outputs"]["actionable_targets"]
    assert all(
        catalogue["usable"] for catalogue in manifest["provider_catalogs"].values()
    )


def test_incomplete_manifest_cannot_publish_actionable_targets():
    manifest = load_json(EXAMPLE_DIR / "run-manifest-v1.incomplete.json")
    assert manifest["status"] == "incomplete"
    assert manifest["outputs"]["actionable_targets"] is None
    assert any(
        not catalogue["usable"] for catalogue in manifest["provider_catalogs"].values()
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "complete_with_unusable_provider",
        "complete_without_actionable_output",
        "incomplete_with_actionable_output",
        "failed_catalogue_marked_usable",
    ],
)
def test_manifest_schema_rejects_fail_open_states(mutation):
    schema = load_json(CONTRACT_DIR / "run-manifest-v1.schema.json")
    manifest = deepcopy(load_json(EXAMPLE_DIR / "run-manifest-v1.complete.json"))

    if mutation == "complete_with_unusable_provider":
        manifest["provider_catalogs"]["gcp"].update(
            {"status": "failed", "usable": False}
        )
    elif mutation == "complete_without_actionable_output":
        manifest["outputs"]["actionable_targets"] = None
    elif mutation == "incomplete_with_actionable_output":
        manifest["status"] = "incomplete"
    elif mutation == "failed_catalogue_marked_usable":
        manifest["status"] = "incomplete"
        manifest["outputs"]["actionable_targets"] = None
        manifest["provider_catalogs"]["gcp"].update(
            {"status": "failed", "usable": True}
        )

    errors = list(Draft202012Validator(schema).iter_errors(manifest))
    assert errors, f"Schema accepted fail-open manifest mutation: {mutation}"


def test_observations_are_never_actionable():
    observations = load_json(EXAMPLE_DIR / "dns-observations-v1.json")
    assert observations
    assert all(item["actionability"] == "excluded" for item in observations)


def test_external_acceptance_tracks_live_contract_and_provider_scope():
    document = EXTERNAL_ACCEPTANCE_PATH.read_text(encoding="utf-8")

    assert "contracts/allocator-targets-v1.schema.json" in document
    assert "allocator-targets-v1.json" in document
    assert "csp_matches_*.txt" in document
    assert "provider_catalogues.json" in document
    assert "--nameservers 1.1.1.1,8.8.8.8" in document
    assert "system resolver" in document
    assert all(provider in document for provider in ("aws", "gcp", "azure"))
    assert "must never make real DNS or HTTP requests" in document
