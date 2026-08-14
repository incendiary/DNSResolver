import json
from pathlib import Path
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from classes.allocator_contract import publish_allocator_targets
from classes.custom_exceptions import OutputWriteError

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (REPO_ROOT / "contracts" / "allocator-targets-v1.schema.json").read_text()
)


def write_matches(tmp_path, lines):
    path = tmp_path / "csp_matches.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_publisher_groups_metadata_and_matches_contract(tmp_path):
    matches = write_matches(
        tmp_path,
        [
            "api.example.com|192.0.2.10|aws|ap-southeast-1|AMAZON|192.0.2.0/24|ap-southeast-1",
            "api.example.com|192.0.2.10|aws|ap-southeast-1|EC2|192.0.2.0/25|ap-southeast-1",
            "ipv6.example.com|2001:db8::10|gcp|asia-southeast1|Google Cloud|2001:db8::/32|unknown",
        ],
    )

    targets = publish_allocator_targets(matches, tmp_path)

    assert len(targets) == 2
    aws_target = next(target for target in targets if target["provider"] == "aws")
    assert aws_target["services"] == ["AMAZON", "EC2"]
    assert aws_target["prefixes"] == ["192.0.2.0/24", "192.0.2.0/25"]
    assert aws_target["dns_record_type"] == "A"
    Draft202012Validator(SCHEMA, format_checker=FormatChecker()).validate(targets)
    assert json.loads((tmp_path / "allocator-targets-v1.json").read_text()) == targets


def test_publisher_excludes_wildcard_records_and_deduplicates(tmp_path):
    target = (
        "api.example.com|192.0.2.10|aws|ap-southeast-1|EC2|192.0.2.0/24|ap-southeast-1"
    )
    matches = write_matches(
        tmp_path,
        [target, target, f"WILDCARD|{target}", f"WILDCARD_ZONE|{target}"],
    )

    targets = publish_allocator_targets(matches, tmp_path)

    assert len(targets) == 1
    assert targets[0]["hostname"] == "api.example.com"


def test_empty_match_file_publishes_valid_empty_array(tmp_path):
    matches = write_matches(tmp_path, [])
    targets = publish_allocator_targets(matches, tmp_path)
    assert targets == []
    assert json.loads((tmp_path / "allocator-targets-v1.json").read_text()) == []


@pytest.mark.parametrize(
    "line",
    [
        "missing|fields|aws",
        "api.example.com|not-an-ip|aws|ap-southeast-1|EC2|192.0.2.0/24|ap-southeast-1",
        "api.example.com|192.0.2.10|unknown|region|service|192.0.2.0/24|region",
        "api.example.com|192.0.2.10|aws|ap-southeast-1|EC2|198.51.100.0/24|ap-southeast-1",
    ],
)
def test_malformed_match_input_fails_without_publishing(line, tmp_path):
    matches = write_matches(tmp_path, [line])
    (tmp_path / "allocator-targets-v1.json").write_text('[{"stale": true}]')
    with pytest.raises(ValueError):
        publish_allocator_targets(matches, tmp_path)
    assert not (tmp_path / "allocator-targets-v1.json").exists()


def test_publisher_preserves_distinct_provider_regions(tmp_path):
    matches = write_matches(
        tmp_path,
        [
            "api.example.com|192.0.2.10|aws|ap-southeast-1|EC2|192.0.2.0/24|ap-southeast-1",
            "api.example.com|192.0.2.10|aws|us-east-1|EC2|192.0.2.0/24|us-east-1",
        ],
    )
    targets = publish_allocator_targets(matches, tmp_path)

    assert len(targets) == 2
    assert {target["region"] for target in targets} == {
        "ap-southeast-1",
        "us-east-1",
    }


@pytest.mark.parametrize("failure", ["open", "write", "replace"])
def test_publication_failure_removes_stale_and_temporary_files(tmp_path, failure):
    matches = write_matches(
        tmp_path,
        [
            "api.example.com|192.0.2.10|aws|ap-southeast-1|EC2|192.0.2.0/24|ap-southeast-1"
        ],
    )
    destination = tmp_path / "allocator-targets-v1.json"
    temporary = tmp_path / "allocator-targets-v1.json.tmp"
    destination.write_text('[{"stale": true}]', encoding="utf-8")

    if failure == "open":
        real_open = open

        def fail_output_open(path, mode="r", *args, **kwargs):
            if Path(path) == temporary and "w" in mode:
                raise OSError("disk full")
            return real_open(path, mode, *args, **kwargs)

        failure_patch = patch("builtins.open", side_effect=fail_output_open)
    elif failure == "write":
        failure_patch = patch(
            "classes.allocator_contract.json.dump", side_effect=OSError("disk full")
        )
    else:
        failure_patch = patch(
            "classes.allocator_contract.os.replace", side_effect=OSError("read only")
        )

    with failure_patch, pytest.raises(OutputWriteError):
        publish_allocator_targets(matches, tmp_path)

    assert not destination.exists()
    assert not temporary.exists()
