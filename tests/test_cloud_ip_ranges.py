"""Hermetic tests for cloud catalogue fetching, validation, and caching."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from imports.cloud_ip_ranges import (
    AZURE_PINNED_URL,
    CatalogueFetchError,
    ProviderCatalogue,
    _cache_path,
    _snapshot_id,
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
    fetch_ip_ranges,
    fetch_ip_ranges_for_azure,
)


def _response(status_code=200, body=None, text=None):
    response = MagicMock()
    response.status = status_code
    content = text if text is not None else json.dumps(body or {})
    response.read.return_value = content.encode()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    return response


STANDARD_PAYLOAD = {
    "prefixes": [
        {
            "ip_prefix": "3.5.140.0/22",
            "region": "eu-west-2",
            "service": "EC2",
            "network_border_group": "eu-west-2",
        },
        {
            "ipv6Prefix": "2600:1900::/28",
            "scope": "global",
            "service": "Google Cloud",
        },
    ]
}
AZURE_PAYLOAD = {
    "values": [
        {
            "name": "AzureCloud.uksouth",
            "properties": {
                "region": "uksouth",
                "systemService": "AzureCloud",
                "addressPrefixes": ["20.26.0.0/16", "2603:1000::/24"],
            },
        }
    ]
}


def test_standard_parser_preserves_ranges_and_metadata():
    with patch(
        "imports.cloud_ip_ranges.urlopen",
        return_value=_response(body=STANDARD_PAYLOAD),
    ):
        ipv4, ipv6, metadata = fetch_ip_ranges("https://example.com/ranges.json")

    assert ipv4 == ["3.5.140.0/22"]
    assert ipv6 == ["2600:1900::/28"]
    assert metadata["3.5.140.0/22"] == ("eu-west-2", "EC2", "eu-west-2")
    assert metadata["2600:1900::/28"] == ("global", "Google Cloud", "unknown")


def test_aws_separate_ipv6_prefix_collection_is_loaded():
    payload = {
        "prefixes": [{"ip_prefix": "3.5.140.0/22", "region": "eu-west-2"}],
        "ipv6_prefixes": [
            {
                "ipv6_prefix": "2600:1f00::/40",
                "region": "us-east-1",
                "service": "EC2",
                "network_border_group": "us-east-1",
            }
        ],
    }
    with patch("imports.cloud_ip_ranges.urlopen", return_value=_response(body=payload)):
        _ipv4, ipv6, metadata = fetch_ip_ranges("https://example.com/aws-ranges.json")
    assert ipv6 == ["2600:1f00::/40"]
    assert metadata["2600:1f00::/40"] == ("us-east-1", "EC2", "us-east-1")


def test_azure_parser_preserves_ranges_and_metadata():
    with patch(
        "imports.cloud_ip_ranges.urlopen",
        return_value=_response(body=AZURE_PAYLOAD),
    ):
        ipv4, ipv6, metadata = fetch_ip_ranges_for_azure(
            "https://example.com/azure.json", False
        )

    assert ipv4 == ["20.26.0.0/16"]
    assert ipv6 == ["2603:1000::/24"]
    assert metadata["20.26.0.0/16"] == ("uksouth", "AzureCloud", "unknown")


def test_azure_global_region():
    payload = {
        "values": [
            {
                "name": "AzureCloud",
                "properties": {"region": "", "addressPrefixes": ["13.64.0.0/16"]},
            }
        ]
    }
    with patch("imports.cloud_ip_ranges.urlopen", return_value=_response(body=payload)):
        _ipv4, _ipv6, metadata = fetch_ip_ranges_for_azure(
            "https://example.com/azure.json", False
        )
    assert metadata["13.64.0.0/16"] == ("global", "AzureCloud", "unknown")


@pytest.mark.parametrize(
    "response,expected_attempts",
    [
        (_response(status_code=503), 3),
        (_response(text="not-json"), 3),
        (_response(body={"other": []}), 1),
        (_response(body={"prefixes": [], "ipv6_prefixes": {}}), 1),
        (_response(body={"prefixes": [{"ip_prefix": "not-a-prefix"}]}), 1),
    ],
)
def test_http_parse_and_validation_failures_are_explicit(response, expected_attempts):
    with (
        patch("imports.cloud_ip_ranges.urlopen", return_value=response) as request,
        patch("imports.cloud_ip_ranges.sleep"),
        pytest.raises(CatalogueFetchError),
    ):
        fetch_ip_ranges("https://example.com/ranges.json")
    assert request.call_count == expected_attempts


def test_transient_http_failure_is_retried_then_succeeds():
    with (
        patch(
            "imports.cloud_ip_ranges.urlopen",
            side_effect=[
                OSError("certificate failure"),
                _response(body=STANDARD_PAYLOAD),
            ],
        ) as request,
        patch("imports.cloud_ip_ranges.sleep"),
    ):
        ipv4, _ipv6, _metadata = fetch_ip_ranges("https://example.com/ranges.json")
    assert ipv4 == ["3.5.140.0/22"]
    assert request.call_count == 2


def test_successful_provider_fetch_records_provenance_and_snapshot(tmp_path):
    with patch(
        "imports.cloud_ip_ranges.fetch_ip_ranges",
        return_value=(["34.0.0.0/8"], ["2600:1900::/28"], {}),
    ):
        catalogue = fetch_google_cloud_ip_ranges(str(tmp_path))

    assert catalogue.status == "complete"
    assert catalogue.usable is True
    assert catalogue.retrieved_at.endswith("Z")
    assert len(catalogue.snapshot_id) == 64
    artifact = json.loads((tmp_path / "gcp_ip_ranges.json").read_text())
    assert artifact["source_url"] == catalogue.source_url
    assert _cache_path(str(tmp_path), "gcp").exists()


def _write_cache(output_dir, provider, retrieved_at=None):
    cache = _cache_path(str(output_dir), provider)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(
        json.dumps(
            {
                "provider": provider,
                "ipv4_ranges": ["192.0.2.0/24"],
                "ipv6_ranges": [],
                "metadata": {},
                "status": "complete",
                "usable": True,
                "source_url": f"https://example.com/{provider}.json",
                "retrieved_at": retrieved_at
                or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "snapshot_id": _snapshot_id((["192.0.2.0/24"], [], {})),
                "error": None,
            }
        )
    )
    return cache


def test_live_failure_uses_fresh_cache_with_explicit_cached_state(tmp_path):
    _write_cache(tmp_path, "aws")
    with patch(
        "imports.cloud_ip_ranges.fetch_ip_ranges",
        side_effect=CatalogueFetchError("TLS failure"),
    ):
        catalogue = fetch_aws_ip_ranges(str(tmp_path))
    assert catalogue.status == "cached"
    assert catalogue.usable is True
    assert catalogue.ipv4_ranges == ["192.0.2.0/24"]
    assert (tmp_path / "aws_ip_ranges.json").exists()


def test_live_failure_and_stale_cache_returns_unusable_state(tmp_path):
    stale = datetime.now(timezone.utc) - timedelta(days=2)
    _write_cache(tmp_path, "aws", stale.isoformat().replace("+00:00", "Z"))
    with patch(
        "imports.cloud_ip_ranges.fetch_ip_ranges",
        side_effect=CatalogueFetchError("HTTP 503"),
    ):
        catalogue = fetch_aws_ip_ranges(str(tmp_path))
    assert catalogue.status == "failed"
    assert catalogue.usable is False
    assert "stale" in catalogue.error


def test_live_failure_and_malformed_cache_returns_unusable_state(tmp_path):
    cache = _cache_path(str(tmp_path), "gcp")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("not-json")
    with patch(
        "imports.cloud_ip_ranges.fetch_ip_ranges",
        side_effect=CatalogueFetchError("malformed response"),
    ):
        catalogue = fetch_google_cloud_ip_ranges(str(tmp_path))
    assert catalogue.status == "failed"
    assert catalogue.usable is False
    assert "malformed response" in catalogue.error


def test_cache_with_mismatched_snapshot_id_is_unusable(tmp_path):
    cache = _write_cache(tmp_path, "gcp")
    payload = json.loads(cache.read_text())
    payload["snapshot_id"] = "wrong"
    cache.write_text(json.dumps(payload))
    with patch(
        "imports.cloud_ip_ranges.fetch_ip_ranges",
        side_effect=CatalogueFetchError("HTTP 503"),
    ):
        catalogue = fetch_google_cloud_ip_ranges(str(tmp_path))
    assert catalogue.usable is False
    assert "snapshot ID does not match" in catalogue.error


def _urlopen_html(html):
    response = MagicMock()
    response.read.return_value = html
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    return response


def test_azure_discovery_uses_current_download_url(tmp_path):
    html = b'<a href="https://download.microsoft.com/download/current.json">x</a>'
    with (
        patch("imports.cloud_ip_ranges.urlopen", return_value=_urlopen_html(html)),
        patch(
            "imports.cloud_ip_ranges.fetch_ip_ranges_for_azure",
            return_value=(["20.0.0.0/8"], [], {}),
        ) as fetch,
    ):
        catalogue = fetch_azure_ip_ranges(str(tmp_path))
    assert catalogue.status == "complete"
    assert catalogue.source_url.endswith("current.json")
    fetch.assert_called_once_with(catalogue.source_url, False)


def test_azure_discovery_failure_uses_pinned_source(tmp_path):
    with (
        patch("imports.cloud_ip_ranges.urlopen", side_effect=OSError("TLS failure")),
        patch("imports.cloud_ip_ranges.sleep"),
        patch(
            "imports.cloud_ip_ranges.fetch_ip_ranges_for_azure",
            return_value=(["20.0.0.0/8"], [], {}),
        ) as fetch,
    ):
        catalogue = fetch_azure_ip_ranges(str(tmp_path))
    assert catalogue.usable is True
    assert catalogue.source_url == AZURE_PINNED_URL
    fetch.assert_called_once_with(AZURE_PINNED_URL, False)


def test_catalogue_iterates_as_existing_matcher_tuple():
    catalogue = ProviderCatalogue(
        "aws",
        ["192.0.2.0/24"],
        [],
        {},
        "complete",
        True,
        "https://example.com/aws.json",
        "2026-01-01T00:00:00Z",
        "id",
    )
    ipv4, ipv6, metadata = catalogue
    assert (ipv4, ipv6, metadata) == (["192.0.2.0/24"], [], {})
