"""
Tests for cloud_ip_ranges.

All HTTP calls are mocked — these tests exercise the parsing and error-handling
logic without making real network requests.
"""

import json
from unittest.mock import MagicMock, patch

import requests

from imports.cloud_ip_ranges import (
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
    fetch_ip_ranges,
    fetch_ip_ranges_for_azure,
)


def _mock_response(status_code=200, body=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = json.dumps(body or {})
    return r


# ---------------------------------------------------------------------------
# fetch_ip_ranges
# ---------------------------------------------------------------------------

GCP_PAYLOAD = {
    "prefixes": [
        {"ipv4Prefix": "34.0.0.0/8"},
        {"ipv6Prefix": "2600:1900::/28"},
    ]
}


def test_fetch_ip_ranges_returns_ipv4_and_ipv6():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(body=GCP_PAYLOAD),
    ):
        v4, v6, _meta = fetch_ip_ranges("http://fake-url")

    assert "34.0.0.0/8" in v4
    assert "2600:1900::/28" in v6


def test_fetch_ip_ranges_non_200_returns_empty():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(status_code=503),
    ):
        v4, v6, _meta = fetch_ip_ranges("http://fake-url")

    assert v4 == []
    assert v6 == []


def test_fetch_ip_ranges_missing_prefixes_key_returns_empty():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(body={"other": []}),
    ):
        v4, v6, _meta = fetch_ip_ranges("http://fake-url")

    assert v4 == []
    assert v6 == []


def test_fetch_ip_ranges_request_exception_returns_empty():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        side_effect=requests.exceptions.RequestException("timeout"),
    ):
        v4, v6, _meta = fetch_ip_ranges("http://fake-url")

    assert v4 == []
    assert v6 == []


def test_fetch_ip_ranges_extreme_flag_does_not_raise():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(body=GCP_PAYLOAD),
    ):
        v4, v6, _meta = fetch_ip_ranges("http://fake-url", extreme=True)

    assert "34.0.0.0/8" in v4


# ---------------------------------------------------------------------------
# fetch_ip_ranges_for_azure
# ---------------------------------------------------------------------------

AZURE_PAYLOAD = {
    "values": [{"properties": {"addressPrefixes": ["13.64.0.0/11", "2603:1010::/48"]}}]
}


def test_fetch_ip_ranges_for_azure_splits_ipv4_and_ipv6():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(body=AZURE_PAYLOAD),
    ):
        v4, v6, _meta = fetch_ip_ranges_for_azure(
            "http://fake-azure-url", extreme=False
        )

    assert "13.64.0.0/11" in v4
    assert "2603:1010::/48" in v6


def test_fetch_ip_ranges_for_azure_non_200_returns_empty():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(status_code=404),
    ):
        v4, v6, _meta = fetch_ip_ranges_for_azure(
            "http://fake-azure-url", extreme=False
        )

    assert v4 == []
    assert v6 == []


def test_fetch_ip_ranges_for_azure_request_exception_returns_empty():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        side_effect=requests.exceptions.RequestException("timeout"),
    ):
        v4, v6, _meta = fetch_ip_ranges_for_azure(
            "http://fake-azure-url", extreme=False
        )

    assert v4 == []
    assert v6 == []


def test_fetch_ip_ranges_for_azure_extreme_does_not_raise():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(body=AZURE_PAYLOAD),
    ):
        v4, v6, _meta = fetch_ip_ranges_for_azure("http://fake-azure-url", extreme=True)

    assert "13.64.0.0/11" in v4


# ---------------------------------------------------------------------------
# Wrapper functions — confirm they call fetch_ip_ranges and write a JSON file
# ---------------------------------------------------------------------------


def test_fetch_google_cloud_ip_ranges_writes_json(tmp_path):
    with patch(
        "imports.cloud_ip_ranges.fetch_ip_ranges",
        return_value=(["34.0.0.0/8"], ["2600::/28"]),
    ):
        result = fetch_google_cloud_ip_ranges(str(tmp_path))

    assert result == (["34.0.0.0/8"], ["2600::/28"])
    assert (tmp_path / "gcp_ip_ranges.json").exists()


def test_fetch_aws_ip_ranges_writes_json(tmp_path):
    with patch(
        "imports.cloud_ip_ranges.fetch_ip_ranges", return_value=(["52.0.0.0/8"], [])
    ):
        result = fetch_aws_ip_ranges(str(tmp_path))

    assert result == (["52.0.0.0/8"], [])
    assert (tmp_path / "aws_ip_ranges.json").exists()


def _mock_urlopen(html: bytes):
    """Return a context-manager mock for urlopen that yields the given HTML."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = html
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


AZURE_DOWNLOAD_HTML = (
    b'<html><a href="https://download.microsoft.com/download/fake.json">link</a></html>'
)


def test_fetch_azure_ip_ranges_scrape_success_writes_json_and_cache(tmp_path):
    with (
        patch(
            "imports.cloud_ip_ranges.urlopen",
            return_value=_mock_urlopen(AZURE_DOWNLOAD_HTML),
        ),
        patch(
            "imports.cloud_ip_ranges.fetch_ip_ranges_for_azure",
            return_value=(["13.64.0.0/11"], []),
        ),
        patch("imports.cloud_ip_ranges._save_azure_cache") as mock_cache,
    ):
        result = fetch_azure_ip_ranges(str(tmp_path))

    assert result == (["13.64.0.0/11"], [])
    assert (tmp_path / "azure_ip_ranges.json").exists()
    mock_cache.assert_called_once_with((["13.64.0.0/11"], []))


def test_fetch_azure_ip_ranges_scrape_fails_uses_local_cache(tmp_path):
    """When the confirmation page is unreachable, fall back to the local cache."""
    with (
        patch("imports.cloud_ip_ranges.urlopen", side_effect=Exception("timeout")),
        patch("imports.cloud_ip_ranges.os.path.exists", return_value=True),
        patch(
            "imports.cloud_ip_ranges._load_azure_cache",
            return_value=(["13.64.0.0/11"], []),
        ),
    ):
        result = fetch_azure_ip_ranges(str(tmp_path))

    assert result == (["13.64.0.0/11"], [])


def test_fetch_azure_ip_ranges_scrape_fails_no_cache_uses_pinned(tmp_path):
    """When scrape fails and there is no cache, the pinned URL is tried."""
    with (
        patch("imports.cloud_ip_ranges.urlopen", side_effect=Exception("timeout")),
        patch("imports.cloud_ip_ranges.os.path.exists", return_value=False),
        patch(
            "imports.cloud_ip_ranges.fetch_ip_ranges_for_azure",
            return_value=(["13.64.0.0/11"], []),
        ),
        patch("imports.cloud_ip_ranges._save_azure_cache"),
    ):
        result = fetch_azure_ip_ranges(str(tmp_path))

    assert result == (["13.64.0.0/11"], [])
    assert (tmp_path / "azure_ip_ranges.json").exists()


def test_fetch_azure_ip_ranges_all_sources_fail_returns_empty(tmp_path):
    """When scrape, cache, and pinned URL all fail, return empty lists."""
    with (
        patch("imports.cloud_ip_ranges.urlopen", side_effect=Exception("timeout")),
        patch("imports.cloud_ip_ranges.os.path.exists", return_value=False),
        patch(
            "imports.cloud_ip_ranges.fetch_ip_ranges_for_azure", return_value=([], [])
        ),
    ):
        result = fetch_azure_ip_ranges(str(tmp_path))

    assert result[:2] == ([], [])


# ---------------------------------------------------------------------------
# Region / service metadata capture
#
# A cloud match is only actionable downstream if the consumer knows where the
# address is allocated from and what it belongs to. All three providers publish
# that alongside the prefix, so it must survive parsing.
# ---------------------------------------------------------------------------


def test_aws_region_and_service_are_captured(monkeypatch):
    """AWS publishes region and service per prefix; both must be retained."""
    payload = {
        "prefixes": [
            {"ip_prefix": "3.5.140.0/22", "region": "eu-west-2", "service": "EC2"},
            {"ip_prefix": "52.94.0.0/22", "region": "us-east-1", "service": "AMAZON"},
        ]
    }
    monkeypatch.setattr(
        "imports.cloud_ip_ranges.requests.get",
        lambda *a, **k: _mock_response(200, payload),
    )

    ipv4, _ipv6, meta = fetch_ip_ranges("http://example.invalid/aws.json")

    assert "3.5.140.0/22" in ipv4
    assert meta["3.5.140.0/22"] == ("eu-west-2", "EC2")
    assert meta["52.94.0.0/22"] == ("us-east-1", "AMAZON")


def test_gcp_scope_is_captured_as_region(monkeypatch):
    """GCP calls it 'scope'; it means the same thing and must map through."""
    payload = {
        "prefixes": [
            {
                "ipv4Prefix": "34.1.208.0/20",
                "service": "Google Cloud",
                "scope": "europe-west2",
            }
        ]
    }
    monkeypatch.setattr(
        "imports.cloud_ip_ranges.requests.get",
        lambda *a, **k: _mock_response(200, payload),
    )

    _ipv4, _ipv6, meta = fetch_ip_ranges("http://example.invalid/gcp.json")

    assert meta["34.1.208.0/20"] == ("europe-west2", "Google Cloud")


def test_missing_metadata_is_reported_as_unknown_not_invented(monkeypatch):
    """A prefix without region/service must say so rather than guess."""
    payload = {"prefixes": [{"ip_prefix": "198.51.100.0/24"}]}
    monkeypatch.setattr(
        "imports.cloud_ip_ranges.requests.get",
        lambda *a, **k: _mock_response(200, payload),
    )

    _ipv4, _ipv6, meta = fetch_ip_ranges("http://example.invalid/x.json")

    assert meta["198.51.100.0/24"] == ("unknown", "unknown")


def test_azure_region_and_system_service_are_captured(monkeypatch):
    """Azure carries region and systemService on the tag's properties."""
    payload = {
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
    monkeypatch.setattr(
        "imports.cloud_ip_ranges.requests.get",
        lambda *a, **k: _mock_response(200, payload),
    )

    ipv4, ipv6, meta = fetch_ip_ranges_for_azure(
        "http://example.invalid/az.json", False
    )

    assert ipv4 == ["20.26.0.0/16"]
    assert ipv6 == ["2603:1000::/24"]
    assert meta["20.26.0.0/16"] == ("uksouth", "AzureCloud")
    assert meta["2603:1000::/24"] == ("uksouth", "AzureCloud")


def test_azure_global_tag_region_is_labelled_global(monkeypatch):
    """Azure leaves region empty on global tags; that must not read as unknown."""
    payload = {
        "values": [
            {
                "name": "AzureCloud",
                "properties": {
                    "region": "",
                    "systemService": "",
                    "addressPrefixes": ["13.64.0.0/16"],
                },
            }
        ]
    }
    monkeypatch.setattr(
        "imports.cloud_ip_ranges.requests.get",
        lambda *a, **k: _mock_response(200, payload),
    )

    _ipv4, _ipv6, meta = fetch_ip_ranges_for_azure(
        "http://example.invalid/az.json", False
    )

    assert meta["13.64.0.0/16"] == ("global", "AzureCloud")
