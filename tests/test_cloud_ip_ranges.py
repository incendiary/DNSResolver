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
        v4, v6 = fetch_ip_ranges("http://fake-url")

    assert "34.0.0.0/8" in v4
    assert "2600:1900::/28" in v6


def test_fetch_ip_ranges_non_200_returns_empty():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(status_code=503),
    ):
        v4, v6 = fetch_ip_ranges("http://fake-url")

    assert v4 == []
    assert v6 == []


def test_fetch_ip_ranges_missing_prefixes_key_returns_empty():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(body={"other": []}),
    ):
        v4, v6 = fetch_ip_ranges("http://fake-url")

    assert v4 == []
    assert v6 == []


def test_fetch_ip_ranges_request_exception_returns_empty():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        side_effect=requests.exceptions.RequestException("timeout"),
    ):
        v4, v6 = fetch_ip_ranges("http://fake-url")

    assert v4 == []
    assert v6 == []


def test_fetch_ip_ranges_extreme_flag_does_not_raise():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(body=GCP_PAYLOAD),
    ):
        v4, v6 = fetch_ip_ranges("http://fake-url", extreme=True)

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
        v4, v6 = fetch_ip_ranges_for_azure("http://fake-azure-url", extreme=False)

    assert "13.64.0.0/11" in v4
    assert "2603:1010::/48" in v6


def test_fetch_ip_ranges_for_azure_non_200_returns_empty():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(status_code=404),
    ):
        v4, v6 = fetch_ip_ranges_for_azure("http://fake-azure-url", extreme=False)

    assert v4 == []
    assert v6 == []


def test_fetch_ip_ranges_for_azure_extreme_does_not_raise():
    with patch(
        "imports.cloud_ip_ranges.requests.get",
        return_value=_mock_response(body=AZURE_PAYLOAD),
    ):
        v4, v6 = fetch_ip_ranges_for_azure("http://fake-azure-url", extreme=True)

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


def test_fetch_azure_ip_ranges_writes_json(tmp_path):
    html = b'<html><a href="https://download.microsoft.com/download/fake.json">link</a></html>'
    mock_resp = MagicMock()
    mock_resp.read.return_value = html
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with (
        patch("imports.cloud_ip_ranges.urlopen", return_value=mock_resp),
        patch(
            "imports.cloud_ip_ranges.fetch_ip_ranges_for_azure",
            return_value=(["13.64.0.0/11"], []),
        ),
    ):
        result = fetch_azure_ip_ranges(str(tmp_path))

    assert result == (["13.64.0.0/11"], [])
    assert (tmp_path / "azure_ip_ranges.json").exists()


def test_fetch_azure_ip_ranges_no_download_link_returns_empty(tmp_path):
    html = b"<html>no link here</html>"
    mock_resp = MagicMock()
    mock_resp.read.return_value = html
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("imports.cloud_ip_ranges.urlopen", return_value=mock_resp):
        result = fetch_azure_ip_ranges(str(tmp_path))

    assert result == ([], [])
