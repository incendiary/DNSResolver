"""Fetch, validate, cache, and describe required cloud IP catalogues."""

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import sleep
from typing import Dict, Iterator, List, Tuple
from urllib.request import urlopen

IPV4_KEYWORDS = ["ipv4Prefix", "ip_prefix"]
IPV6_KEYWORDS = ["ipv6Prefix", "ipv6_prefix"]
FETCH_ATTEMPTS = 3
FETCH_TIMEOUT_SECONDS = 10
RETRY_DELAY_SECONDS = 0.25

PROVIDER_SOURCES = {
    "gcp": "https://www.gstatic.com/ipranges/cloud.json",
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
}
MAX_CACHE_AGE = {
    "gcp": timedelta(hours=24),
    "aws": timedelta(hours=24),
    # Microsoft currently publishes this catalogue weekly.
    "azure": timedelta(days=14),
}


class CatalogueFetchError(RuntimeError):
    """A provider catalogue could not be fetched or validated."""


@dataclass(frozen=True)
class ProviderCatalogue:
    provider: str
    ipv4_ranges: List[str]
    ipv6_ranges: List[str]
    metadata: Dict[str, List[Tuple[str, str, str]]]
    status: str
    usable: bool
    source_url: str
    retrieved_at: str | None
    snapshot_id: str | None
    error: str | None = None

    def __iter__(self) -> Iterator:
        """Keep range unpacking compatible with the existing matcher boundary."""
        yield self.ipv4_ranges
        yield self.ipv6_ranges
        yield self.metadata

    def manifest_entry(self) -> dict:
        return {
            "status": self.status,
            "usable": self.usable,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "snapshot_id": self.snapshot_id,
        }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _get_json(url: str) -> dict:
    errors = []
    for attempt in range(FETCH_ATTEMPTS):
        try:
            with urlopen(url, timeout=FETCH_TIMEOUT_SECONDS) as response:
                status = getattr(response, "status", response.getcode())
                if status != 200:
                    raise CatalogueFetchError(f"HTTP {status}")
                body = response.read().decode("utf-8")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise CatalogueFetchError("top-level JSON value is not an object")
            return data
        except (OSError, UnicodeDecodeError, ValueError, CatalogueFetchError) as error:
            errors.append(str(error))
            if attempt + 1 < FETCH_ATTEMPTS:
                sleep(RETRY_DELAY_SECONDS)
    raise CatalogueFetchError(
        f"failed after {FETCH_ATTEMPTS} attempts: {errors[-1] or 'unknown error'}"
    )


def _validate_ranges(ipv4_ranges: List[str], ipv6_ranges: List[str]) -> None:
    if not ipv4_ranges and not ipv6_ranges:
        raise CatalogueFetchError("catalogue contains no IP prefixes")
    for cidr in ipv4_ranges:
        try:
            version = ipaddress.ip_network(cidr).version
        except ValueError as error:
            raise CatalogueFetchError(f"invalid IPv4 prefix: {cidr}") from error
        if version != 4:
            raise CatalogueFetchError(f"invalid IPv4 prefix: {cidr}")
    for cidr in ipv6_ranges:
        try:
            version = ipaddress.ip_network(cidr).version
        except ValueError as error:
            raise CatalogueFetchError(f"invalid IPv6 prefix: {cidr}") from error
        if version != 6:
            raise CatalogueFetchError(f"invalid IPv6 prefix: {cidr}")


def _add_metadata(metadata, cidr, attribution):
    entries = metadata.setdefault(cidr, [])
    if attribution not in entries:
        entries.append(attribution)


def _normalise_metadata(metadata, ranges):
    if not isinstance(metadata, dict):
        raise CatalogueFetchError("catalogue metadata is not an object")
    normalised = {}
    for cidr in ranges:
        entries = metadata.get(cidr)
        # Snapshots written before multi-valued metadata used one three-item
        # list: [region, service, border_group].
        if (
            isinstance(entries, list)
            and len(entries) == 3
            and all(isinstance(value, str) for value in entries)
        ):
            entries = [entries]
        if not isinstance(entries, list) or not entries:
            raise CatalogueFetchError(f"catalogue has no metadata for prefix: {cidr}")
        for entry in entries:
            if not (
                isinstance(entry, (list, tuple))
                and len(entry) == 3
                and all(isinstance(value, str) and value for value in entry)
            ):
                raise CatalogueFetchError(f"invalid metadata for prefix: {cidr}")
            _add_metadata(normalised, cidr, tuple(entry))
    return normalised


def _parse_standard(data: dict, extreme: bool) -> Tuple[List, List, Dict]:
    prefixes = data.get("prefixes")
    if not isinstance(prefixes, list):
        raise CatalogueFetchError("missing or invalid 'prefixes' list")
    ipv6_prefixes = data.get("ipv6_prefixes", [])
    if not isinstance(ipv6_prefixes, list):
        raise CatalogueFetchError("invalid 'ipv6_prefixes' list")

    ipv4_ranges = []
    ipv6_ranges = []
    metadata = {}
    for prefix in prefixes + ipv6_prefixes:
        if not isinstance(prefix, dict):
            raise CatalogueFetchError("prefix entry is not an object")
        region = prefix.get("region") or prefix.get("scope") or "unknown"
        service = prefix.get("service") or "unknown"
        border_group = prefix.get("network_border_group") or "unknown"
        for keyword in IPV4_KEYWORDS:
            if keyword in prefix:
                cidr = prefix[keyword]
                ipv4_ranges.append(cidr)
                _add_metadata(metadata, cidr, (region, service, border_group))
        for keyword in IPV6_KEYWORDS:
            if keyword in prefix:
                cidr = prefix[keyword]
                ipv6_ranges.append(cidr)
                _add_metadata(metadata, cidr, (region, service, border_group))
    _validate_ranges(ipv4_ranges, ipv6_ranges)
    if extreme:
        print("IPv4 Ranges:", ipv4_ranges)
        print("IPv6 Ranges:", ipv6_ranges)
    return ipv4_ranges, ipv6_ranges, metadata


def _parse_azure(data: dict, extreme: bool) -> Tuple[List, List, Dict]:
    values = data.get("values")
    if not isinstance(values, list):
        raise CatalogueFetchError("missing or invalid 'values' list")

    ipv4_ranges = []
    ipv6_ranges = []
    metadata = {}
    for value in values:
        if not isinstance(value, dict) or not isinstance(value.get("properties"), dict):
            raise CatalogueFetchError("Azure value entry has invalid properties")
        props = value["properties"]
        prefixes = props.get("addressPrefixes")
        if not isinstance(prefixes, list):
            raise CatalogueFetchError("Azure value has no addressPrefixes list")
        region = props.get("region") or "global"
        service = props.get("systemService") or value.get("name") or "unknown"
        for cidr in prefixes:
            (ipv6_ranges if ":" in cidr else ipv4_ranges).append(cidr)
            _add_metadata(metadata, cidr, (region, service, "unknown"))
    _validate_ranges(ipv4_ranges, ipv6_ranges)
    if extreme:
        print("IPv4 Ranges:", ipv4_ranges)
        print("IPv6 Ranges:", ipv6_ranges)
    return ipv4_ranges, ipv6_ranges, metadata


def fetch_ip_ranges(url: str, extreme: bool = False) -> Tuple[List, List, Dict]:
    return _parse_standard(_get_json(url), extreme)


def fetch_ip_ranges_for_azure(url: str, extreme: bool) -> Tuple[List, List, Dict]:
    return _parse_azure(_get_json(url), extreme)


def _snapshot_id(ranges: Tuple[List, List, Dict]) -> str:
    payload = json.dumps(ranges, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _cache_path(output_dir: str, provider: str) -> Path:
    return Path(output_dir).parent / ".provider_catalog_cache" / f"{provider}.json"


def _write_catalogue(path: Path, catalogue: ProviderCatalogue) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(asdict(catalogue), handle, indent=2)
    os.replace(temporary, path)


def _save_catalogue(output_dir: str, catalogue: ProviderCatalogue) -> None:
    _write_catalogue(
        Path(output_dir) / f"{catalogue.provider}_ip_ranges.json", catalogue
    )
    _write_catalogue(_cache_path(output_dir, catalogue.provider), catalogue)


def _load_cached_catalogue(
    output_dir: str, provider: str, source_url: str
) -> ProviderCatalogue:
    path = _cache_path(output_dir, provider)
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    retrieved_at = datetime.fromisoformat(data["retrieved_at"].replace("Z", "+00:00"))
    now = _utc_now()
    if retrieved_at > now + timedelta(minutes=5):
        raise CatalogueFetchError(f"cached catalogue has a future timestamp ({path})")
    if now - retrieved_at > MAX_CACHE_AGE[provider]:
        raise CatalogueFetchError(f"cached catalogue is stale ({path})")
    raw_ranges = (data["ipv4_ranges"], data["ipv6_ranges"], data["metadata"])
    _validate_ranges(raw_ranges[0], raw_ranges[1])
    calculated_snapshot = _snapshot_id(raw_ranges)
    if data.get("snapshot_id") not in (None, calculated_snapshot):
        raise CatalogueFetchError(
            f"cached catalogue snapshot ID does not match ({path})"
        )
    ranges = (
        raw_ranges[0],
        raw_ranges[1],
        _normalise_metadata(raw_ranges[2], raw_ranges[0] + raw_ranges[1]),
    )
    catalogue = ProviderCatalogue(
        provider=provider,
        ipv4_ranges=ranges[0],
        ipv6_ranges=ranges[1],
        metadata=ranges[2],
        status="cached",
        usable=True,
        source_url=data.get("source_url") or source_url,
        retrieved_at=data["retrieved_at"],
        snapshot_id=_snapshot_id(ranges),
    )
    _write_catalogue(Path(output_dir) / f"{provider}_ip_ranges.json", catalogue)
    return catalogue


def _failed_catalogue(
    provider: str, source_url: str, error: Exception
) -> ProviderCatalogue:
    return ProviderCatalogue(
        provider=provider,
        ipv4_ranges=[],
        ipv6_ranges=[],
        metadata={},
        status="failed",
        usable=False,
        source_url=source_url,
        retrieved_at=None,
        snapshot_id=None,
        error=str(error),
    )


def _fetch_catalogue(
    provider: str, source_url: str, output_dir: str, extreme: bool, parser
) -> ProviderCatalogue:
    try:
        ranges = parser(source_url, extreme)
        if len(ranges) != 3:
            raise CatalogueFetchError("parser returned an incomplete catalogue")
        _validate_ranges(ranges[0], ranges[1])
        ranges = (
            ranges[0],
            ranges[1],
            _normalise_metadata(ranges[2], ranges[0] + ranges[1]),
        )
        catalogue = ProviderCatalogue(
            provider=provider,
            ipv4_ranges=ranges[0],
            ipv6_ranges=ranges[1],
            metadata=ranges[2],
            status="complete",
            usable=True,
            source_url=source_url,
            retrieved_at=_timestamp(_utc_now()),
            snapshot_id=_snapshot_id(ranges),
        )
        _save_catalogue(output_dir, catalogue)
        return catalogue
    except (
        CatalogueFetchError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as live_error:
        try:
            return _load_cached_catalogue(output_dir, provider, source_url)
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            CatalogueFetchError,
        ) as cache_error:
            return _failed_catalogue(
                provider,
                source_url,
                CatalogueFetchError(f"live fetch: {live_error}; cache: {cache_error}"),
            )


def fetch_google_cloud_ip_ranges(
    output_dir: str, extreme: bool = False
) -> ProviderCatalogue:
    return _fetch_catalogue(
        "gcp", PROVIDER_SOURCES["gcp"], output_dir, extreme, fetch_ip_ranges
    )


def fetch_aws_ip_ranges(output_dir: str, extreme: bool = False) -> ProviderCatalogue:
    return _fetch_catalogue(
        "aws", PROVIDER_SOURCES["aws"], output_dir, extreme, fetch_ip_ranges
    )


# Pinned as of 2026-05-10. It is only attempted when discovery is unavailable.
AZURE_PINNED_URL = (
    "https://download.microsoft.com/download/7/1/d/"
    "71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20260504.json"
)
AZURE_CONFIRMATION_URL = (
    "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
)


def _discover_azure_url() -> str:
    errors = []
    for attempt in range(FETCH_ATTEMPTS):
        try:
            with urlopen(
                AZURE_CONFIRMATION_URL, timeout=FETCH_TIMEOUT_SECONDS
            ) as response:
                html = response.read().decode("utf-8")
            match = re.search(
                r"https://download\.microsoft\.com/download/[^\"]+\.json", html
            )
            if not match:
                raise CatalogueFetchError("download link not found")
            return match.group(0)
        except Exception as error:
            errors.append(str(error))
            if attempt + 1 < FETCH_ATTEMPTS:
                sleep(RETRY_DELAY_SECONDS)
    raise CatalogueFetchError(f"Azure URL discovery failed: {errors[-1]}")


def fetch_azure_ip_ranges(output_dir: str, extreme: bool = False) -> ProviderCatalogue:
    discovery_error = None
    try:
        source_url = _discover_azure_url()
    except CatalogueFetchError as error:
        discovery_error = error
        source_url = AZURE_PINNED_URL

    catalogue = _fetch_catalogue(
        "azure", source_url, output_dir, extreme, fetch_ip_ranges_for_azure
    )
    if catalogue.usable:
        return catalogue
    if discovery_error:
        return ProviderCatalogue(
            **{**asdict(catalogue), "error": f"{discovery_error}; {catalogue.error}"}
        )
    return catalogue
