"""Module for fetching and parsing IP ranges from Google Cloud, AWS, Azure, and
checking if an IP address is in given IP ranges."""

import json
import os
import re
from typing import Dict, List, Tuple
from urllib.request import urlopen

import requests

IPV4_KEYWORDS = ["ipv4Prefix", "ip_prefix", "addressPrefixes"]
IPV6_KEYWORDS = ["ipv6Prefix", "ipv6_prefix", "addressPrefixes"]


def fetch_ip_ranges_for_azure(url: str, extreme: bool) -> Tuple[List, List, Dict]:
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(
                f"Failed to fetch IP ranges for Azure. Status code: {response.status_code}"
            )
            return [], [], {}

        data = json.loads(response.text)

        ipv4_ranges = []
        ipv6_ranges = []
        metadata = {}

        for value in data.get("values", []):
            props = value.get("properties", {})
            # Global tags carry an empty region; say so rather than inventing one.
            region = props.get("region") or "global"
            service = props.get("systemService") or value.get("name") or "unknown"
            for item in props.get("addressPrefixes", []):
                if ":" in item:
                    ipv6_ranges.append(item)
                else:
                    ipv4_ranges.append(item)
                metadata[item] = (region, service, "unknown")

        if extreme:
            print("IPv4 Ranges:", ipv4_ranges)
            print("IPv6 Ranges:", ipv6_ranges)

        return ipv4_ranges, ipv6_ranges, metadata

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the IP ranges: {e}")
        return [], [], {}


def fetch_ip_ranges(url: str, extreme: bool = False) -> Tuple[List, List, Dict]:
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"Failed to fetch IP ranges. Status code: {response.status_code}")
            return [], [], {}

        data = json.loads(response.text)

        if "prefixes" not in data:
            print(f"No 'prefixes' key in retrieved data: {data}")
            return [], [], {}

        ipv4_ranges = []
        ipv6_ranges = []
        metadata = {}

        for prefix in data["prefixes"]:
            # AWS calls it 'region', GCP calls it 'scope'. Both name the place an
            # address is allocated from, which is what an operator needs in order
            # to act on a match.
            region = prefix.get("region") or prefix.get("scope") or "unknown"
            service = prefix.get("service") or "unknown"
            # AWS publishes the network border group: the boundary an Elastic IP
            # is actually allocated and advertised from. It usually mirrors the
            # region but differs for Local Zones and Wavelength, which is exactly
            # where the distinction matters. GCP and Azure publish no equivalent.
            border_group = prefix.get("network_border_group") or "unknown"

            for keyword in IPV4_KEYWORDS:
                if keyword in prefix:
                    cidr = prefix[keyword]
                    ipv4_ranges.append(cidr)
                    metadata[cidr] = (region, service, border_group)
            for keyword in IPV6_KEYWORDS:
                if keyword in prefix:
                    cidr = prefix[keyword]
                    ipv6_ranges.append(cidr)
                    metadata[cidr] = (region, service, border_group)

        if extreme:
            print("IPv4 Ranges:", ipv4_ranges)
            print("IPv6 Ranges:", ipv6_ranges)

        return ipv4_ranges, ipv6_ranges, metadata

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the IP ranges: {e}")
    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")

    return [], [], {}


def _fetch_and_save(
    url: str, filename: str, output_dir: str, extreme: bool
) -> Tuple[List, List, Dict]:
    ranges = fetch_ip_ranges(url, extreme)
    with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as f:
        json.dump(ranges, f, indent=4)
    return ranges


def fetch_google_cloud_ip_ranges(
    output_dir: str, extreme: bool = False
) -> Tuple[List, List, Dict]:
    return _fetch_and_save(
        "https://www.gstatic.com/ipranges/cloud.json",
        "gcp_ip_ranges.json",
        output_dir,
        extreme,
    )


def fetch_aws_ip_ranges(
    output_dir: str, extreme: bool = False
) -> Tuple[List, List, Dict]:
    return _fetch_and_save(
        "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "aws_ip_ranges.json",
        output_dir,
        extreme,
    )


# Pinned as of 2026-05-10. Update when Microsoft rotates the file.
AZURE_PINNED_URL = (
    "https://download.microsoft.com/download/7/1/d/"
    "71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20260504.json"
)
AZURE_CACHE_PATH = ".azure_ip_cache.json"


def _save_azure_cache(ranges: Tuple[List, List, Dict]) -> None:
    try:
        with open(AZURE_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(ranges, f, indent=4)
    except IOError as e:
        print(f"Warning: could not write Azure IP cache: {e}")


def _load_azure_cache() -> Tuple[List, List, Dict]:
    with open(AZURE_CACHE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Caches written before region/service capture hold only the two range lists.
    # Read them rather than discarding a usable cache; metadata is simply absent.
    metadata = data[2] if len(data) > 2 else {}
    return data[0], data[1], metadata


def fetch_azure_ip_ranges(
    output_dir: str, extreme: bool = False
) -> Tuple[List, List, Dict]:
    confirmation_url = (
        "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
    )
    json_url = None

    # Step 1: scrape the confirmation page for the current download URL
    try:
        with urlopen(confirmation_url, timeout=10) as response:
            html = response.read().decode("utf-8")
            match = re.search(
                r'https://download\.microsoft\.com/download/[^"]+\.json', html
            )
            if match:
                json_url = match.group(0)
            else:
                print("Azure IP fetch: download link not found on confirmation page.")
    except Exception as e:
        print(f"Azure IP fetch: confirmation page unavailable — {e}")

    # Step 2: if scrape succeeded, fetch and return
    if json_url:
        ranges = fetch_ip_ranges_for_azure(json_url, extreme)
        if ranges[0] or ranges[1]:
            _save_azure_cache(ranges)
            with open(
                os.path.join(output_dir, "azure_ip_ranges.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(ranges, f, indent=4)
            return ranges

    # Step 3: scrape failed — try local cache
    if os.path.exists(AZURE_CACHE_PATH):
        print(
            f"Azure IP fetch: using cached ranges from '{AZURE_CACHE_PATH}'. "
            "To fetch fresh data set AZURE_PINNED_URL to the latest Microsoft download URL."
        )
        try:
            return _load_azure_cache()
        except Exception as e:
            print(f"Azure IP fetch: cache load failed — {e}")

    # Step 4: no cache — fall back to pinned URL
    print(
        f"Azure IP fetch: no cache found, falling back to pinned URL ({AZURE_PINNED_URL}). "
        "This may be stale — update AZURE_PINNED_URL in cloud_ip_ranges.py if needed."
    )
    ranges = fetch_ip_ranges_for_azure(AZURE_PINNED_URL, extreme)
    if ranges[0] or ranges[1]:
        _save_azure_cache(ranges)
        with open(
            os.path.join(output_dir, "azure_ip_ranges.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(ranges, f, indent=4)
        return ranges

    print("Azure IP fetch: all sources exhausted — no Azure ranges loaded.")
    return [], [], {}
