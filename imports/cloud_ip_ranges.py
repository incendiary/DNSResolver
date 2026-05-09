"""Module for fetching and parsing IP ranges from Google Cloud, AWS, Azure, and
checking if an IP address is in given IP ranges."""

import json
import os
import re
import sys
from typing import List, Tuple
from urllib.request import urlopen

import requests

IPV4_KEYWORDS = ["ipv4Prefix", "ip_prefix", "addressPrefixes"]
IPV6_KEYWORDS = ["ipv6Prefix", "ipv6_prefix", "addressPrefixes"]


def fetch_ip_ranges_for_azure(url: str, extreme: bool) -> Tuple[List, List]:
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(
                f"Failed to fetch IP ranges for Azure. Status code: {response.status_code}"
            )
            return [], []

        data = json.loads(response.text)

        ipv4_ranges = [
            item
            for value in data.get("values", [])
            for item in value.get("properties", {}).get("addressPrefixes", [])
            if ":" not in item  # Exclude IPv6 addresses
        ]
        ipv6_ranges = [
            item
            for value in data.get("values", [])
            for item in value.get("properties", {}).get("addressPrefixes", [])
            if ":" in item  # Only include IPv6 addresses
        ]
        if extreme:
            print("IPv4 Ranges:", ipv4_ranges)
            print("IPv6 Ranges:", ipv6_ranges)

        return ipv4_ranges, ipv6_ranges

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the IP ranges: {e}")
        sys.exit(1)


def fetch_ip_ranges(url: str, extreme: bool = False) -> Tuple[List, List]:
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"Failed to fetch IP ranges. Status code: {response.status_code}")
            return [], []

        data = json.loads(response.text)

        if "prefixes" not in data:
            print(f"No 'prefixes' key in retrieved data: {data}")
            return [], []

        ipv4_ranges = [
            prefix[keyword]
            for prefix in data["prefixes"]
            for keyword in IPV4_KEYWORDS
            if keyword in prefix
        ]
        ipv6_ranges = [
            prefix[keyword]
            for prefix in data["prefixes"]
            for keyword in IPV6_KEYWORDS
            if keyword in prefix
        ]
        if extreme:
            print("IPv4 Ranges:", ipv4_ranges)
            print("IPv6 Ranges:", ipv6_ranges)

        return ipv4_ranges, ipv6_ranges

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the IP ranges: {e}")
    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")

    return [], []


def _fetch_and_save(
    url: str, filename: str, output_dir: str, extreme: bool
) -> Tuple[List, List]:
    ranges = fetch_ip_ranges(url, extreme)
    with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as f:
        json.dump(ranges, f, indent=4)
    return ranges


def fetch_google_cloud_ip_ranges(
    output_dir: str, extreme: bool = False
) -> Tuple[List, List]:
    return _fetch_and_save(
        "https://www.gstatic.com/ipranges/cloud.json",
        "gcp_ip_ranges.json",
        output_dir,
        extreme,
    )


def fetch_aws_ip_ranges(output_dir: str, extreme: bool = False) -> Tuple[List, List]:
    return _fetch_and_save(
        "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "aws_ip_ranges.json",
        output_dir,
        extreme,
    )


def fetch_azure_ip_ranges(output_dir: str, extreme: bool = False) -> Tuple[List, List]:
    url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
    try:
        with urlopen(url) as response:
            html = response.read().decode("utf-8")
            download_link = re.search(
                r'https://download\.microsoft\.com/download/[^"]+', html
            )
            if download_link:
                json_url = download_link.group(0)
                ranges = fetch_ip_ranges_for_azure(json_url, extreme)
                with open(
                    os.path.join(output_dir, "azure_ip_ranges.json"),
                    "w",
                    encoding="utf-8",
                ) as f:
                    json.dump(ranges, f, indent=4)
                return ranges
            print("Failed to find download link in the Azure IP ranges page.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching Azure Cloud IP ranges: {e}")
    except IOError as e:
        print(f"An error occurred while writing the Azure IP file: {e}")
    return [], []
