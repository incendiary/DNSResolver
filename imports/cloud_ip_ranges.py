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
    """
    :param url: The URL from which to fetch the IP ranges for Azure.
    :param extreme: A boolean flag indicating whether to print the fetched IP ranges or not.
    :return: A tuple containing two lists: the list of IPv4 ranges and the list of IPv6 ranges.

    This method fetches the IP ranges for Azure from the provided URL. It sends a GET request to the URL and
    checks the response status code. If the status code is not 200, it prints an error message and returns empty
    lists for both IPv4 and IPv6 ranges.

    If the status code is 200, it parses the response JSON and extracts the IPv4 and IPv6 ranges from the
    "addressPrefixes" property of each "properties" object in the "values" list. It filters out any IPv6 addresses
    from the IPv4 ranges list and filters out any non-IPv6 addresses from the IPv6 ranges list.

    If the "extreme" flag is set to True, it also prints the fetched IPv4 and IPv6 ranges.

    Finally, it returns a tuple containing the filtered IPv4 ranges and the filtered IPv6 ranges.

    If any error occurs during the request or parsing the response, it prints an error message and exits the program
    with a non-zero status code.
    """
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"Failed to fetch IP ranges for Azure. Status code: {response.status_code}")
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
    """
    Fetch IP ranges from specified URL.

    :param url: URL for HTTP request
    :param extreme: Boolean to print IP ranges
    :return: IPv4 and IPv6 ranges
    """
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


def fetch_google_cloud_ip_ranges(output_dir: str, extreme: bool = False) -> Tuple[List, List]:
    """
    Fetch Google Cloud IP ranges and save as JSON.

    :param output_dir: Directory for JSON output
    :param extreme: Boolean to print IP ranges
    :return: IP ranges
    """
    url = "https://www.gstatic.com/ipranges/cloud.json"
    ranges = fetch_ip_ranges(url, extreme)
    with open(os.path.join(output_dir, "gcp_ip_ranges.json"), "w", encoding="utf-8") as f:
        json.dump(ranges, f, indent=4)
    return ranges


def fetch_aws_ip_ranges(output_dir: str, extreme: bool = False) -> Tuple[List, List]:
    """
    Fetch AWS IP ranges and save as JSON.

    :param output_dir: Directory for JSON output
    :param extreme: Boolean to print IP ranges
    :return: IP ranges
    """
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    ranges = fetch_ip_ranges(url, extreme)
    with open(os.path.join(output_dir, "aws_ip_ranges.json"), "w", encoding="utf-8") as f:
        json.dump(ranges, f, indent=4)
    return ranges


def fetch_azure_ip_ranges(output_dir: str, extreme: bool = False) -> Tuple[List, List]:
    """
    Fetch Azure IP ranges and save as JSON.

    :param output_dir: Directory for JSON output
    :param extreme: Boolean to print IP ranges
    :return: IP ranges
    """
    url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
    try:
        with urlopen(url) as response:
            html = response.read().decode("utf-8")
            download_link = re.search(r'https://download\.microsoft\.com/download/[^"]+', html)
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
