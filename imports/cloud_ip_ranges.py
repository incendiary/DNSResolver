"""Module for fetching and parsing IP ranges from Google Cloud, AWS, Azure, and
checking if an IP address is in given IP ranges."""

import ipaddress
import json
import os
import re
from urllib.request import urlopen

import requests


def fetch_google_cloud_ip_ranges(output_dir, extreme=False):
    """
    Fetches the IP ranges of Google Cloud and saves them to a JSON file.

    :param output_dir: The directory where the JSON file will be saved.
    :param extreme: A flag indicating whether to print the fetched IP ranges. Defaults to False.
    :return: A tuple containing two lists: IPv4 ranges and IPv6 ranges.
    :rtype: tuple
    """
    url = "https://www.gstatic.com/ipranges/cloud.json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = json.loads(response.text)
            with open(
                os.path.join(output_dir, "gcp_ip_ranges.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(data, f, indent=4)
            ipv4_ranges = [
                prefix["ipv4Prefix"]
                for prefix in data["prefixes"]
                if "ipv4Prefix" in prefix
            ]
            ipv6_ranges = [
                prefix["ipv6Prefix"]
                for prefix in data["prefixes"]
                if "ipv6Prefix" in prefix
            ]
            if extreme:
                print("Google Cloud IPv4 Ranges:", ipv4_ranges)
                print("Google Cloud IPv6 Ranges:", ipv6_ranges)
            return ipv4_ranges, ipv6_ranges
        print(
            f"Failed to fetch Google Cloud IP ranges. Status code: {response.status_code}"
        )
        return [], []
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching Google Cloud IP ranges: {e}")
        return [], []
    except IOError as e:
        print(f"An error occurred while writing the GCP IP file: {e}")
        return [], []


def fetch_aws_ip_ranges(output_dir, extreme=False):
    """
    Fetches the AWS IP ranges from the official AWS IP ranges JSON file and saves it to a file.

    :param output_dir: The directory where the JSON file should be saved.
    :param extreme: Whether to print the fetched IP ranges or not. Defaults to False.
    :return: A tuple containing two lists: IPv4 ranges and IPv6 ranges.
    :rtype: tuple
    """
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = json.loads(response.text)
            with open(
                os.path.join(output_dir, "aws_ip_ranges.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(data, f, indent=4)
            ipv4_ranges = [
                prefix["ip_prefix"]
                for prefix in data["prefixes"]
                if "ip_prefix" in prefix
            ]
            ipv6_ranges = [
                prefix["ipv6_prefix"]
                for prefix in data["ipv6_prefixes"]
                if "ipv6_prefix" in prefix
            ]
            if extreme:
                print("AWS IPv4 Ranges:", ipv4_ranges)
                print("AWS IPv6 Ranges:", ipv6_ranges)
            return ipv4_ranges, ipv6_ranges
        print(f"Failed to fetch AWS IP ranges. Status code: {response.status_code}")
        return [], []
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching AWS Cloud IP ranges: {e}")
        return [], []
    except IOError as e:
        print(f"An error occurred while writing the AWS IP file: {e}")
        return [], []


def fetch_azure_ip_ranges(output_dir, extreme=False):
    """
    Fetches Azure IP ranges and saves them to a JSON file.

    :param output_dir: The directory where the JSON file will be saved.
    :param extreme: A flag indicating whether to print the IP ranges to the console.
    :return: A tuple containing two lists: the IPv4 ranges and the IPv6 ranges.
    """
    url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
    try:
        with urlopen(url) as response:
            html = response.read().decode("utf-8")
            download_link = re.search(
                r'https://download\.microsoft\.com/download/[^"]+', html
            )
            if download_link:
                json_url = download_link.group(0)
                with urlopen(json_url) as json_response:
                    data = json.loads(json_response.read().decode("utf-8"))
                    with open(
                        os.path.join(output_dir, "azure_ip_ranges.json"),
                        "w",
                        encoding="utf-8",
                    ) as f:
                        json.dump(data, f, indent=4)
                    ipv4_ranges = [
                        prefix
                        for region in data["values"]
                        for prefix in region["properties"]["addressPrefixes"]
                        if "." in prefix
                    ]
                    ipv6_ranges = [
                        prefix
                        for region in data["values"]
                        for prefix in region["properties"]["addressPrefixes"]
                        if ":" in prefix
                    ]
                    if extreme:
                        print("Azure IPv4 Ranges:", ipv4_ranges)
                        print("Azure IPv6 Ranges:", ipv6_ranges)
                    return ipv4_ranges, ipv6_ranges
            print("Failed to find download link in the Azure IP ranges page.")
            return [], []

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching Azure Cloud IP ranges: {e}")
        return [], []

    except IOError as e:
        print(f"An error occurred while writing the Azure IP file: {e}")
        return [], []


# Function to check if an IP address is within given IP ranges
def is_in_ip_ranges(ip_address, ipv4_ranges, ipv6_ranges, verbose=False, extreme=False):
    """
    Checks if the given IP address is within any of the specified IP ranges.

    :param ip_address: The IP address to check.
    :param ipv4_ranges: List of IPv4 ranges to check against.
    :param ipv6_ranges: List of IPv6 ranges to check against.
    :param verbose: (optional) If True, prints additional information about the search.
    Defaults to False.
    :param extreme: (optional) If True, prints additional information about invalid IP
    addresses. Defaults to False.
    :return: True if the IP address is within any of the ranges, False otherwise.

    """

    def check_ranges(ip, range_set, verbose=False, extreme=False):
        for cidr in range_set:
            if ip in ipaddress.ip_network(cidr):
                if verbose:
                    print(f"{ip} found in {cidr}")
                return True
            if extreme:
                print(f"{ip} not found in {cidr}")
        return False

    try:
        ip = ipaddress.ip_address(ip_address)
        range_sets = (
            (ipv4_ranges, ipv6_ranges)
            if ip.version == 4
            else (ipv6_ranges, ipv4_ranges)
        )
        for range_set in range_sets:
            if check_ranges(ip, range_set, verbose, extreme):
                return True
        if verbose:
            print(f"{ip} not found in any range")
        return False
    except ValueError:
        if verbose or extreme:
            print(f"Invalid IP: {ip_address}")
        return False
