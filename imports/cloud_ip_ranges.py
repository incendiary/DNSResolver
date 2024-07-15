"""Module for fetching and parsing IP ranges from Google Cloud, AWS, Azure, and
checking if an IP address is in given IP ranges."""

import json
import os
import re
from urllib.request import urlopen

import requests


def fetch_google_cloud_ip_ranges(output_dir, extreme=False):
    """
    Fetches the Google Cloud IP ranges and saves them to a JSON file.

    :param output_dir: The output directory where the JSON file will be saved.
    :param extreme: (Optional) If set to True, it prints the fetched IP ranges to the console.
    :return: A tuple with two lists: the IPv4 ranges and the IPv6 ranges.

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
    Fetches the AWS IP ranges and saves them in a JSON file.

    :param output_dir: The directory where the JSON file will be saved.
    :param extreme: (Optional) If set to True, print the fetched IP ranges to the console.
    :return: A tuple containing a list of IPv4 ranges and a list of IPv6 ranges.
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
    :param output_dir: The directory where the fetched Azure IP ranges JSON file will be saved.
    :param extreme: A boolean indicating whether to print the fetched IP ranges to the console.
    :return: A tuple containing two lists - the first list contains the IPv4 ranges and the second list contains the
    IPv6 ranges.

    The `fetch_azure_ip_ranges` method retrieves the Azure IP ranges information from Microsoft's official website and
    saves it as a JSON file. It then extracts the IPv4 and IPv6 ranges from the retrieved data.

    Example usage:

        ipv4_ranges, ipv6_ranges = fetch_azure_ip_ranges("/path/to/output", extreme=True)
        print("IPv4:", ipv4_ranges)
        print("IPv6:", ipv6_ranges)
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
