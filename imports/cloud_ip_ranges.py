import json
import os
import re
import requests
from urllib.request import urlopen
import ipaddress


# Function to fetch and parse Google Cloud IP ranges
def fetch_google_cloud_ip_ranges(output_dir, extreme=False):
    url = "https://www.gstatic.com/ipranges/cloud.json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            with open(os.path.join(output_dir, "gcp_ip_ranges.json"), "w") as f:
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
        else:
            print(
                f"Failed to fetch Google Cloud IP ranges. Status code: {response.status_code}"
            )
            return [], []
    except Exception as e:
        print(f"An error occurred while fetching Google Cloud IP ranges: {e}")
        return [], []


# Function to fetch and parse AWS IP ranges
def fetch_aws_ip_ranges(output_dir, extreme=False):
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            with open(os.path.join(output_dir, "aws_ip_ranges.json"), "w") as f:
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
        else:
            print(f"Failed to fetch AWS IP ranges. Status code: {response.status_code}")
            return [], []
    except Exception as e:
        print(f"An error occurred while fetching AWS IP ranges: {e}")
        return [], []


# Function to fetch and parse Azure IP ranges
def fetch_azure_ip_ranges(output_dir, extreme=False):
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
                        os.path.join(output_dir, "azure_ip_ranges.json"), "w"
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
            else:
                print("Failed to find download link in the Azure IP ranges page.")
                return [], []
    except Exception as e:
        print(f"An error occurred while fetching Azure IP ranges: {e}")
        print(f"Azure URL: {url}")
        return [], []


# Function to check if an IP address is within given IP ranges
def is_in_ip_ranges(ip_address, ipv4_ranges, ipv6_ranges, verbose=False, extreme=False):
    def check_ranges(ip, range_set, verbose=False, extreme=False):
        for cidr in range_set:
            if ip in ipaddress.ip_network(cidr):
                if verbose:
                    print(f"{ip} found in {cidr}")
                return True
            elif extreme:
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
        print(f"Invalid IP: {ip_address}") if verbose or extreme else None
        return False
