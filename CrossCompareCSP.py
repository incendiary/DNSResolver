import json
import requests
import ipaddress
from datetime import datetime


# Function to fetch and parse Google Cloud IP ranges
def fetch_google_cloud_ip_ranges():
    url = "https://www.gstatic.com/ipranges/cloud.json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            ipv4_ranges = [prefix['ipv4Prefix'] for prefix in data['prefixes'] if 'ipv4Prefix' in prefix]
            ipv6_ranges = [prefix['ipv6Prefix'] for prefix in data['prefixes'] if 'ipv6Prefix' in prefix]
            return ipv4_ranges, ipv6_ranges
        else:
            print(f"Failed to fetch Google Cloud IP ranges. Status code: {response.status_code}")
            return [], []
    except Exception as e:
        print(f"An error occurred while fetching Google Cloud IP ranges: {e}")
        return [], []


# Function to fetch and parse AWS IP ranges
def fetch_aws_ip_ranges():
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            ipv4_ranges = [prefix['ip_prefix'] for prefix in data['prefixes'] if 'ip_prefix' in prefix]
            ipv6_ranges = [prefix['ipv6_prefix'] for prefix in data['ipv6_prefixes'] if 'ipv6_prefix' in prefix]
            return ipv4_ranges, ipv6_ranges
        else:
            print(f"Failed to fetch AWS IP ranges. Status code: {response.status_code}")
            return [], []
    except Exception as e:
        print(f"An error occurred while fetching AWS IP ranges: {e}")
        return [], []


# Function to fetch and parse Azure IP ranges
def fetch_azure_ip_ranges():
    url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            ipv4_ranges = [prefix for prefix in data['values'] if
                           'properties' in prefix and 'addressPrefixes' in prefix['properties']]
            ipv6_ranges = []
            for prefix in ipv4_ranges:
                for addr in prefix['properties']['addressPrefixes']:
                    if ":" in addr:
                        ipv6_ranges.append(addr)
                    else:
                        ipv4_ranges.append(addr)
            return ipv4_ranges, ipv6_ranges
        else:
            print(f"Failed to fetch Azure IP ranges. Status code: {response.status_code}")
            return [], []
    except Exception as e:
        print(f"An error occurred while fetching Azure IP ranges: {e}")
        return [], []


# Function to check if an IP address is within given IP ranges
def is_in_ip_ranges(ip_address, ipv4_ranges, ipv6_ranges):
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.version == 4:
            for cidr in ipv4_ranges:
                if ip in ipaddress.ip_network(cidr):
                    return True
        elif ip.version == 6:
            for cidr in ipv6_ranges:
                if ip in ipaddress.ip_network(cidr):
                    return True
        return False
    except ValueError:
        return False


# Fetch IP ranges
gcp_ipv4, gcp_ipv6 = fetch_google_cloud_ip_ranges()
aws_ipv4, aws_ipv6 = fetch_aws_ip_ranges()
azure_ipv4, azure_ipv6 = fetch_azure_ip_ranges()

# Check if fetching IP ranges failed, exit if it did
if not gcp_ipv4 and not gcp_ipv6:
    print("Unable to fetch Google Cloud IP ranges. Exiting.")
    exit(1)
if not aws_ipv4 and not aws_ipv6:
    print("Unable to fetch AWS IP ranges. Exiting.")
    exit(1)
if not azure_ipv4 and not azure_ipv6:
    print("Unable to fetch Azure IP ranges. Exiting.")
    exit(1)

# Get the current timestamp and format it
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
resolved_results_file = "resolved_results.txt"
gcp_output_file = f"gcp_comparison_results_{timestamp}.txt"
aws_output_file = f"aws_comparison_results_{timestamp}.txt"
azure_output_file = f"azure_comparison_results_{timestamp}.txt"

# Open resolved_results.txt and compare IP addresses
with open(resolved_results_file, 'r') as f:
    with open(gcp_output_file, 'w') as gcp_output, open(aws_output_file, 'w') as aws_output, open(azure_output_file,
                                                                                                  'w') as azure_output:
        for line in f:
            line = line.strip()
            if line.startswith("A:") or line.startswith("CNAME:"):
                parts = line.split()
                fqdn = parts[0].rstrip(':')
                ip_address = parts[1]

                in_gcp = is_in_ip_ranges(ip_address, gcp_ipv4, gcp_ipv6)
                gcp_status = "in" if in_gcp else "not in"
                gcp_output.write(f"{fqdn} resolves to {ip_address} which is {gcp_status} Google address range\n")

                in_aws = is_in_ip_ranges(ip_address, aws_ipv4, aws_ipv6)
                aws_status = "in" if in_aws else "not in"
                aws_output.write(f"{fqdn} resolves to {ip_address} which is {aws_status} AWS address range\n")

                in_azure = is_in_ip_ranges(ip_address, azure_ipv4, azure_ipv6)
                azure_status = "in" if in_azure else "not in"
                azure_output.write(f"{fqdn} resolves to {ip_address} which is {azure_status} Azure address range\n")

print(f"Comparison results saved to {gcp_output_file}, {aws_output_file}, and {azure_output_file}")
