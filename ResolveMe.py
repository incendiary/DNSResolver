import argparse
import os
import json
import re
import threading
import ipaddress
from datetime import datetime
from tqdm import tqdm
import requests
from urllib.request import urlopen
import dns.resolver
import dns.exception


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


# Function to detect potential cloud service takeovers
def detect_potential_takeovers(dangling_cname_file, output_file):
    # Define patterns for known cloud services
    patterns = {
        "aws": re.compile(r"\.compute\.amazonaws\.com\."),
        "azure": re.compile(r"\.cloudapp\.azure\.com\."),
        "gcp": re.compile(r"\.cloud\.google\.com\."),
    }

    with open(dangling_cname_file, "r") as infile, open(output_file, "a") as outfile:
        for line in infile:
            domain = line.strip()
            for cloud_provider, pattern in patterns.items():
                if pattern.search(domain):
                    outfile.write(
                        f"Potential {cloud_provider.upper()} takeover candidate: {domain}\n"
                    )
                    print(
                        f"Potential {cloud_provider.upper()} takeover candidate: {domain}"
                    )


# Function to process each domain
def process_domain(
    domain,
    nameservers,
    authoritative,
    resolve_all,
    output_files,
    pbar,
    verbose,
    extreme,
):
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers

    resolved_records = []
    order_index = 0

    try:
        current_domain = domain
        while True:
            cname_chain_resolved = False
            for record_type in ["CNAME"]:
                try:
                    answer = resolver.resolve(current_domain, record_type)
                    resolved_records.append(
                        (record_type, [str(rdata) for rdata in answer])
                    )
                    current_domain = str(answer[0].target)
                    cname_chain_resolved = True
                    break
                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers,
                ):
                    continue

            if not cname_chain_resolved:
                break

        # Resolve A and AAAA records for the final domain
        final_ips = []
        for record_type in ["A", "AAAA"]:
            try:
                answer = resolver.resolve(current_domain, record_type)
                final_ips.extend([str(rdata) for rdata in answer])
                resolved_records.append((record_type, [str(rdata) for rdata in answer]))
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
            ):
                continue

        if resolved_records:
            if verbose or extreme:
                print(f"Writing resolved records for domain: {domain}")

            print(output_files["resolved"])

            with open(output_files["resolved"], "a") as f:
                f.write(f"{domain}:\n")
                for record_type, records in resolved_records:
                    f.write(f"  {record_type}:\n")
                    for record in records:
                        f.write(f"    {record}\n")
                if verbose or extreme:
                    print(
                        f"Written resolved records to file: {output_files['resolved']}"
                    )

            # Check if IPs are in cloud ranges
            in_gcp = any(is_in_ip_ranges(ip, gcp_ipv4, gcp_ipv6) for ip in final_ips)
            in_aws = any(is_in_ip_ranges(ip, aws_ipv4, aws_ipv6) for ip in final_ips)
            in_azure = any(
                is_in_ip_ranges(ip, azure_ipv4, azure_ipv6) for ip in final_ips
            )

            if in_gcp:
                if verbose or extreme:
                    print(f"Writing GCP resolved IPs for domain: {domain}")
                with open(output_files["gcp"], "a") as f:
                    f.write(f"{domain}: {final_ips}\n")
                if verbose or extreme:
                    print(f"Written GCP records to file: {output_files['gcp']}")
            if in_aws:
                if verbose or extreme:
                    print(f"Writing AWS resolved IPs for domain: {domain}")
                with open(output_files["aws"], "a") as f:
                    f.write(f"{domain}: {final_ips}\n")
                if verbose or extreme:
                    print(f"Written AWS records to file: {output_files['aws']}")
            if in_azure:
                if verbose or extreme:
                    print(f"Writing Azure resolved IPs for domain: {domain}")
                with open(output_files["azure"], "a") as f:
                    f.write(f"{domain}: {final_ips}\n")
                if verbose or extreme:
                    print(f"Written Azure records to file: {output_files['azure']}")

            if verbose or extreme:
                print(f"{domain} resolved to {resolved_records}")
                if in_gcp:
                    print(f"{domain} is in Google Cloud IP ranges.")
                if in_aws:
                    print(f"{domain} is in AWS IP ranges.")
                if in_azure:
                    print(f"{domain} is in Azure IP ranges.")

    except dns.exception.DNSException as e:
        if verbose or extreme:
            print(f"Failed to resolve {domain}: {e}")

    finally:
        pbar.update(1)


def main(domains_file, output_dir, resolvers=None, verbose=False, extreme=False):
    # Create output directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(output_dir, timestamp)
    os.makedirs(output_dir, exist_ok=True)

    # Output files
    resolved_file = os.path.join(output_dir, f"resolved_results_{timestamp}.txt")
    gcp_file = os.path.join(output_dir, f"gcp_results_{timestamp}.txt")
    aws_file = os.path.join(output_dir, f"aws_results_{timestamp}.txt")
    azure_file = os.path.join(output_dir, f"azure_results_{timestamp}.txt")
    dangling_cname_file = os.path.join(
        output_dir, f"dangling_cname_results_{timestamp}.txt"
    )

    # Create empty dangling CNAME file to avoid FileNotFoundError
    with open(dangling_cname_file, "w") as f:
        pass

    output_files = {
        "resolved": resolved_file,
        "gcp": gcp_file,
        "aws": aws_file,
        "azure": azure_file,
    }

    # Prepare nameservers list if provided
    if resolvers:
        nameservers = resolvers.split(",")
    else:
        nameservers = None

    # Fetch and parse cloud provider IP ranges
    global gcp_ipv4, gcp_ipv6, aws_ipv4, aws_ipv6, azure_ipv4, azure_ipv6
    gcp_ipv4, gcp_ipv6 = fetch_google_cloud_ip_ranges(output_dir, extreme)
    aws_ipv4, aws_ipv6 = fetch_aws_ip_ranges(output_dir, extreme)
    azure_ipv4, azure_ipv6 = fetch_azure_ip_ranges(output_dir, extreme)

    # Read domains from input file
    with open(domains_file, "r") as f:
        domains = f.read().splitlines()

    if verbose or extreme:
        print(f"Domains to process: {domains}")

    # Initialize progress bar
    with tqdm(total=len(domains), desc="Processing Domains") as pbar:
        threads = []

        # Process each domain using threads
        for domain in domains:
            if verbose or extreme:
                print(f"Starting thread for domain: {domain}")
            thread = threading.Thread(
                target=process_domain,
                args=(
                    domain,
                    nameservers,
                    False,  # Set authoritative to False for now
                    False,  # Set resolve_all to False for now
                    output_files,
                    pbar,
                    verbose,
                    extreme,
                ),
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    # Check for potential cloud service takeovers
    detect_potential_takeovers(dangling_cname_file, resolved_file)

    # Print final messages
    print("All resolutions completed. Results saved to", output_dir)

    if extreme:
        print("AWS IPv4 Ranges:", aws_ipv4)
        print("AWS IPv6 Ranges:", aws_ipv6)
        print("Google Cloud IPv4 Ranges:", gcp_ipv4)
        print("Google Cloud IPv6 Ranges:", gcp_ipv6)
        print("Azure IPv4 Ranges:", azure_ipv4)
        print("Azure IPv6 Ranges:", azure_ipv6)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Resolve DNS records for domains and check against cloud provider IP ranges."
    )
    parser.add_argument(
        "domains_file",
        type=str,
        help="Path to the file containing domains (one per line)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="output",
        help="Directory to save output files (default: output)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose mode to display more information",
    )
    parser.add_argument(
        "--extreme",
        "-e",
        action="store_true",
        help="Enable extreme mode to display extensive information (including IP ranges)",
    )
    parser.add_argument(
        "--resolvers",
        "-r",
        type=str,
        help="Comma-separated list of custom resolvers. Overrides system resolvers.",
    )

    args = parser.parse_args()

    main(
        args.domains_file,
        args.output_dir,
        args.resolvers,
        verbose=args.verbose,
        extreme=args.extreme,
    )
