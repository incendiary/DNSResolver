import dns.resolver
import dns.query
import dns.message
import argparse
import time
import threading
import json
import requests
import ipaddress
from datetime import datetime
import os
import re
import random
from tqdm import tqdm
from urllib.request import urlopen
import base64
import socket


# Function to fetch and parse Google Cloud IP ranges
def fetch_google_cloud_ip_ranges(output_dir):
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
def fetch_aws_ip_ranges(output_dir):
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
            return ipv4_ranges, ipv6_ranges
        else:
            print(f"Failed to fetch AWS IP ranges. Status code: {response.status_code}")
            return [], []
    except Exception as e:
        print(f"An error occurred while fetching AWS IP ranges: {e}")
        return [], []


# Function to fetch and parse Azure IP ranges
def fetch_azure_ip_ranges(output_dir):
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


def query_ns(server_ip, domain):
    try:
        query = dns.message.make_query(domain, dns.rdatatype.NS)
        response = dns.query.udp(query, server_ip, timeout=3)
        return response
    except Exception as e:
        print(f"Failed to query {server_ip} for {domain}: {e}")
        return None


def get_tld_ns(tld):
    try:
        root_ns = "a.root-servers.net"
        root_ns_ip = dns.resolver.resolve(root_ns, "A")[0].to_text()
        response = query_ns(root_ns_ip, tld)
        if response:
            tld_ns = [
                rr.target.to_text()
                for rr in response.authority[0]
                if rr.rdtype == dns.rdatatype.NS
            ]
            return tld_ns
    except Exception as e:
        print(f"Failed to retrieve TLD nameservers for {tld}: {e}")
    return None


def get_domain_ns(tld_ns, domain):
    for ns in tld_ns:
        try:
            ns_ip = dns.resolver.resolve(ns, "A")[0].to_text()
            response = query_ns(ns_ip, domain)
            if response and response.answer:
                domain_ns = [
                    rr.target.to_text()
                    for rr in response.answer[0]
                    if rr.rdtype == dns.rdatatype.NS
                ]
                return domain_ns
            elif response and response.authority:
                domain_ns = [
                    rr.target.to_text()
                    for rr in response.authority[0]
                    if rr.rdtype == dns.rdatatype.NS
                ]
                return domain_ns
        except dns.exception.DNSException as e:
            print(f"Failed to query {ns} for {domain}: {e}")
    return None


def get_subdomain_ns(domain_ns, subdomain):
    if not domain_ns:
        return None

    for ns in domain_ns:
        try:
            ns_ip = dns.resolver.resolve(ns, "A")[0].to_text()
            response = query_ns(ns_ip, subdomain)
            if response and response.answer:
                subdomain_ns = [
                    rr.target.to_text()
                    for rr in response.answer[0]
                    if rr.rdtype == dns.rdatatype.NS
                ]
                return subdomain_ns
            elif response and response.authority:
                subdomain_ns = [
                    rr.target.to_text()
                    for rr in response.authority[0]
                    if rr.rdtype == dns.rdatatype.NS
                ]
                return subdomain_ns
        except dns.exception.DNSException as e:
            print(f"Failed to query {ns} for {subdomain}: {e}")
    return None


def resolve_domain(domain, nameservers=None, authoritative=False):
    records = {}
    retries = 3
    timeout = 10  # Timeout in seconds

    while retries > 0:
        try:
            this_resolver = dns.resolver.Resolver()
            if authoritative:
                domain_ns = resolve_domain_iteratively(domain)
                print(
                    f"Authoritative nameservers for {domain}: {domain_ns}"
                )  # Log authoritative nameservers
                if domain_ns:
                    this_resolver.nameservers = []
                    for ns in domain_ns:
                        try:
                            ns_ips = dns.resolver.resolve(ns, "A")
                            for ns_ip in ns_ips:
                                this_resolver.nameservers.append(ns_ip.to_text())
                        except Exception as e:
                            print(f"Failed to resolve nameserver {ns}: {e}")
            elif nameservers:
                this_resolver.nameservers = nameservers
            this_resolver.timeout = timeout
            this_resolver.lifetime = timeout

            for qtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
                try:
                    answers = this_resolver.resolve(
                        domain, qtype, raise_on_no_answer=False
                    )
                    records[qtype] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    print(f"No answer for {domain} type {qtype}")
                    records[qtype] = []
                except dns.exception.DNSException as e:
                    print(f"Error resolving {domain} type {qtype}: {e}")
                    records[qtype] = []

            return records  # Return records if resolved successfully

        except dns.resolver.NoAnswer:
            # Handle no answer by assuming parent domain's NS is authoritative
            break
        except dns.resolver.NXDOMAIN:
            records["NXDOMAIN"] = True
            return records
        except dns.exception.Timeout:
            retries -= 1
            if retries > 0:
                print(
                    f"Timeout occurred - {domain}. Retrying... Attempts left: {retries}"
                )
                time.sleep(1)  # Wait for a moment before retrying
            else:
                print(
                    f"Maximum retries exceeded for {domain}. Returning timeout message."
                )
                records["TIMEOUT"] = True
                return records
        except Exception as e:
            print(f"An error occurred while resolving 287 {domain}: {e}")
            return records  # Return empty records on any other error

    return (
        records  # Fallback in case retries are exhausted without successful resolution
    )


def resolve_domain_iteratively(domain):
    parts = domain.split(".")
    tld = parts[-1]
    tld_ns = get_tld_ns(tld)
    print(f"TLD nameservers for {tld}: {tld_ns}")  # Log TLD nameservers
    if not tld_ns:
        print(f"Failed to retrieve TLD name servers for {tld}")
        return []

    current_domain = parts[-2] + "." + tld
    domain_ns = get_domain_ns(tld_ns, current_domain)
    print(
        f"Domain nameservers for {current_domain}: {domain_ns}"
    )  # Log domain nameservers
    if not domain_ns:
        print(f"Failed to retrieve domain name servers for {current_domain}")
        return []

    for i in range(len(parts) - 2, 0, -1):
        subdomain = ".".join(parts[i:])
        subdomain_ns = get_subdomain_ns(domain_ns, subdomain)
        print(
            f"Subdomain nameservers for {subdomain}: {subdomain_ns}"
        )  # Log subdomain nameservers
        if subdomain_ns:
            domain_ns = subdomain_ns
        else:
            break

    return domain_ns


# Function to resolve CNAME records recursively with retries and timeout handling
def resolve_cname_recursively(domain, nameservers=None, authoritative=False):
    resolved_records = {}
    to_resolve = [domain]

    while to_resolve:
        current_domain = to_resolve.pop(0)
        records = resolve_domain(
            current_domain, nameservers, authoritative=authoritative
        )
        resolved_records[current_domain] = records
        if "CNAME" in records:
            to_resolve.extend(records["CNAME"])

    return resolved_records


# Function to detect potential cloud service takeovers
def detect_potential_takeovers(dangling_cname_file, output_file):
    # Define patterns for known cloud services
    patterns = {
        "aws": re.compile(r"\.compute\.amazonaws\.com\."),
        "azure": re.compile(r"\.cloudapp\.azure\.com\."),
        "gcp": re.compile(r"\.cloud\.google\.com\."),
    }

    with open(dangling_cname_file, "r") as infile, open(output_file, "w") as outfile:
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


def process_domain(domain, nameservers, authoritative, resolve_all, output_files, pbar):
    try:
        resolved_records = resolve_cname_recursively(
            domain, nameservers, authoritative=authoritative
        )
        differences_found = False
        differences = []

        if resolve_all:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = nameservers
            domain_ns = resolve_domain_iteratively(domain)
            print(
                f"Domain NS for {domain} when resolving all: {domain_ns}"
            )  # Log domain NS
            if domain_ns:
                authoritative_ns = domain_ns
                authoritative_ips = []
                for ns in authoritative_ns:
                    try:
                        ns_ips = resolver.resolve(ns, "A")
                        for ns_ip in ns_ips:
                            authoritative_ips.append(ns_ip.address)
                    except Exception as e:
                        print(f"Failed to resolve authoritative nameserver {ns}: {e}")
                all_records = []
                for ns_ip in authoritative_ips:
                    try:
                        ns_records = resolve_cname_recursively(
                            domain, [ns_ip], authoritative=True
                        )
                        all_records.append(ns_records)
                        if len(all_records) > 1:
                            if ns_records != all_records[0]:
                                differences_found = True
                                differences.append((ns_ip, ns_records))
                    except Exception as e:
                        print(
                            f"Error while resolving {domain} with authoritative IP {ns_ip}: {e}"
                        )

                if differences_found:
                    with open(output_files["differences"], "a") as diff_file:
                        diff_file.write(f"Differences found for {domain}:\n")
                        for ns_ip, ns_records in differences:
                            diff_file.write(f"  {ns_ip}:\n")
                            for record_type, values in ns_records[domain].items():
                                if isinstance(values, list):  # Ensure values is a list
                                    for value in values:
                                        diff_file.write(f"    {record_type}: {value}\n")

        with open(output_files["resolved"], "a") as output_file:
            output_file.write(f"{domain}:\n")
            for domain, records in resolved_records.items():
                for record_type, values in records.items():
                    if isinstance(values, list):  # Ensure values is a list
                        for value in values:
                            output_file.write(f"  {record_type}: {value}\n")
                            # Check against GCP ranges
                            if record_type == "A":
                                in_gcp = is_in_ip_ranges(value, gcp_ipv4, gcp_ipv6)
                                gcp_status = "in" if in_gcp else "not in"
                                with open(output_files["gcp"], "a") as gcp_output:
                                    gcp_output.write(
                                        f"{domain} resolves to {value} which is {gcp_status} Google address range\n"
                                    )
                            # Check against AWS ranges
                            in_aws = is_in_ip_ranges(value, aws_ipv4, aws_ipv6)
                            aws_status = "in" if in_aws else "not in"
                            with open(output_files["aws"], "a") as aws_output:
                                aws_output.write(
                                    f"{domain} resolves to {value} which is {aws_status} AWS address range\n"
                                )
                            # Check against Azure ranges
                            in_azure = is_in_ip_ranges(value, azure_ipv4, azure_ipv6)
                            azure_status = "in" if in_azure else "not in"
                            with open(output_files["azure"], "a") as azure_output:
                                azure_output.write(
                                    f"{domain} resolves to {value} which is {azure_status} Azure address range\n"
                                )
        pbar.update(1)

    except Exception as e:
        print(f"An error occurred while resolving {domain}: {e}")
        with open(output_files["timeout"], "a") as timeout_file:
            timeout_file.write(f"{domain}: {e}\n")
        pbar.update(1)


def main():
    # Argument parsing
    parser = argparse.ArgumentParser(
        description="DNS Resolver with optional authoritative queries and cloud range checking."
    )
    parser.add_argument(
        "input_file", help="Input file with DNS names/FQDNs line by line."
    )
    parser.add_argument(
        "--authoritative",
        "-a",
        action="store_true",
        help="Query authoritative servers directly.",
    )
    parser.add_argument(
        "--resolve-all",
        "-A",
        action="store_true",
        help="Query all authoritative servers for the domain for differences in resolution.",
    )
    parser.add_argument(
        "--resolvers",
        "-r",
        type=str,
        help="Comma-separated list of custom resolvers. Overrides system resolvers.",
    )
    parser.add_argument(
        "--threads",
        "-t",
        type=int,
        default=None,
        help="Number of concurrent threads. Default is number of CPU cores.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output directory for result files.",
    )
    args = parser.parse_args()

    # Use provided nameservers or system nameservers
    if args.resolvers:
        nameservers = args.resolvers.split(",")
    else:
        nameservers = dns.resolver.Resolver().nameservers

    if args.authoritative:
        args.resolve_all = True

    # Determine the number of threads
    num_threads = args.threads if args.threads is not None else (os.cpu_count() - 1)

    # Timestamp for output file names
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output if args.output else os.path.join("output", timestamp)

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    output_files = {
        "resolved": os.path.join(output_dir, f"resolved_results_{timestamp}.txt"),
        "dangling": os.path.join(output_dir, f"dangling_cnames_{timestamp}.txt"),
        "timeout": os.path.join(output_dir, f"timeouts_{timestamp}.txt"),
        "gcp": os.path.join(output_dir, f"gcp_{timestamp}.txt"),
        "aws": os.path.join(output_dir, f"aws_{timestamp}.txt"),
        "azure": os.path.join(output_dir, f"azure_{timestamp}.txt"),
        "differences": os.path.join(output_dir, f"differences_{timestamp}.txt"),
        "json_output": os.path.join(output_dir, f"resolved_results_{timestamp}.json"),
    }

    # Read input domains
    with open(args.input_file, "r") as f:
        domains = [line.strip() for line in f.readlines()]

    # Fetch cloud IP ranges
    global gcp_ipv4, gcp_ipv6, aws_ipv4, aws_ipv6, azure_ipv4, azure_ipv6
    gcp_ipv4, gcp_ipv6 = fetch_google_cloud_ip_ranges(output_dir)
    aws_ipv4, aws_ipv6 = fetch_aws_ip_ranges(output_dir)
    azure_ipv4, azure_ipv6 = fetch_azure_ip_ranges(output_dir)

    # Thread pool for processing domains
    threads = []
    json_results = {}
    with tqdm(total=len(domains), desc="Processing Domains") as pbar:
        for domain in domains:
            thread = threading.Thread(
                target=process_domain,
                args=(
                    domain,
                    nameservers,
                    args.authoritative,
                    args.resolve_all,
                    output_files,
                    pbar,
                ),
            )
            threads.append(thread)
            thread.start()
            if len(threads) >= num_threads:
                for t in threads:
                    t.join()
                threads = []

        # Wait for remaining threads to finish
        for t in threads:
            t.join()

    # Additional data for JSON output
    json_results["command"] = " ".join(os.sys.argv)
    json_results["source_ip"] = socket.gethostbyname(socket.gethostname())
    json_results["external_ip"] = requests.get("https://ifconfig.io/ip").text.strip()
    json_results["gcp_ipv4"] = base64.b64encode("\n".join(gcp_ipv4).encode()).decode()
    json_results["gcp_ipv6"] = base64.b64encode("\n".join(gcp_ipv6).encode()).decode()
    json_results["aws_ipv4"] = base64.b64encode("\n".join(aws_ipv4).encode()).decode()
    json_results["aws_ipv6"] = base64.b64encode("\n".join(aws_ipv6).encode()).decode()
    json_results["azure_ipv4"] = base64.b64encode(
        "\n".join(azure_ipv4).encode()
    ).decode()
    json_results["azure_ipv6"] = base64.b64encode(
        "\n".join(azure_ipv6).encode()
    ).decode()
    json_results["resolved_domains"] = {}

    with open(output_files["resolved"], "r") as f:
        domain = None
        for line in f:
            line = line.strip()
            if line.endswith(":"):
                domain = line[:-1]
                json_results["resolved_domains"][domain] = {}
            else:
                record_type, value = line.split(": ", 1)
                if record_type not in json_results["resolved_domains"][domain]:
                    json_results["resolved_domains"][domain][record_type] = []
                json_results["resolved_domains"][domain][record_type].append(value)

    with open(output_files["json_output"], "w") as json_file:
        json.dump(json_results, json_file, indent=4)

    print(f"All resolutions completed. Results saved to {output_dir}")


if __name__ == "__main__":
    main()
