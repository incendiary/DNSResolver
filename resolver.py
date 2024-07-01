"""
This python module resolves DNS records for a given list of domains
and checks them against the known IP ranges of major cloud providers
(AWS, GCP, and Azure).

This script handles multithreading for DNS resolutions and provides
different verbose levels for extra logging (default, verbose, and extreme).
The results of DNS resolution and Cloud IPs matching are stored in the specified
output directory.

The script can be run directly with the use of command-line arguments for
specifying the domains file, output directory, verbosity mode and custom resolvers.
"""

import json
import os
import threading
from datetime import datetime

from imports.environment import parse_arguments

from tqdm import tqdm

from imports.cloud_ip_ranges import (
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
)
from imports.domain_processor import process_domain
from imports.environment import create_empty_files_or_directories, get_environment_info


def main(
    domains_file,
    output_dir,
    resolvers=None,
    max_threads=None,
    verbose=False,
    extreme=False,
    perform_service_checks=True,
    timeout=10,
    retries=3,
):
    """
    Main method for resolving domains and detecting potential cloud service takeovers.

    :param domains_file: Path to a file containing domains to be resolved.
    :type domains_file: str
    :param output_dir: Directory where output files will be saved.
    :type output_dir: str
    :param resolvers: Optional comma-separated list of custom DNS resolvers.
    :type resolvers: str, optional
    :param verbose: If True, prints additional information during processing.
    :type verbose: bool, optional
    :param extreme: If True, fetches and prints cloud provider IP ranges.
    :type extreme: bool, optional
    :return: None
    """

    # Create output directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(output_dir, timestamp)
    os.makedirs(output_dir, exist_ok=True)

    # Output files
    resolution_file = os.path.join(output_dir, f"resolution_results_{timestamp}.txt")
    tcp_common_ports_unreachable_file = os.path.join(
        output_dir, f"tls_common_ports_unreachable_{timestamp}.txt"
    )
    unresolved_file = os.path.join(output_dir, f"unresolved_results_{timestamp}.txt")
    gcp_file = os.path.join(output_dir, f"gcp_results_{timestamp}.txt")
    aws_file = os.path.join(output_dir, f"aws_results_{timestamp}.txt")
    azure_file = os.path.join(output_dir, f"azure_results_{timestamp}.txt")
    dangling_cname_file = os.path.join(
        output_dir, f"dangling_cname_results_{timestamp}.txt"
    )
    environment_file = os.path.join(output_dir, f"environment_results_{timestamp}.json")
    ssl_tls_failure_file = os.path.join(
        output_dir, f"ssl_tls_failure_results_{timestamp}.txt"
    )
    http_failure_file = os.path.join(
        output_dir, f"http_failure_results_{timestamp}.txt"
    )
    screenshot_failure_file = os.path.join(
        output_dir, f"failure_results_{timestamp}.txt"
    )
    ns_takeover_file = os.path.join(output_dir, f"ns_takeover_results_{timestamp}.txt")

    screenshot_dir = os.path.join(output_dir, f"screenshot_results_{timestamp}")
    timeout_file = os.path.join(output_dir, f"timeout_results_{timestamp}.txt")
    output_files = {
        "standard": {
            "resolved": resolution_file,
            "unresolved": unresolved_file,
            "gcp": gcp_file,
            "aws": aws_file,
            "azure": azure_file,
            "dangling": dangling_cname_file,
            "ns_takeover": ns_takeover_file,
            "environment": environment_file,
            "timeout": timeout_file,
        },
        "service_checks": {
            "ssl_tls_failure_file": ssl_tls_failure_file,
            "http_failure_file": http_failure_file,
            "tcp_common_ports_unreachable_file": tcp_common_ports_unreachable_file,
            "screenshot_dir": screenshot_dir,
            "screenshot_failures": screenshot_failure_file,
        },
    }

    # Create empty files to avoid FileNotFoundError
    create_empty_files_or_directories(output_files, perform_service_checks)

    environment_info = get_environment_info()
    with open(
        output_files["standard"]["environment"], "w", encoding="utf-8"
    ) as json_file:
        json_file.write(json.dumps(environment_info, indent=4))

    if resolvers:
        nameservers = resolvers.split(",")
    else:
        nameservers = None

    # Fetch and parse cloud provider IP ranges
    gcp_ipv4, gcp_ipv6 = fetch_google_cloud_ip_ranges(output_dir, extreme)
    aws_ipv4, aws_ipv6 = fetch_aws_ip_ranges(output_dir, extreme)
    azure_ipv4, azure_ipv6 = fetch_azure_ip_ranges(output_dir, extreme)

    # Read domains from input file
    with open(domains_file, "r", encoding="utf-8") as f:
        domains = f.read().splitlines()

    if verbose:
        print(f"Domains to process: {domains}")

    if max_threads is None:
        max_threads = 10  # Default to 10 threads if not specified

    # Initialize progress bar
    with tqdm(total=len(domains), desc="Processing Domains") as pbar:
        threads = []

        # Process each domain using threads
        for domain in domains:
            if verbose:
                print(f"Starting thread for domain: {domain}")
            if len(threads) >= max_threads:
                threads.pop(
                    0
                ).join()  # remove the oldest thread and wait it to complete
            thread = threading.Thread(
                target=process_domain,
                args=(
                    domain,
                    nameservers,  # Values can be none for system resolution, a list for --resolvers
                    output_files,
                    pbar,
                    verbose,
                    extreme,
                    gcp_ipv4,
                    gcp_ipv6,
                    aws_ipv4,
                    aws_ipv6,
                    azure_ipv4,
                    azure_ipv6,
                    perform_service_checks,
                    timeout,
                    retries,
                ),
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

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

    args = parse_arguments()

    main(
        args.domains_file,
        args.output_dir,
        max_threads=args.max_threads,
        resolvers=args.resolvers,
        perform_service_checks=args.service_checks,
        verbose=args.verbose,
        extreme=args.extreme,
        timeout=args.timeout,
        retries=args.retries,
    )
