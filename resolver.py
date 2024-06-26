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

import argparse
import json
import os
import threading
from datetime import datetime

from tqdm import tqdm

from imports.cloud_ip_ranges import (
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
)
from imports.cname_checker import detect_direct_takeovers
from imports.domain_processor import process_domain
from imports.environment import create_empty_files, get_environment_info


def main(
    domains_file,
    output_dir,
    resolvers=None,
    verbose=False,
    extreme=False,
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
    resolved_file = os.path.join(
        output_dir, f"resolved_results_{timestamp}.txt")
    gcp_file = os.path.join(output_dir, f"gcp_results_{timestamp}.txt")
    aws_file = os.path.join(output_dir, f"aws_results_{timestamp}.txt")
    azure_file = os.path.join(output_dir, f"azure_results_{timestamp}.txt")
    dangling_cname_file = os.path.join(
        output_dir, f"dangling_cname_results_{timestamp}.txt"
    )
    direct_reference_file = os.path.join(
        output_dir, f"direct_reference_results_{timestamp}.txt"
    )
    environment_file = os.path.join(
        output_dir, f"environment_results_{timestamp}.json")

    output_files = {
        "resolved": resolved_file,
        "gcp": gcp_file,
        "aws": aws_file,
        "azure": azure_file,
        "direct": direct_reference_file,
        "dangling": dangling_cname_file,
        "environment": environment_file,
    }

    # Create empty files to avoid FileNotFoundError
    create_empty_files(output_files)

    environment_info = get_environment_info()
    with open(output_files["environment"], "w", encoding="utf-8") as json_file:
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
                    nameservers,  # Values can be none for system resolution, a list for --resolvers
                    False,  # Set authoritative to False for now
                    False,  # Set resolve_all to False for now
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
                ),
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    # Check for potential cloud service takeovers
    detect_direct_takeovers(direct_reference_file, resolved_file)

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
        description="Resolve DNS records for domains and check against cloud provider IP ranges.")
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

    parser.add_argument(
        "--internal-resolvers",
        "-ir",
        type=str,
        help="Comma-separated list of internal custom resolvers.",
    )

    parser.add_argument(
        "--external-resolvers",
        "-er",
        type=str,
        help="Comma-separated list of external custom resolvers.",
    )

    args = parser.parse_args()

    main(
        args.domains_file,
        args.output_dir,
        resolvers=args.resolvers,
        verbose=args.verbose,
        extreme=args.extreme,
    )
