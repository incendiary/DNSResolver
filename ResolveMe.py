import argparse
import os
import threading
from datetime import datetime
from tqdm import tqdm
import json

from imports.cloud_ip_ranges import (
    fetch_google_cloud_ip_ranges,
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
)
from imports.cname_checker import detect_direct_takeovers
from imports.domain_processor import process_domain
from imports.environment import create_empty_files, get_environment_info


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
    direct_reference_file = os.path.join(
        output_dir, f"direct_reference_results_{timestamp}.txt"
    )
    environment_file = os.path.join(output_dir, f"environment_results_{timestamp}.json")

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
    with open(output_files["environment"], "w") as json_file:
        json_file.write(json.dumps(environment_info, indent=4))

    # Prepare nameservers list if provided
    if resolvers:
        nameservers = resolvers.split(",")
    else:
        nameservers = None

    # Fetch and parse cloud provider IP ranges
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

    # Check if both `internal_resolvers` and `external_resolvers` are set
    if (args.internal_resolvers and not args.external_resolvers) or (
        not args.internal_resolvers and args.external_resolvers
    ):
        parser.error(
            "Both internal-resolvers and external-resolvers must be set together"
        )

    if args.resolvers and (args.internal_resolvers or args.external_resolvers):
        parser.error(
            "resolvers cannot be set along with internal-resolvers or external-resolvers"
        )

    main(
        args.domains_file,
        args.output_dir,
        args.resolvers,
        verbose=args.verbose,
        extreme=args.extreme,
    )
