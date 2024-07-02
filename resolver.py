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

import threading
from datetime import datetime

from tqdm import tqdm

from imports.cloud_ip_ranges import (
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
)
from imports.domain_processor import process_domain
from imports.environment import (
    parse_arguments,
    initialize_environment,
    save_environment_info,
    get_environment_info,
    read_domains,
)
from imports.dns_based_checks import load_domain_categorisation_regexes


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
    """

    # Initialize the environment and fetch the required configurations
    timestamp, output_dir, output_files = initialize_environment(
        output_dir, perform_service_checks
    )

    # Save environment information
    environment_info = get_environment_info()
    save_environment_info(output_files["standard"]["environment"], environment_info)

    if resolvers:
        nameservers = resolvers.split(",")
    else:
        nameservers = None

    # Fetch and parse cloud provider IP ranges
    gcp_ipv4, gcp_ipv6 = fetch_google_cloud_ip_ranges(output_dir, extreme)
    aws_ipv4, aws_ipv6 = fetch_aws_ip_ranges(output_dir, extreme)
    azure_ipv4, azure_ipv6 = fetch_azure_ip_ranges(output_dir, extreme)

    # Read domains from input file
    domains = read_domains(domains_file)

    if verbose:
        print(f"Domains to process: {domains}")

    patterns = load_domain_categorisation_regexes()

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
                ).join()  # remove the oldest thread and wait for it to complete
            thread = threading.Thread(
                target=process_domain,
                args=(
                    domain,
                    nameservers,
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
                    patterns,
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
