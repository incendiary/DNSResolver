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

from tqdm import tqdm

from imports.cloud_ip_ranges import (
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
)
from imports.dns_based_checks import load_domain_categorisation_patterns
from imports.domain_processor import process_domain
from imports.environment import (
    get_environment_info,
    initialize_environment,
    parse_arguments,
    read_domains,
    save_environment_info,
)


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
    :param domains_file: The path to the file containing the list of domains to process.
    :param output_dir: The path to the directory where the output files will be saved.
    :param resolvers: A comma-separated list of custom DNS resolvers to use.
    :param max_threads: The maximum number of concurrent threads to use for processing domains.
    :param verbose: Flag indicating whether to print verbose output during processing.
    :param extreme: Flag indicating whether to perform extreme checks (fetching IP ranges) for AWS, Google Cloud, and Azure.
    :param perform_service_checks: Flag indicating whether to perform service checks for each resolved IP address.
    :param timeout: The timeout value (in seconds) for DNS resolution and service checks.
    :param retries: The number of times to retry failed resolutions.
    :return: None
    """
    timestamp, output_dir, output_files = initialize_environment(
        output_dir, perform_service_checks
    )
    environment_info = get_environment_info()
    save_environment_info(output_files["standard"]["environment"], environment_info)

    if resolvers:
        nameservers = resolvers.split(",")
    else:
        nameservers = None

    gcp_ipv4, gcp_ipv6 = fetch_google_cloud_ip_ranges(output_dir, extreme)
    aws_ipv4, aws_ipv6 = fetch_aws_ip_ranges(output_dir, extreme)
    azure_ipv4, azure_ipv6 = fetch_azure_ip_ranges(output_dir, extreme)

    domains = read_domains(domains_file)

    if verbose:
        print(f"Domains to process: {domains}")

    patterns = load_domain_categorisation_patterns()

    if max_threads is None:
        max_threads = 10

    dangling_domains = set()
    failed_domains = set(domains)

    for attempt in range(retries + 1):
        if not failed_domains:
            break

        current_failed_domains = list(failed_domains)
        failed_domains.clear()

        with tqdm(
            total=len(current_failed_domains),
            desc=f"Processing Domains (Attempt {attempt + 1})",
        ) as pbar:
            threads = []

            for domain in current_failed_domains:
                if verbose:
                    print(f"Starting thread for domain: {domain}")
                if len(threads) >= max_threads:
                    threads.pop(0).join()
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
                        dangling_domains,
                        failed_domains,
                    ),
                )
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

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
