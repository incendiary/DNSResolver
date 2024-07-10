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
from classes.EnvironmentManager import EnvironmentManager


def main():
    env_manager = EnvironmentManager()
    env_manager.parse_arguments()

    env_manager.initialize_environment()
    env_manager.save_environment_info()

    gcp_ipv4, gcp_ipv6 = fetch_google_cloud_ip_ranges(
        env_manager.get_output_dir(), env_manager.extreme
    )
    aws_ipv4, aws_ipv6 = fetch_aws_ip_ranges(
        env_manager.get_output_dir(), env_manager.extreme
    )
    azure_ipv4, azure_ipv6 = fetch_azure_ip_ranges(
        env_manager.get_output_dir(), env_manager.extreme
    )

    env_manager.set_domains()

    if env_manager.verbose:
        env_manager.get_logger().info(
            f"Domains to process: {env_manager.get_domains()}"
        )

    patterns = load_domain_categorisation_patterns()

    max_threads = env_manager.max_threads or 10

    dangling_domains = set()
    failed_domains = set(env_manager.get_domains())

    for attempt in range(env_manager.retries + 1):
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
                if env_manager.verbose:
                    env_manager.get_logger().info(
                        f"Starting thread for domain: {domain}"
                    )
                if len(threads) >= max_threads:
                    threads.pop(0).join()
                thread = threading.Thread(
                    target=process_domain,
                    args=(
                        domain,
                        env_manager.get_resolvers(),
                        env_manager.get_output_files(),
                        pbar,
                        env_manager.get_verbose(),
                        env_manager.get_extreme(),
                        gcp_ipv4,
                        gcp_ipv6,
                        aws_ipv4,
                        aws_ipv6,
                        azure_ipv4,
                        azure_ipv6,
                        env_manager.get_service_checks(),
                        env_manager.get_timeout(),
                        env_manager.get_retries(),
                        patterns,
                        dangling_domains,
                        failed_domains,
                        env_manager.evidence,
                        env_manager.get_logger(),  # Pass the logger to process_domain
                    ),
                )
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

    # Print final messages
    env_manager.get_logger().info(
        "All resolutions completed. Results saved to %s", env_manager.get_output_dir()
    )

    if env_manager.extreme:
        env_manager.get_logger().info("AWS IPv4 Ranges: %s", aws_ipv4)
        env_manager.get_logger().info("AWS IPv6 Ranges: %s", aws_ipv6)
        env_manager.get_logger().info("Google Cloud IPv4 Ranges: %s", gcp_ipv4)
        env_manager.get_logger().info("Google Cloud IPv6 Ranges: %s", gcp_ipv6)
        env_manager.get_logger().info("Azure IPv4 Ranges: %s", azure_ipv4)
        env_manager.get_logger().info("Azure IPv6 Ranges: %s", azure_ipv6)


if __name__ == "__main__":
    main()
