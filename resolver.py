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
from imports.environment import EnvironmentManager
from imports.cloud_ip_ranges import (
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
)
from imports.domain_processor import process_domain
from imports.dns_based_checks import load_domain_categorisation_patterns


def main():
    env_manager = EnvironmentManager()
    env_manager.parse_arguments()

    timestamp, output_dir, output_files = env_manager.initialize_environment()

    environment_info = env_manager.get_environment_info()
    env_manager.save_environment_info(
        output_files["standard"]["environment"], environment_info
    )

    nameservers = env_manager.resolvers.split(",") if env_manager.resolvers else None

    gcp_ipv4, gcp_ipv6 = fetch_google_cloud_ip_ranges(output_dir, env_manager.extreme)
    aws_ipv4, aws_ipv6 = fetch_aws_ip_ranges(output_dir, env_manager.extreme)
    azure_ipv4, azure_ipv6 = fetch_azure_ip_ranges(output_dir, env_manager.extreme)

    domains = env_manager.read_domains(env_manager.domains_file)

    if env_manager.verbose:
        env_manager.get_logger().info(f"Domains to process: {domains}")

    patterns = load_domain_categorisation_patterns()

    max_threads = env_manager.max_threads or 10

    dangling_domains = set()
    failed_domains = set(domains)

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
                        nameservers,
                        output_files,
                        pbar,
                        env_manager.verbose,
                        env_manager.extreme,
                        gcp_ipv4,
                        gcp_ipv6,
                        aws_ipv4,
                        aws_ipv6,
                        azure_ipv4,
                        azure_ipv6,
                        env_manager.service_checks,
                        env_manager.timeout,
                        env_manager.retries,
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
        "All resolutions completed. Results saved to %s", output_dir
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
