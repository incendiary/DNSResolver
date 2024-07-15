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
from classes.DomainProcessingContext import DomainProcessingContext


def main():
    env_manager = EnvironmentManager()
    # env_manager.parse_arguments()

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

    patterns = load_domain_categorisation_patterns(env_manager.get_config_file())

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
                    env_manager.log_info(f"Starting thread for domain: {domain}")
                if len(threads) >= max_threads:
                    threads.pop(0).join()

                domain_context = DomainProcessingContext(env_manager)
                domain_context.set_domain(domain)
                domain_context.set_nameservers(env_manager.get_resolvers())
                domain_context.set_output_files(env_manager.get_output_files())
                domain_context.set_verbose(env_manager.get_verbose())
                domain_context.set_extreme(env_manager.get_extreme())
                domain_context.set_gcp_ipv4(gcp_ipv4)
                domain_context.set_gcp_ipv6(gcp_ipv6)
                domain_context.set_aws_ipv4(aws_ipv4)
                domain_context.set_aws_ipv6(aws_ipv6)
                domain_context.set_azure_ipv4(azure_ipv4)
                domain_context.set_azure_ipv6(azure_ipv6)
                domain_context.set_perform_service_checks(
                    env_manager.get_service_checks()
                )
                domain_context.set_timeout(env_manager.get_timeout())
                domain_context.set_retries(env_manager.get_retries())
                domain_context.set_patterns(patterns)
                domain_context.set_dangling_domains(dangling_domains)
                domain_context.set_failed_domains(failed_domains)
                domain_context.set_evidence_enabled(env_manager.get_evidence())
                domain_context.set_logger(env_manager.get_logger())

                thread = threading.Thread(
                    target=process_domain,
                    args=(domain_context, env_manager, pbar),
                )
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

    # Print final messages
    env_manager.log_info(
        f"All resolutions completed. Results saved to %s", env_manager.get_output_dir()
    )

    if env_manager.get_extreme():
        env_manager.log_info("AWS IPv4 Ranges: %s", aws_ipv4)
        env_manager.log_info("AWS IPv6 Ranges: %s", aws_ipv6)
        env_manager.log_info("Google Cloud IPv4 Ranges: %s", gcp_ipv4)
        env_manager.log_info("Google Cloud IPv6 Ranges: %s", gcp_ipv6)
        env_manager.log_info("Azure IPv4 Ranges: %s", azure_ipv4)
        env_manager.log_info("Azure IPv6 Ranges: %s", azure_ipv6)


if __name__ == "__main__":
    main()
