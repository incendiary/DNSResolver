"""
This module provides functions related to DNS resolution, CSP checks, and service connectivity checks for domains.

It imports functions from three other modules:
- cloud_csp_checks for performing CSP (Content Security Policy) checks
- dns_based_checks for creating a DNS resolver and resolving domains
- service_connectivity_checks for performing checks for service connectivity

The main function in this module, process_domain, combines these checks to
perform a comprehensive domain analysis.

Functions:
  process_domain : Processes a domain by performing DNS resolution,
                   CSP checks, and service connectivity checks.
"""

from imports.cloud_csp_checks import perform_csp_checks
from imports.dns_based_checks import create_resolver, resolve_domain
from imports.service_connectivity_checks import perform_service_connectivity_checks


def process_domain(
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
):
    """
    Process a domain by performing DNS resolution, CSP checks, and service connectivity checks.

    :param domain: The domain to be processed.
    :param nameservers: The nameservers to be used for DNS resolution.
    :param output_files: The output files to store the results.
    :param pbar: The progress bar to update.
    :param verbose: Set to True for verbose output.
    :param extreme: Set to True to enable extreme mode.
    :param gcp_ipv4: The IPv4 ranges for Google Cloud Platform.
    :param gcp_ipv6: The IPv6 ranges for Google Cloud Platform.
    :param aws_ipv4: The IPv4 ranges for Amazon Web Services.
    :param aws_ipv6: The IPv6 ranges for Amazon Web Services.
    :param azure_ipv4: The IPv4 ranges for Microsoft Azure.
    :param azure_ipv6: The IPv6 ranges for Microsoft Azure.
    :param perform_service_checks: Set to True to perform service connectivity checks.
    :param timeout: The timeout for DNS resolution.
    :param retries: The number of DNS resolution retries.
    :param patterns: The patterns to match against DNS responses.
    :param dangling_domains: List to store dangling domain results.
    :param failed_domains: List to store failed domain results.
    :return: None
    """
    resolver = create_resolver(timeout, nameservers)

    success, final_ips = resolve_domain(
        resolver,
        domain,
        nameservers,
        output_files,
        verbose,
        retries,
        patterns,
        dangling_domains,
        failed_domains,
    )

    if success:
        perform_csp_checks(
            domain,
            output_files,
            final_ips,
            gcp_ipv4,
            gcp_ipv6,
            aws_ipv4,
            aws_ipv6,
            azure_ipv4,
            azure_ipv6,
            verbose,
            extreme,
        )

        if perform_service_checks:
            perform_service_connectivity_checks(domain, output_files, verbose, extreme)

    pbar.update(1)
