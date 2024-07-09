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

from imports.cloud_service_provider_checks import perform_csp_checks
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
    evidence_enabled,
    logger,
):
    """
    :param domain: The domain to be processed.
    :param nameservers: The list of nameservers to use for DNS resolution.
    :param output_files: The list of output files to write results to.
    :param pbar: The progress bar object to update.
    :param verbose: Boolean flag indicating whether to print verbose output.
    :param extreme: Boolean flag indicating whether to run extreme checks.
    :param gcp_ipv4: The list of GCP IPv4 addresses to check against.
    :param gcp_ipv6: The list of GCP IPv6 addresses to check against.
    :param aws_ipv4: The list of AWS IPv4 addresses to check against.
    :param aws_ipv6: The list of AWS IPv6 addresses to check against.
    :param azure_ipv4: The list of Azure IPv4 addresses to check against.
    :param azure_ipv6: The list of Azure IPv6 addresses to check against.
    :param perform_service_checks: Boolean flag indicating whether to perform service connectivity checks.
    :param timeout: The timeout value for DNS resolution.
    :param retries: The number of times to retry DNS resolution.
    :param patterns: The list of patterns to match against resolved IP addresses.
    :param dangling_domains: The list of dangling domains found during resolution.
    :param failed_domains: The list of failed domains during resolution.
    :param evidence_enabled: Boolean flag indicating whether to enable evidence collection.
    :param logger: Logger instance for logging information.
    :return: None
    """
    resolver = create_resolver(timeout, nameservers)

    logger.info(f"Processing domain: {domain}")

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
        evidence_enabled,
        logger,
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
            logger,
        )

        if perform_service_checks:
            perform_service_connectivity_checks(domain, output_files, verbose, logger)

    pbar.update(1)
    logger.info(f"Finished processing domain: {domain}")
