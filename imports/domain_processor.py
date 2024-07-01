"""This module focuses on performing DNS record analyses for given domain
names. It provides functionality to resolve a domain's CNAME chain, check for
dangling CNAMEs, and resolve the domain's 'A' (IPv4) and 'AAAA' (IPv6) records.

The main function in the module, `process_domain`, also verifies if the
resolved IPs are within IP ranges of certain cloud platforms, specifically
Google Cloud Platform, Amazon Web Service, and Microsoft Azure.

Functions defined in the `cloud_ip_ranges` and `cname_checker` modules are
used to support these operations.

In brief, this module is intended to provide a thorough DNS resolution process
and relation check with known cloud platforms, aiding in identifying potential
security pitfalls like dangling DNS records.

The results of these operations are written to specified output files and can
optionally be printed to the console in verbose scenarios.
"""

import dns.resolver
from imports.cloud_csp_checks import perform_csp_checks
from imports.dns_based_checks import resolve_domain, create_resolver
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
):
    """
    Process a domain and resolve its DNS records and perform additional checks.

    :param domain: The domain to be processed.
    :param nameservers: Optional list of nameservers to use for DNS resolution.
    :param output_files: Dictionary of output file paths.
    :param pbar: Progress bar object to update.
    :param verbose: Boolean flag indicating whether to enable verbose logging.
    :param extreme: Boolean flag indicating whether to enable extreme checks.
    :param gcp_ipv4: List of GCP IPv4 CIDR ranges.
    :param gcp_ipv6: List of GCP IPv6 CIDR ranges.
    :param aws_ipv4: List of AWS IPv4 CIDR ranges.
    :param aws_ipv6: List of AWS IPv6 CIDR ranges.
    :param azure_ipv4: List of Azure IPv4 CIDR ranges.
    :param azure_ipv6: List of Azure IPv6 CIDR ranges.
    :param perform_service_checks: Boolean flag indicating whether to perform service checks.
    :param timeout: Timeout for DNS resolution in seconds.
    :return: None
    """

    resolver = create_resolver(timeout, nameservers)

    print(verbose)

    success, final_ips = resolve_domain(
        resolver, domain, nameservers, output_files, verbose
    )

    print(final_ips)

    # returns true if domain completed resolution
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
