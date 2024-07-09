"""
This module performs checks for resolved domains and their associated IP addresses against known IP ranges
of major Cloud Service Providers (CSP) such as AWS, GCP, and Azure.

Functions:
- perform_csp_checks: Checks resolved IPs against known IP ranges of major cloud providers (AWS, GCP, Azure)
                      and logs the results.

The module leverages the IP ranges fetched from respective cloud providers to match against resolved IPs.
"""

import logging

logger = logging.getLogger("DNSResolver")


def perform_csp_checks(
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
):
    """
    :param domain: The domain being checked.
    :param output_files: Dictionary of output files to write results to.
    :param final_ips: List of resolved IP addresses for the domain.
    :param gcp_ipv4: List of Google Cloud IPv4 ranges.
    :param gcp_ipv6: List of Google Cloud IPv6 ranges.
    :param aws_ipv4: List of AWS IPv4 ranges.
    :param aws_ipv6: List of AWS IPv6 ranges.
    :param azure_ipv4: List of Azure IPv4 ranges.
    :param azure_ipv6: List of Azure IPv6 ranges.
    :param verbose: Boolean flag indicating whether to print verbose output.
    :param extreme: Boolean flag indicating whether to run extreme checks.
    :return: None
    """
    gcp_matches = []
    aws_matches = []
    azure_matches = []

    for ip in final_ips:
        if ip in gcp_ipv4 or ip in gcp_ipv6:
            gcp_matches.append(ip)
        if ip in aws_ipv4 or ip in aws_ipv6:
            aws_matches.append(ip)
        if ip in azure_ipv4 or ip in azure_ipv6:
            azure_matches.append(ip)

    if gcp_matches:
        with open(output_files["standard"]["gcp"], "a", encoding="utf-8") as file:
            file.write(f"{domain} resolved to Google Cloud IPs: {gcp_matches}\n")
        logger.info(f"{domain} resolved to Google Cloud IPs: {gcp_matches}")

    if aws_matches:
        with open(output_files["standard"]["aws"], "a", encoding="utf-8") as file:
            file.write(f"{domain} resolved to AWS IPs: {aws_matches}\n")
        logger.info(f"{domain} resolved to AWS IPs: {aws_matches}")

    if azure_matches:
        with open(output_files["standard"]["azure"], "a", encoding="utf-8") as file:
            file.write(f"{domain} resolved to Azure IPs: {azure_matches}\n")
        logger.info(f"{domain} resolved to Azure IPs: {azure_matches}")

    if verbose or extreme:
        if gcp_matches or aws_matches or azure_matches:
            logger.info(f"{domain} resolved to cloud IPs:")
            if gcp_matches:
                logger.info(f"  Google Cloud: {gcp_matches}")
            if aws_matches:
                logger.info(f"  AWS: {aws_matches}")
            if azure_matches:
                logger.info(f"  Azure: {azure_matches}")
