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


def perform_csp_checks(domain_context, env_manager, final_ips):
    """
    :param domain_context: The DomainProcessingContext object containing domain details.
    :param env_manager: The EnvironmentManager object.
    :param final_ips: List of resolved IP addresses for the domain.
    :return: None
    """
    domain = domain_context.get_domain()
    output_files = env_manager.get_output_files()
    gcp_ipv4 = domain_context.get_gcp_ipv4()
    gcp_ipv6 = domain_context.get_gcp_ipv6()
    aws_ipv4 = domain_context.get_aws_ipv4()
    aws_ipv6 = domain_context.get_aws_ipv6()
    azure_ipv4 = domain_context.get_azure_ipv4()
    azure_ipv6 = domain_context.get_azure_ipv6()
    verbose = env_manager.get_verbose()
    extreme = env_manager.get_extreme()
    logger = env_manager.get_logger()

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
