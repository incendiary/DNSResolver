"""
DNS Resolver and Cloud Service Provider (CSP) Check Module

This module provides functionality to perform DNS resolution and check
resolved IP addresses against known IP ranges of major Cloud Service Providers
(CSP) such as AWS, GCP, and Azure. It includes methods to handle
domain processing context, logging, and evidence collection.

Functions:
    perform_csp_checks: Checks resolved IPs against known CSP IP ranges and
    logs the results.

    get_vendor_ips: Retrieves IP ranges for each vendor based on IP version.

    get_ip_matches: Matches IP addresses against the vendor IP ranges.

    is_ip_version: Checks if an IP address matches the specified IP version.

    match_ip_with_vendors: Matches an IP object with vendor IP ranges and
    updates matches.

    merge_matches: Merges IPv4 and IPv6 matches.

    log_and_write: Logs and writes matched IP addresses to the specified
    output files.

    log_cloud_ips: Logs the resolved cloud IPs for a given domain.

    process_domains: Processes a list of domains with retries, checking them
    against CSP IP ranges.

Usage:
    This module is typically used as part of a larger DNS resolution and
    domain analysis system. It can be integrated into scripts or applications
    that require checking domains against CSP IP ranges and logging the
    results for further analysis.

Dependencies:
    - ipaddress
    - os
"""

import ipaddress
import os


def perform_csp_checks(domain_context, env_manager, final_ips):
    """
    Checks IPs against known CSP IP ranges and logs the results.

    :param domain_context: An instance of DomainProcessingContext
    :type domain_context: DomainProcessingContext
    :param env_manager: An instance of EnvironmentManager
    :type env_manager: EnvironmentManager
    :param final_ips: List of IP addresses
    :type final_ips: list[str]
    :return: None
    """
    domain = domain_context.get_domain()
    output_files = env_manager.get_output_files()

    vendor_ips_context_ipv4 = get_vendor_ips(domain_context, ip_version=4)
    vendor_ips_context_ipv6 = get_vendor_ips(domain_context, ip_version=6)

    matches_ipv4 = get_ip_matches(final_ips, vendor_ips_context_ipv4, domain_context, ip_version=4)
    matches_ipv6 = get_ip_matches(final_ips, vendor_ips_context_ipv6, domain_context, ip_version=6)

    matches = merge_matches(matches_ipv4, matches_ipv6, vendor_ips_context_ipv4)

    success = False

    for vendor, matched_ips in matches.items():
        if matched_ips:
            success = (
                log_and_write(vendor, matched_ips, domain, output_files, domain_context) or success
            )
        else:
            domain_context.log_info(f"No cloud IPs were resolved for {vendor}")

    return success


def get_vendor_ips(domain_context, ip_version):
    """
    Get vendor IP ranges based on IP version.

    :param domain_context: An instance of DomainProcessingContext
    :type domain_context: DomainProcessingContext
    :param ip_version: IP version (4 or 6)
    :type ip_version: int
    :return: Dictionary of vendor IP ranges
    :rtype: dict
    """
    if ip_version == 4:
        return {
            "gcp": domain_context.get_gcp_ipv4(),
            "aws": domain_context.get_aws_ipv4(),
            "azure": domain_context.get_azure_ipv4(),
        }
    if ip_version == 6:
        return {
            "gcp": domain_context.get_gcp_ipv6(),
            "aws": domain_context.get_aws_ipv6(),
            "azure": domain_context.get_azure_ipv6(),
        }
    return {}


def get_ip_matches(final_ips, vendor_ips_context, domain_context, ip_version):
    """
    Get IP matches for a given IP version.

    :param final_ips: List of IP addresses
    :type final_ips: list[str]
    :param vendor_ips_context: Dictionary of vendor IP ranges
    :type vendor_ips_context: dict
    :param domain_context: An instance of DomainProcessingContext
    :type domain_context: DomainProcessingContext
    :param ip_version: IP version (4 or 6)
    :type ip_version: int
    :return: Dictionary of matched IPs for each vendor
    :rtype: dict
    """
    matches = {vendor: set() for vendor in vendor_ips_context}
    for ip in final_ips:
        if not is_ip_version(ip, ip_version):
            continue
        ip_obj = ipaddress.IPv4Address(ip) if ip_version == 4 else ipaddress.IPv6Address(ip)
        match_ip_with_vendors(ip_obj, vendor_ips_context, domain_context, matches)
    return matches


def is_ip_version(ip, ip_version):
    """
    Check if the IP is of the specified IP version.

    :param ip: IP address as a string
    :type ip: str
    :param ip_version: IP version (4 or 6)
    :type ip_version: int
    :return: True if the IP matches the version, False otherwise
    :rtype: bool
    """
    return (ip_version == 4 and "." in ip) or (ip_version == 6 and ":" in ip)


def match_ip_with_vendors(ip_obj, vendor_ips_context, domain_context, matches):
    """
    Match IP object with vendor IP ranges and update matches.

    :param ip_obj: IP address object
    :type ip_obj: ipaddress.IPv4Address or ipaddress.IPv6Address
    :param vendor_ips_context: Dictionary of vendor IP ranges
    :type vendor_ips_context: dict
    :param domain_context: An instance of DomainProcessingContext
    :type domain_context: DomainProcessingContext
    :param matches: Dictionary of matched IPs for each vendor
    :type matches: dict
    :return: None
    """
    for vendor, ips in vendor_ips_context.items():
        for ip_range in ips:
            try:
                if ip_obj in ipaddress.ip_network(ip_range):
                    domain_context.log_info(
                        f"IP {ip_obj} is in range {ip_range} for vendor {vendor}"
                    )
                    matches[vendor].add(str(ip_obj))
            except ValueError as e:
                domain_context.log_info(f"Error processing IP range {ip_range}: {e}")


def merge_matches(matches_ipv4, matches_ipv6, vendor_ips_context):
    """
    Merge IPv4 and IPv6 matches.

    :param matches_ipv4: Dictionary of IPv4 matches
    :type matches_ipv4: dict
    :param matches_ipv6: Dictionary of IPv6 matches
    :type matches_ipv6: dict
    :param vendor_ips_context: Dictionary of vendor IP ranges
    :type vendor_ips_context: dict
    :return: Merged dictionary of matches
    :rtype: dict
    """
    return {
        vendor: list(matches_ipv4[vendor] | matches_ipv6[vendor]) for vendor in vendor_ips_context
    }


def log_and_write(vendor, matched_ips, domain, output_files, domain_context):
    """
    Method: log_and_write

    :param vendor: The vendor name.
    :param matched_ips: A list of matched IPs.
    :param domain: The domain name.
    :param output_files: A dictionary containing output file paths.
    :param domain_context: The domain context instance.
    :return: None
    """

    if matched_ips:
        message = f"{domain} resolved to {vendor} IPs: {matched_ips}"
        file_path = output_files["standard"][vendor]

        # Check if the message already exists in the file
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                if message in file.read():
                    return False

        with open(file_path, "a", encoding="utf-8") as file:
            file.write(message + "\n")

        domain_context.log_info(message)
        return True
    return False


def log_cloud_ips(matches, domain, domain_context):
    """
    Logs cloud IPs for a resolved domain.

    :param matches: Dictionary with provider to IP list mapping
    :param domain: Resolved domain
    :param domain_context: The domain context instance.
    :return: None
    """
    domain_context.log_info(f"{domain} resolved to cloud IPs:")
    for vendor, matched_ips in matches.items():
        if matched_ips:
            domain_context.log_info(f"  {vendor}: {matched_ips}")


def process_domains(domains, domain_context, env_manager):
    """
    Processes a list of domains with retries, checking them against CSP IP ranges.

    :param domains: List of domains to process
    :type domains: list[str]
    :param domain_context: An instance of DomainProcessingContext
    :type domain_context: DomainProcessingContext
    :param env_manager: An instance of EnvironmentManager
    :type env_manager: EnvironmentManager
    :return: None
    """
    for _ in range(env_manager.get_retries() + 1):
        success = perform_csp_checks(domain_context, env_manager, domains)
        if success:
            break
