"""
This module provides functions related to DNS resolution,
CSP checks, and service connectivity checks for domains.

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
from imports.create_domain_context import create_domain_context
from imports.dns_based_checks import resolve_domain_async
from imports.service_connectivity_checks import \
    perform_service_connectivity_checks


async def process_domain_async(domain, env_manager, pbar, csp_ip_addresses):
    domain_context = create_domain_context(
        domain, env_manager, set(), set(), csp_ip_addresses
    )
    domain_context.create_resolver()

    env_manager.log_info(f"Processing domain: {domain}")

    success, final_ips = await resolve_domain_async(domain_context, env_manager)

    env_manager.log_info(
        f"Processing domain: {domain} was {'successful' if success else 'unsuccessful'}"
    )

    if success:
        perform_csp_checks(domain_context, env_manager, final_ips)
        env_manager.log_info(f"Performing CSP Checks for: {domain} and {final_ips}")
        if env_manager.get_service_checks():
            env_manager.log_info(
                f"Performing Service Connectivity Checks for: {domain} and {final_ips}"
            )
            perform_service_connectivity_checks(domain_context, env_manager)

    pbar.update(1)
    domain_context.log_info(
        f"Finished processing domain: {domain_context.get_domain()}"
    )

    return success, final_ips
