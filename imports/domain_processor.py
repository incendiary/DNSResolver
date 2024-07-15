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
from imports.dns_based_checks import resolve_domain
from imports.service_connectivity_checks import perform_service_connectivity_checks


def process_domain(domain_context, env_manager, pbar):
    domain_context.create_resolver()

    domain = domain_context.get_domain()
    env_manager.get_logger().info(f"Processing domain: {domain}")

    success, final_ips = resolve_domain(domain_context, env_manager)

    if success:
        perform_csp_checks(domain_context, env_manager, final_ips)

        if env_manager.get_service_checks():
            perform_service_connectivity_checks(domain_context, env_manager)

    pbar.update(1)
    env_manager.get_logger().info(f"Finished processing domain: {domain}")
