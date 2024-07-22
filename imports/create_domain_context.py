"""
Module: domain_context
----------------------

This module provides functionality for creating and initializing the domain context
used in DNS resolution and domain analysis workflows.

Classes:
    - DomainProcessingContext

Functions:
    - create_domain_context: Initializes a DomainProcessingContext instance for a given domain.
"""

from classes.domain_processing_context import DomainProcessingContext


def create_domain_context(
    domain, env_manager, dangling_domains, failed_domains, csp_ip_addresses
):
    """
    Initializes a DomainProcessingContext instance for a given domain.

    Args:
        domain (str): The domain name to be processed.
        env_manager (EnvironmentManager): The environment manager instance.
        dangling_domains (set): Set to store dangling domains.
        failed_domains (set): Set to store failed domains.
        csp_ip_addresses (CSPIPAddresses): Instance containing CSP IP ranges.

    Returns:
        DomainProcessingContext: Initialized context for the given domain.
    """
    domain_context = DomainProcessingContext(env_manager, csp_ip_addresses)
    domain_context.set_domain(domain)
    domain_context.dangling_domains = dangling_domains
    domain_context.failed_domains = failed_domains
    return domain_context
