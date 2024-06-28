"""
This module provides methods to detect
potential cloud service takeovers by identifying dangling CNAME records.

Functions:
--------
check_dangling_cname(current_domain, nameservers):
    Check if a domain has a dangling CNAME record.
"""

import dns.resolver


def check_dangling_cname(current_domain, nameservers):
    """
    Check if a domain has a dangling CNAME record

    :param current_domain: the domain to check
    :type current_domain: str
    :param nameservers: optional list of nameservers to use for resolution
    :type nameservers: list[str]
    :return: True if the domain has a dangling CNAME record, False otherwise
    :rtype: bool
    """
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers

    try:
        resolver.resolve(current_domain, "A")
        return False  # If resolving the A record succeeds, it's not a dangling CNAME
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        try:
            resolver.resolve(current_domain, "AAAA")
            return False  # If resolving the AAAA record succeeds, it's not a dangling CNAME
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
        ):
            return True  # If both A and AAAA records cannot be resolved, it's a dangling CNAME
