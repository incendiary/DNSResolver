"""
This module provides methods to detect
potential cloud service takeovers by identifying dangling CNAME records.

Functions:
--------
check_dangling_cname(current_domain, nameservers):
    Check if a domain has a dangling CNAME record.
"""

import dns.resolver


def check_dangling_cname(current_domain, nameservers, original_domain, output_files):
    """
    Check if a domain has a dangling CNAME record

    :param current_domain: the domain to check
    :type current_domain: str
    :param nameservers: optional list of nameservers to use for resolution
    :type nameservers: list[str]
    :param original_domain: the original domain name
    :type original_domain: str
    :param output_files: Dictionary of output file paths.
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
            try:
                resolver.resolve(current_domain, "MX")
                return False  # If resolving the MX record succeeds, it's not a dangling CNAME
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
            ):
                try:
                    resolver.resolve(current_domain, "NS")
                    with open(
                        output_files["standard"]["ns_takeover"], "a", encoding="utf-8"
                    ) as file:
                        file.write(f"{original_domain}|{current_domain}\n")
                    return False  # If resolving the NS record succeeds, log and it's not a dangling CNAME
                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers,
                ):
                    return True  # If A, AAAA, MX, and NS records cannot be resolved, it's a dangling CNAME
