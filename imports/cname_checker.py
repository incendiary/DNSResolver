"""
This module provides methods to detect
potential cloud service takeovers by identifying dangling CNAME records.

Functions:
--------
detect_direct_takeovers(dangling_cname_file, output_file):
    Detect potential takeover candidates from a list of dangling CNAME records.

check_dangling_cname(current_domain, nameservers):
    Check if a domain has a dangling CNAME record.
"""

import json
import re

import dns.resolver


def detect_direct_takeovers(dangling_cname_file, output_file):
    """

    :param dangling_cname_file: Path to the file containing the list of dangling CNAME records.
    :param output_file: Path to the output file where potential takeover candidates will be written.
    :return: None

    This method is used to detect potential takeover candidates from a list of dangling
    CNAME records. It reads a configuration file called "config.json" which contains patterns
    for different cloud providers. The method then checks each domain in the dangling_cname_file
    against the patterns and writes potential candidates to the output_file.

    Example usage:

    detect_direct_takeovers("dangling_cname_records.txt", "output.txt")

    """
    with open("config.json", "r", encoding="utf-8") as f:
        patterns = json.load(f)

    patterns = {k: re.compile(v) for k, v in patterns.items()}

    with open(dangling_cname_file, "r", encoding="utf-8") as infile, open(
        output_file, "a", encoding="utf-8"
    ) as outfile:
        for line in infile:
            domain = line.strip()
            for cloud_provider, pattern in patterns.items():
                if pattern.search(domain):
                    outfile.write(
                        f"Potential {cloud_provider.upper()} takeover candidate: {domain}\n"
                    )
                    print(
                        f"Potential {cloud_provider.upper()} takeover candidate: {domain}"
                    )


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
