"""
This module provides methods to detect
potential cloud service takeovers by identifying dangling CNAME records.
Functions:
--------
check_dangling_cname(current_domain, nameservers):
    Check if a domain has a dangling CNAME record.
"""

import json
import re

import dns.resolver


def load_domain_categorisation_patterns(config_file="config.json"):
    """
    Load domain categorisation regex patterns and metadata from a JSON config file.
    """
    with open(config_file, "r", encoding="utf-8") as f:
        config = json.load(f)
    return config.get("domain_categorization", {})


def categorise_domain(domain, patterns):
    """
    Categorise the given domain based on the provided regex patterns.

    :param domain: The domain to categorise.
    :param patterns: A dictionary of category names and their corresponding regex patterns and metadata.
    :return: The category name, recommendation, and evidence if a match is found, otherwise 'unknown'.
    """
    for category, data in patterns.items():
        if re.search(data["pattern"], domain):
            return category, data["recommendation"], data["evidence"]
    return "unknown", "No recommendation", "No evidence"


def is_dangling_record(resolver, domain, record_type):
    """
    Check if a specific DNS record type is dangling.
    :param resolver: Resolver object
    :param domain: Domain to check
    :param record_type: DNS record type
    :return: True if the record is dangling, False otherwise
    """
    try:
        resolver.resolve(domain, record_type)
        return False
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
    ):
        return True


def check_dangling_cname(
    current_domain, nameservers, original_domain, output_files, patterns
):
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers

    for record_type in ["A", "AAAA", "MX"]:
        if not is_dangling_record(resolver, current_domain, record_type):
            return False

    if not is_dangling_record(resolver, current_domain, "NS"):
        with open(
            output_files["standard"]["ns_takeover"], "a", encoding="utf-8"
        ) as file:
            file.write(f"{original_domain}|{current_domain}\n")
        return False

    category, recommendation, evidence = categorise_domain(current_domain, patterns)

    with open(output_files["standard"]["dangling"], "a", encoding="utf-8") as file:
        file.write(
            f"{original_domain}|{current_domain}|{category}|{recommendation}|{evidence}\n"
        )

    return True


def dns_query_with_retry(resolver, domain, record_type, retries, output_files, verbose):
    for retry in range(retries):
        try:
            answer = resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answer]
        except (
            dns.resolver.Timeout,
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
        ) as e:
            if verbose and retry < retries - 1:
                print(
                    f"Failed to resolve DNS for {domain} - retry {retry+1} of {retries}: {e}"
                )
            elif retry == retries - 1:
                with open(
                    output_files["standard"]["timeout"], "a", encoding="utf-8"
                ) as f:
                    f.write(f"{domain}\n")
                    f.write("--------\n")
                    if verbose:
                        print(
                            f"DNS resolution for {domain} timed out - Final Timeout: {e}"
                        )
            continue
    return None


def create_resolver(timeout, nameservers):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


def resolve_domain(
    resolver, domain, nameservers, output_files, verbose, retries, patterns
):
    resolved_records = []
    current_domain = domain
    while True:
        cname_chain_resolved = False
        for record_type in ["CNAME"]:
            answer = dns_query_with_retry(
                resolver, current_domain, record_type, retries, output_files, verbose
            )
            if answer:
                resolved_records.append((record_type, answer))
                current_domain = str(answer[0])
                cname_chain_resolved = True
                if check_dangling_cname(
                    current_domain, nameservers, domain, output_files
                ):
                    with open(
                        output_files["standard"]["dangling"], "a", encoding="utf-8"
                    ) as file:
                        category = categorise_domain(current_domain, patterns)
                        file.write(f"{domain}|{current_domain}|{category}\n")

                break
        if not cname_chain_resolved:
            break

    final_ips = []
    for record_type in ["A", "AAAA"]:
        answer = dns_query_with_retry(
            resolver, current_domain, record_type, retries, output_files, verbose
        )
        if answer:
            final_ips.extend(answer)
            resolved_records.append((record_type, answer))

    if resolved_records:
        if verbose:
            print(
                f"Writing resolved records for domain: {domain} to {output_files['standard']['resolved']}"
            )
        with open(output_files["standard"]["resolved"], "a", encoding="utf-8") as f:
            f.write(f"{domain}:\n")
            for record_type, records in resolved_records:
                f.write(f"  {record_type}:\n")
                for record in records:
                    f.write(f"    {record}\n")
            f.write("--------\n")
        return True, final_ips
    return False, []
