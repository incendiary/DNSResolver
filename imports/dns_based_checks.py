"""
This module provides functions to categorize and resolve DNS domains for security research.

The `load_domain_categorisation_patterns` function loads domain classification patterns from a given configuration file.

The `categorise_domain` function categorizes a domain based on provided patterns. If a match is not found, the domain will be categorized as "unknown".

The `is_dangling_record` function checks whether a DNS record of a particular type is dangling or not for a given domain.

The `check_dangling_cname` function checks whether a given domain is a dangling CNAME and returns boolean.

The `dns_query_with_retry` function attempts to resolve a DNS query and includes retry logic for cases when initial attempts fail, helpful in case of network issues or server failures.

The `resolve_domain` function completes the DNS resolution for a domain using several parameters.

The `create_resolver` function creates a DNS resolver object configured with a specified timeout and nameservers.
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
    :param resolver: The DNS resolver object used to perform the DNS resolution.
    :param domain: The domain name for which to check the record.
    :param record_type: The type of DNS record to check (e.g., 'A', 'CNAME', 'MX', etc.).
    :return: A boolean value indicating whether the record is dangling or not.

    This method checks if a given DNS record of the specified type is dangling for the given domain.
    A dangling record is a record that does not have a valid answer, does not exist (NXDOMAIN),
    does not have any nameservers, or times out during resolution.

    Examples:
        >>> resolver = dns.resolver.Resolver()
        >>> is_dangling_record(resolver, 'example.com', 'A')
        Checking A record for example.com
        Record A for example.com is not dangling
        False

        >>> is_dangling_record(resolver, 'example.com', 'AAAA')
        Checking AAAA record for example.com
        Record AAAA for example.com is dangling
        True
    """
    try:
        print(f"Checking {record_type} record for {domain}")
        resolver.resolve(domain, record_type)
        print(f"Record {record_type} for {domain} is not dangling")
        return False
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        print(f"Record {record_type} for {domain} is dangling")
        return True


def check_dangling_cname(current_domain, nameservers, original_domain, output_files, patterns):
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
        file.write(f"{original_domain}|{current_domain}|{category}|{recommendation}|{evidence}\n")

    return True


def dns_query_with_retry(
    resolver,
    domain,
    record_type,
    retries,
    verbose,
    dangling_domains,
    failed_domains,
):
    """

    This method `dns_query_with_retry` attempts to resolve a DNS query with retry logic. It takes the following parameters:

    :param resolver: The DNS resolver object used to make the query.
    :param domain: The domain to query for.
    :param record_type: The type of DNS record to query for.
    :param retries: The maximum number of retries to attempt.
    :param verbose: A boolean flag indicating whether to print verbose output.
    :param dangling_domains: A set to store domain names that have failed temporarily.
    :param failed_domains: A set to store domain names that have permanently failed.

    :return: A list of strings representing the resolved IP addresses, or None if resolution failed.

    """
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
                    f"Failed to resolve DNS for {domain} - retry {retry + 1} of {retries}: {e}"
                )
            elif retry == retries - 1:
                if domain not in dangling_domains:
                    failed_domains.add(domain)  # Track domain for retry
                    if verbose:
                        print(
                            f"DNS resolution for {domain} timed out - Final Timeout: {e}"
                        )
            continue
    return None


def resolve_domain(
    resolver,
    domain,
    nameservers,
    output_files,
    verbose,
    retries,
    patterns,
    dangling_domains,
    failed_domains,
):
    """
    Resolve a domain using the given parameters.

    :param resolver: The DNS resolver object.
    :param domain: The domain to resolve.
    :param nameservers: The list of nameservers to use for the resolution.
    :param output_files: The dictionary containing output file paths.
    :param verbose: True if verbose output is enabled; False otherwise.
    :param retries: The number of retries for DNS queries.
    :param patterns: The list of patterns to match for dangling CNAMEs.
    :param dangling_domains: The set to store dangling domains.
    :param failed_domains: The set to store failed domains.
    :return: A tuple containing a boolean indicating if the resolution was successful and a list of resolved IP addresses.
    """
    resolved_records = []
    current_domain = domain
    while True:
        cname_chain_resolved = False
        for record_type in ["CNAME"]:
            answer = dns_query_with_retry(
                resolver,
                current_domain,
                record_type,
                retries,
                verbose,
                dangling_domains,
                failed_domains,
            )
            if answer:
                resolved_records.append((record_type, answer))
                current_domain = str(answer[0])
                cname_chain_resolved = True
                if check_dangling_cname(
                    current_domain, nameservers, domain, output_files, patterns
                ):
                    dangling_domains.add(current_domain)
                break
        if not cname_chain_resolved:
            break

    final_ips = []
    for record_type in ["A", "AAAA"]:
        answer = dns_query_with_retry(
            resolver,
            current_domain,
            record_type,
            retries,
            verbose,
            dangling_domains,
            failed_domains,
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


def create_resolver(timeout, nameservers):
    """
    :param timeout: The timeout value for DNS resolution in seconds.
    :param nameservers: A list of IP addresses of the DNS servers to be used for resolution. If not provided, the default system DNS servers will be used.
    :return: A DNS resolver object configured with the specified timeout and nameservers.

    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    if nameservers:
        resolver.nameservers = nameservers
    return resolver
