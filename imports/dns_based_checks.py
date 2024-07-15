"""
This module provides functions to categorize and resolve DNS domains for security research.

The load_domain_categorisation_patterns function loads domain classification patterns from a given configuration file.

The categorise_domain function categorizes a domain based on provided patterns. If a match is not found, the domain
 will be categorized as "unknown".

The is_dangling_record function checks whether a DNS record of a particular type is dangling or not for a
given domain.

The check_dangling_cname function checks whether a given domain is a dangling CNAME and returns boolean.

The dns_query_with_retry function attempts to resolve a DNS query and includes retry logic for cases when initial
attempts fail, helpful in case of network issues or server failures.

The resolve_domain function completes the DNS resolution for a domain using several parameters.

The create_resolver function creates a DNS resolver object configured with a specified timeout and nameservers.
"""

import json
import os
import re
import subprocess

import dns.resolver


def load_domain_categorisation_patterns(config_file="config.json"):
    """
    Load domain categorization patterns from the given config file.

    :param config_file: The path to the config file. Defaults to "config.json".
    :type config_file: str
    :return: A dictionary of domain categorization patterns.
    :rtype: dict
    """
    with open(config_file, "r", encoding="utf-8") as f:
        config = json.load(f)
    return config.get("domain_categorization", {})


def categorise_domain(domain, patterns):
    """
    Categorizes a domain based on a set of patterns.

    :param domain: The domain to categorize.
    :type domain: str
    :param patterns: A dictionary containing patterns to match against the domain.
                     Should have the following structure:
                     {
                         category1: {
                             "regex": pattern1,
                             "recommendation": recommendation1,
                             "evidence": evidence1
                         },
                         category2: {
                             "regex": pattern2,
                             "recommendation": recommendation2,
                             "evidence": evidence2
                         },
                         ...
                     }
    :type patterns: dict
    :return: A tuple containing the category, recommendation, and evidence for the domain. If no matching
             pattern is found, it returns the default values "unknown", "Unclassified", and "N/A".
    :rtype: tuple
    """
    for category, pattern in patterns.items():
        if re.search(pattern["regex"], domain):
            return category, pattern["recommendation"], pattern["evidence"]
    return "unknown", "Unclassified", "N/A"


def is_dangling_record(resolver, domain, record_type):
    """
    This method `is_dangling_record` is used to determine if a specified record for a given domain is a dangling
    record or not.

    :param resolver: A DNS resolver object used to query DNS information.
    :param domain: The domain for which the record is being checked.
    :param record_type: The type of the record being checked.

    :return: True if the record is a dangling record, False otherwise.

    The method attempts to resolve the specified record for the given domain using the provided DNS resolver.
    If no valid answer is obtained, indicating that the record does not exist or cannot be resolved,
    it is considered as a dangling record and True is returned. If a valid answer is obtained, it means
    the record exists and is not a dangling record, so False is returned.
    """
    try:
        resolver.resolve(domain, record_type)
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return True


def perform_dig(domain, nameserver, reason, evidence_dir):
    """
    Perform a DNS lookup using the dig command and save the output to a file.

    :param domain: The domain name to perform the DNS lookup for.
    :param nameserver: The nameserver to use for the DNS lookup.
    :param reason: The reason for performing the DNS lookup.
    :param evidence_dir: The directory where the output file will be saved.
    :return: None
    """
    result = subprocess.run(
        ["dig", f"@{nameserver}", domain],
        capture_output=True,
        text=True,
    )
    filename = os.path.join(evidence_dir, f"{domain}_{reason}_{nameserver}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(result.stdout)
        f.write("\n")
        f.write(result.stderr)


def resolve_domain(domain_context, env_manager):
    """
    :param domain_context: an instance of DomainContext class containing information about the domain
    :param env_manager: an instance of EnvManager class containing environment settings
    :return: a tuple with two elements - a boolean indicating if domain resolution was successful or not, and a
    list of final IP addresses
    """
    resolved_records = []
    current_domain = domain_context.get_domain()

    verbose = env_manager.get_verbose()
    logger = env_manager.get_logger()
    output_files = env_manager.get_output_files()

    while True:
        cname_chain_resolved = False
        for record_type in ["CNAME"]:
            answer = dns_query_with_retry(
                domain_context, env_manager, current_domain, record_type
            )
            if answer:
                resolved_records.append((record_type, answer))
                current_domain = str(answer[0])
                cname_chain_resolved = True
                if check_dangling_cname(domain_context, env_manager, current_domain):
                    domain_context.add_dangling_domain_to_domains(current_domain)
                break
        if not cname_chain_resolved:
            break

    final_ips = []
    for record_type in ["A", "AAAA"]:
        answer = dns_query_with_retry(
            domain_context, env_manager, current_domain, record_type
        )
        if answer:
            final_ips.extend(answer)
            resolved_records.append((record_type, answer))

    if resolved_records:
        if verbose:
            logger.info(
                f"Writing resolved records for domain: {domain_context.get_domain()} to "
                f"{output_files['standard']['resolved']}"
            )
        with open(
            output_files["standard"]["resolved"],
            "a",
            encoding="utf-8",
        ) as f:
            f.write(f"{domain_context.get_domain()}:\n")
            for record_type, records in resolved_records:
                f.write(f"  {record_type}:\n")
                for record in records:
                    f.write(f"    {record}\n")
            f.write("--------\n")
        return True, final_ips
    return False, []


def dns_query_with_retry(domain_context, env_manager, current_domain, record_type):
    """
    :param domain_context: The DomainContext object that contains the resolver and domain information.
    :param env_manager: The EnvManager object that contains the retry, verbose, logger, output files, and evidence
    settings.
    :param current_domain: The domain to query for DNS records.
    :param record_type: The type of DNS records to query for.

    :return: A list of strings containing the resolved DNS records for the given domain and record type, or
    None if resolution fails after all retries.

    """
    resolver = domain_context.get_resolver()
    retries = env_manager.get_retries()
    verbose = env_manager.get_verbose()
    logger = env_manager.get_logger()
    dangling_domains = domain_context.get_dangling_domains()
    failed_domains = domain_context.get_failed_domains()
    output_files = env_manager.get_output_files()
    evidence_enabled = env_manager.get_evidence()

    for retry in range(retries):
        try:
            answer = resolver.resolve(current_domain, record_type)
            return [str(rdata) for rdata in answer]
        except (
            dns.resolver.Timeout,
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
        ) as e:
            if verbose and retry < retries - 1:
                logger.info(
                    f"Failed to resolve DNS for {current_domain} - retry {retry + 1} of {retries}: {e}"
                )
            elif retry == retries - 1:
                if current_domain not in dangling_domains:
                    failed_domains.add(current_domain)  # Track domain for retry
                    if verbose:
                        logger.info(
                            f"DNS resolution for {current_domain} timed out - Final Timeout: {e}"
                        )
                if evidence_enabled:
                    for nameserver in resolver.nameservers:
                        perform_dig(
                            current_domain,
                            nameserver,
                            "timeout",
                            output_files["evidence"]["dig"],
                        )
            continue
    return None


def check_dangling_cname(domain_context, env_manager, current_domain):
    """
    :param domain_context: Object that contains information about the domain and its context.
    :param env_manager: Object that manages the environment settings.
    :param current_domain: The current domain being checked for dangling CNAME.

    :return: True if the current domain has dangling CNAME records, False otherwise.
    """
    resolver = dns.resolver.Resolver()
    nameservers = domain_context.get_nameservers()
    original_domain = domain_context.get_domain()
    output_files = env_manager.get_output_files()
    patterns = domain_context.get_patterns()
    evidence_enabled = env_manager.get_evidence()

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

    category, recommendation, evidence_link = categorise_domain(
        current_domain, patterns
    )
    with open(output_files["standard"]["dangling"], "a", encoding="utf-8") as file:
        file.write(
            f"{original_domain}|{current_domain}|{category}|{recommendation}|{evidence_link}\n"
        )

    if evidence_enabled:
        for nameserver in resolver.nameservers:
            perform_dig(
                current_domain, nameserver, "dangling", output_files["evidence"]["dig"]
            )

    return True
