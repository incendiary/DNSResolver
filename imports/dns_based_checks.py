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
    with open(config_file, "r", encoding="utf-8") as f:
        config = json.load(f)
    return config.get("domain_categorization", {})


def categorise_domain(domain, patterns):
    for category, pattern in patterns.items():
        if re.search(pattern["regex"], domain):
            return category, pattern["recommendation"], pattern["evidence"]
    return "unknown", "Unclassified", "N/A"


def is_dangling_record(resolver, domain, record_type):
    try:
        resolver.resolve(domain, record_type)
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return True


def perform_dig(domain, nameserver, reason, evidence_dir):
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
