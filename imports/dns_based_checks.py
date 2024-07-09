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

import os
import re
import json
import subprocess

import dns.resolver
from imports.environment import setup_logger

logger = setup_logger()


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
    filename = os.path.join(evidence_dir, f"{domain}_{reason}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(result.stdout)
        f.write("\n")
        f.write(result.stderr)


def check_dangling_cname(
    current_domain,
    nameservers,
    original_domain,
    output_files,
    patterns,
    evidence_enabled,
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

    category, recommendation, evidence_link = categorise_domain(
        current_domain, patterns
    )
    with open(output_files["standard"]["dangling"], "a", encoding="utf-8") as file:
        file.write(
            f"{original_domain}|{current_domain}|{category}|{recommendation}|{evidence_link}\n"
        )

    if evidence_enabled:
        perform_dig(
            current_domain,
            resolver.nameservers[0],
            "dangling",
            output_files["evidence"]["dig"],
        )

    return True


def dns_query_with_retry(
    resolver,
    domain,
    record_type,
    retries,
    verbose,
    dangling_domains,
    failed_domains,
    output_files,
    evidence_enabled,
):
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
                logger.info(
                    f"Failed to resolve DNS for {domain} - retry {retry + 1} of {retries}: {e}"
                )
            elif retry == retries - 1:
                if domain not in dangling_domains:
                    failed_domains.add(domain)  # Track domain for retry
                    if verbose:
                        logger.info(
                            f"DNS resolution for {domain} timed out - Final Timeout: {e}"
                        )
                if evidence_enabled:
                    perform_dig(
                        domain,
                        resolver.nameservers[0],
                        "timeout",
                        output_files["evidence"]["dig"],
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
    evidence_enabled,
):
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
                output_files,
                evidence_enabled,
            )
            if answer:
                resolved_records.append((record_type, answer))
                current_domain = str(answer[0])
                cname_chain_resolved = True
                if check_dangling_cname(
                    current_domain,
                    nameservers,
                    domain,
                    output_files,
                    patterns,
                    evidence_enabled,
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
            output_files,
            evidence_enabled,
        )
        if answer:
            final_ips.extend(answer)
            resolved_records.append((record_type, answer))

    if resolved_records:
        if verbose:
            logger.info(
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
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    if nameservers:
        resolver.nameservers = nameservers
    return resolver
