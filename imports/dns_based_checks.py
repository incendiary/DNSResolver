import json
import os
import re
import subprocess
import platform
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

    """
    for category, pattern in patterns.items():
        if re.search(pattern["regex"], domain):
            return category, pattern["recommendation"], pattern["evidence"]
    return "unknown", "Unclassified", "N/A"


def is_dangling_record(resolver, domain, record_type):
    """
    Checks if a specified DNS record for a given domain is a dangling record or not.
    """
    try:
        resolver.resolve(domain, record_type)
        return False
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
    ):
        return True


def perform_nslookup(domain, nameserver, reason, evidence_dir):
    """
    Perform a DNS lookup using the nslookup command and save the output to a file.

    :param domain: The domain name to perform the DNS lookup for.
    :param nameserver: The nameserver to use for the DNS lookup.
    :param reason: The reason for performing the DNS lookup.
    :param evidence_dir: The directory where the output file will be saved.
    :return: None
    """
    try:
        result = subprocess.run(
            ["nslookup", domain, nameserver],
            capture_output=True,
            text=True,
            check=False,
        )
    except subprocess.CalledProcessError as e:
        print(
            f"Command failed with error: {e.returncode}, output: {e.output}, stderr: {e.stderr}"
        )
        raise e from None
    filename = os.path.join(evidence_dir, f"{domain}_{reason}_{nameserver}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(result.stdout)
        f.write("\n")
        f.write(result.stderr)


def perform_dig(domain, nameserver, reason, evidence_dir):
    """
    Perform a DNS lookup using the dig command and save the output to a file.

    :param domain: The domain name to perform the DNS lookup for.
    :param nameserver: The nameserver to use for the DNS lookup.
    :param reason: The reason for performing the DNS lookup.
    :param evidence_dir: The directory where the output file will be saved.
    :return: None
    """
    try:
        result = subprocess.run(
            ["dig", f"@{nameserver}", domain],
            capture_output=True,
            text=True,
            check=False,
        )
    except subprocess.CalledProcessError as e:
        print(
            f"Command failed with error: {e.returncode}, output: {e.output}, stderr: {e.stderr}"
        )
        raise e from None
    filename = os.path.join(evidence_dir, f"{domain}_{reason}_{nameserver}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(result.stdout)
        f.write("\n")
        f.write(result.stderr)


def check_tools_availability():
    """
    Check the availability of nslookup and dig tools in the system path.
    :return: Tuple indicating the availability of nslookup and dig (nslookup_available, dig_available)
    """
    nslookup_available = (
        subprocess.run(["which", "nslookup"], capture_output=True, text=True).returncode
        == 0
    )
    dig_available = (
        subprocess.run(["which", "dig"], capture_output=True, text=True).returncode == 0
    )
    return nslookup_available, dig_available


def perform_dns_lookup(domain, nameserver, reason, evidence_dir):
    """
    Perform a DNS lookup using either nslookup or dig, depending on the system.

    :param domain: The domain name to perform the DNS lookup for.
    :param nameserver: The nameserver to use for the DNS lookup.
    :param reason: The reason for performing the DNS lookup.
    :param evidence_dir: The directory where the output file will be saved.
    :return: None
    """
    nslookup_available, dig_available = check_tools_availability()

    if platform.system() == "Windows":
        if nslookup_available:
            perform_nslookup(domain, nameserver, reason, evidence_dir)
        else:
            log_error(f"nslookup not available on Windows system for domain {domain}")
    else:
        if dig_available:
            perform_dig(domain, nameserver, reason, evidence_dir)
        elif nslookup_available:
            perform_nslookup(domain, nameserver, reason, evidence_dir)
        else:
            log_error(
                f"Neither dig nor nslookup available on non-Windows system for domain {domain}"
            )


def log_error(message):
    """
    Log an error message to the log file.
    :param message: The error message to log.
    :return: None
    """
    with open("error.log", "a", encoding="utf-8") as f:
        f.write(f"{message}\n")


# Example usage of perform_dns_lookup function
def resolve_domain(domain_context, env_manager):
    """
    Resolves domain and returns a success status and the final IP addresses.
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
    Tries to resolve DNS query and implements retry for failures.

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
                    f"Failed to resolve DNS for {current_domain} - "
                    f"retry {retry + 1} of {retries}: {e}"
                )
            elif retry == retries - 1:
                if current_domain not in dangling_domains:
                    failed_domains.add(current_domain)  # Track domain for retry
                    if verbose:
                        logger.info(
                            f"DNS resolution for {current_domain} timed out - Final Timeout: {e}"
                        )
                if evidence_enabled:
                    perform_dns_lookup(
                        current_domain,
                        resolver.nameservers[0],
                        "timeout",
                        output_files["evidence"]["dns"],
                    )
            continue
    return None


def check_dangling_cname(domain_context, env_manager, current_domain):
    """
    Checks if a domain is a dangling CNAME, returning a boolean result.
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
        perform_dns_lookup(
            current_domain,
            resolver.nameservers[0],
            "dangling",
            output_files["evidence"]["dns"],
        )

    return True
