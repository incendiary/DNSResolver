import asyncio
import json
import os
import platform
import re
import subprocess

import aiodns
import aiofiles


async def load_domain_categorisation_patterns(config_file="config.json"):
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


async def is_dangling_record_async(resolver, domain, record_type):
    """
    Asynchronously checks if a specified DNS record for a given domain is a dangling record or not.
    """
    try:
        await resolver.query(domain, record_type)
        return False
    except aiodns.error.DNSError as e:
        if e.args[0] in [3, 4]:  # NXDOMAIN (Domain name not found) or SERVFAIL
            return True
        return False


def check_tools_availability():
    """
    Check the availability of nslookup and dig tools in the system path.
    :return: Tuple indicating the availability of nslookup and dig (nslookup_available, dig_available)
    """
    if platform.system() == "Windows":
        nslookup_available = (
            subprocess.run(
                ["where", "nslookup"], capture_output=True, text=True
            ).returncode
            == 0
        )
        dig_available = (
            subprocess.run(["where", "dig"], capture_output=True, text=True).returncode
            == 0
        )
    else:
        nslookup_available = (
            subprocess.run(
                ["which", "nslookup"], capture_output=True, text=True
            ).returncode
            == 0
        )
        dig_available = (
            subprocess.run(["which", "dig"], capture_output=True, text=True).returncode
            == 0
        )

    return nslookup_available, dig_available


def log_error(message):
    """
    Log an error message to the log file.
    :param message: The error message to log.
    :return: None
    """
    with open("error.log", "a", encoding="utf-8") as f:
        f.write(f"{message}\n")


async def resolve_domain_async(domain_context, env_manager):
    """
    Asynchronously resolves a domain and returns a success status and the final IP addresses.
    """
    resolved_records = []
    current_domain = domain_context.get_domain()
    resolver = aiodns.DNSResolver()
    random_nameserver = env_manager.get_random_nameserver()

    if random_nameserver:
        resolver.nameservers = [random_nameserver]
        env_manager.log_info(
            f"Using nameserver {random_nameserver} for resolving {current_domain}"
        )

    try:
        answers = await resolver.query(current_domain, "A")
        final_ips = [answer.host for answer in answers]
        resolved_records.append(("A", final_ips))

        is_dangling = await check_dangling_cname_async(
            domain_context, env_manager, current_domain
        )
        if is_dangling:
            domain_context.add_dangling_domain_to_domains(current_domain)

        return True, final_ips
    except aiodns.error.DNSError as e:
        if e.args[0] == 4:  # NXDOMAIN (Domain name not found)
            env_manager.log_info(
                f"{current_domain} not found, checking for dangling CNAME."
            )
            is_dangling = await check_dangling_cname_async(
                domain_context, env_manager, current_domain
            )
            if is_dangling:
                domain_context.add_dangling_domain_to_domains(current_domain)
                return True, []
        else:
            env_manager.log_error(f"DNS resolution error for {current_domain}: {e}")
            return False, []


async def save_and_log_dns_result(
    result, domain, nameserver, reason, evidence_dir, env_manager, command_name
):
    stdout, stderr = await result.communicate()
    content = stdout.decode() + "\n" + stderr.decode()
    filename = os.path.join(evidence_dir, f"{domain}_{reason}_{nameserver}.txt")
    await env_manager.write_to_file(filename, content)
    env_manager.log_info(
        f"{command_name} result saved for domain {domain} using nameserver {nameserver}"
    )


async def perform_nslookup(domain, nameserver, reason, evidence_dir, env_manager):
    """
    Perform a DNS lookup using the nslookup command and save the output to a file.
    """
    try:
        result = await asyncio.create_subprocess_exec(
            "nslookup",
            domain,
            nameserver,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await save_and_log_dns_result(
            result, domain, nameserver, reason, evidence_dir, env_manager, "nslookup"
        )
    except Exception as e:
        env_manager.log_error(f"Command failed with error: {e}")
        raise e from None


async def perform_dig(domain, nameserver, reason, evidence_dir, env_manager):
    """
    Perform a DNS lookup using the dig command and save the output to a file.
    """
    try:
        result = await asyncio.create_subprocess_exec(
            "dig",
            f"@{nameserver}",
            domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await save_and_log_dns_result(
            result, domain, nameserver, reason, evidence_dir, env_manager, "dig"
        )
    except Exception as e:
        env_manager.log_error(f"Command failed with error: {e}")
        raise e from None


async def perform_dns_evidence(domain, nameserver, reason, evidence_dir, env_manager):
    """
    Perform a DNS lookup using either nslookup or dig, depending on the system.

    :param domain: The domain name to perform the DNS lookup for.
    :param nameserver: The nameserver to use for the DNS lookup.
    :param reason: The reason for performing the DNS lookup.
    :param evidence_dir: The directory where the output file will be saved.
    :param env_manager: The environment manager instance for logging.
    :return: None
    """
    nslookup_available, dig_available = check_tools_availability()

    if platform.system() == "Windows":
        if nslookup_available:
            await perform_nslookup(
                domain, nameserver, reason, evidence_dir, env_manager
            )
        else:
            env_manager.log_error(
                f"nslookup not available on Windows system for domain {domain}"
            )
    else:
        if dig_available:
            await perform_dig(domain, nameserver, reason, evidence_dir, env_manager)
        elif nslookup_available:
            await perform_nslookup(
                domain, nameserver, reason, evidence_dir, env_manager
            )
        else:
            env_manager.log_error(
                f"Neither dig nor nslookup available on non-Windows system for domain {domain}"
            )


async def perform_dns_checks_async(domain_context, env_manager, final_ips):
    """
    Performs DNS checks and evidence collection if enabled.
    """
    resolver = aiodns.DNSResolver()
    patterns = env_manager.get_patterns()
    current_domain = domain_context.get_domain()
    output_files = env_manager.get_output_files()
    evidence_enabled = env_manager.get_evidence()

    random_nameserver = env_manager.get_random_nameserver()
    if random_nameserver:
        resolver.nameservers = [random_nameserver]
        env_manager.log_info(
            f"Using nameserver {random_nameserver} for DNS checks on {domain_context.get_domain()}"
        )

    if final_ips:
        await env_manager.write_to_file(
            output_files["standard"]["resolved"],
            f"{current_domain}|{'|'.join(final_ips)}",
        )
        env_manager.log_info(f"Resolved IPs for domain {current_domain}: {final_ips}")

    if evidence_enabled:
        for nameserver in env_manager.get_resolvers():
            await perform_dns_evidence(
                current_domain,
                nameserver,
                "dangling",
                output_files["evidence"]["dns"],
                env_manager,
            )

    category, recommendation, evidence_link = categorise_domain(
        current_domain, patterns
    )
    await env_manager.write_to_file(
        output_files["standard"]["dangling"],
        f"{current_domain}|{category}|{recommendation}|{evidence_link}",
    )
    env_manager.log_info(
        f"Categorised domain {current_domain} as {category} with recommendation: {recommendation}"
    )


async def check_dangling_cname_async(domain_context, env_manager, current_domain):
    """
    Asynchronously checks if a domain is a dangling CNAME, returning a boolean result.
    """
    resolver = aiodns.DNSResolver()
    original_domain = domain_context.get_domain()
    output_files = env_manager.get_output_files()
    evidence_enabled = env_manager.get_evidence()

    random_nameserver = env_manager.get_random_nameserver()
    if random_nameserver:
        resolver.nameservers = [random_nameserver]
        env_manager.log_info(
            f"Using nameserver {random_nameserver} for resolving {current_domain}"
        )

    for record_type in ["A", "AAAA", "MX"]:
        if not await is_dangling_record_async(resolver, current_domain, record_type):
            return False

    if not await is_dangling_record_async(resolver, current_domain, "NS"):
        await env_manager.write_to_file(
            output_files["standard"]["ns_takeover"],
            f"{original_domain}|{current_domain}",
        )
        env_manager.log_info(f"NS takeover possible for domain {current_domain}")
        return False

    patterns = env_manager.get_patterns()
    category, recommendation, evidence_link = categorise_domain(
        current_domain, patterns
    )
    await env_manager.write_to_file(
        output_files["standard"]["dangling"],
        f"{original_domain}|{current_domain}|{category}|{recommendation}|{evidence_link}",
    )
    env_manager.log_info(
        f"Domain {current_domain} is a dangling CNAME with category: {category}"
    )

    if evidence_enabled:
        for nameserver in env_manager.get_resolvers():
            await perform_dns_evidence(
                current_domain,
                nameserver,
                "dangling",
                output_files["evidence"]["dns"],
                env_manager,
            )

    return True
