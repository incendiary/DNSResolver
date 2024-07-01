"""
This module provides methods to detect
potential cloud service takeovers by identifying dangling CNAME records.

Functions:
--------
check_dangling_cname(current_domain, nameservers):
    Check if a domain has a dangling CNAME record.
"""

import dns.resolver


def create_resolver(timeout, nameservers):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout  # Set the timeout for the resolver
    resolver.timeout = timeout  # Set the timeout for individual requests
    if nameservers:
        resolver.nameservers = nameservers

    return resolver


def resolve_domain(
    resolver,
    domain,
    nameservers,
    output_files,
    verbose,
):

    resolved_records = []

    try:
        current_domain = domain
        while True:
            cname_chain_resolved = False
            for record_type in ["CNAME"]:
                try:
                    answer = resolver.resolve(current_domain, record_type)
                    resolved_records.append(
                        (record_type, [str(rdata) for rdata in answer])
                    )
                    current_domain = str(answer[0].target)
                    cname_chain_resolved = True
                    # Check if the domain is a dangling cname
                    if check_dangling_cname(
                        current_domain, nameservers, domain, output_files
                    ):
                        # Write the domain to output file
                        with open(
                            output_files["standard"]["dangling"], "a", encoding="utf-8"
                        ) as file:
                            print(
                                f"Writing resolved records for domain: {domain}|{current_domain} to "
                                f"{output_files['standard']['dangling']}"
                            )
                            file.write(f"{domain}|{current_domain}\n")
                    break
                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers,
                    dns.resolver.Timeout,
                ):
                    continue

            if not cname_chain_resolved:
                break

        # Resolve A and AAAA records for the final domain
        final_ips = []
        for record_type in ["A", "AAAA"]:
            try:
                answer = resolver.resolve(current_domain, record_type)
                final_ips.extend([str(rdata) for rdata in answer])
                resolved_records.append((record_type, [str(rdata) for rdata in answer]))
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.resolver.Timeout,
            ):
                continue

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

    except dns.exception.Timeout as e:
        # Handle the timeout exception by writing to the timeout file
        with open(output_files["standard"]["timeout"], "a", encoding="utf-8") as f:
            f.write(f"{domain}\n")
            f.write("--------\n")

        if verbose:
            print(f"DNS resolution for {domain} timed out: {e}")

        return False

    except dns.exception.DNSException as e:
        with open(output_files["standard"]["unresolved"], "a", encoding="utf-8") as f:
            f.write(f"{domain}:\n")
            for record_type, records in resolved_records:
                f.write(f"  {record_type}:\n")
                for record in records:
                    f.write(f"    {record}\n")
            f.write("--------\n")

        if verbose:
            print(f"Failed to resolve {domain}: {e}")

        return False


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
                    return False  # If resolving the NS record succeeds, log, and it's not a dangling CNAME
                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers,
                ):
                    return True  # If A, AAAA, MX, and NS records cannot be resolved, it's a dangling CNAME
