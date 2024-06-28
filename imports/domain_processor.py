"""This module focuses on performing DNS record analyses for given domain
names. It provides functionality to resolve a domain's CNAME chain, check for
dangling CNAMEs, and resolve the domain's 'A' (IPv4) and 'AAAA' (IPv6) records.

The main function in the module, `process_domain`, also verifies if the
resolved IPs are within IP ranges of certain cloud platforms, specifically
 Google Cloud Platform, Amazon Web Service, and Microsoft Azure.

Functions defined in the `cloud_ip_ranges` and `cname_checker` modules are
used to support these operations.

In brief, this module is intended to provide a thorough DNS resolution process
and relation check with known cloud platforms, aiding in identifying potential
security pitfalls like dangling DNS records.

The results of these operations are written to specified output files and can
optionally be printed to the console in verbose scenarios.
"""

import dns.resolver

from imports.cloud_csp_checks import perform_csp_checks
from imports.dns_based_checks import check_dangling_cname
from imports.service_connectivity_checks import perform_service_connectivity_checks


def process_domain(
    domain,
    nameservers,
    output_files,
    pbar,
    verbose,
    extreme,
    gcp_ipv4,
    gcp_ipv6,
    aws_ipv4,
    aws_ipv6,
    azure_ipv4,
    azure_ipv6,
    perform_service_checks,
):
    """Resolve the given domain and process the results.

    :param domain: The domain to process.
    :param nameservers: The list of nameservers to use for resolving.
    :param output_files: A dictionary containing output file paths.
    :param pbar: An instance of ProgressBar to track progress.
    :param verbose: Whether to print verbose output.
    :param extreme: Whether to print extreme output.
    :param gcp_ipv4: The list of Google Cloud Platform IPv4 ranges.
    :param gcp_ipv6: The list of Google Cloud Platform IPv6 ranges.
    :param aws_ipv4: The list of Amazon Web Services IPv4 ranges.
    :param aws_ipv6: The list of Amazon Web Services IPv6 ranges.
    :param azure_ipv4: The list of Microsoft Azure IPv4 ranges.
    :param azure_ipv6: The list of Microsoft Azure IPv6 ranges.
    :return: None
    """
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers

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
                    if check_dangling_cname(current_domain, nameservers):
                        # Write the domain to output file
                        with open(
                            output_files["dangling"], "a", encoding="utf-8"
                        ) as file:
                            file.write(f"{current_domain}\n")
                            file.write("--------\n")
                    break
                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers,
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
            ):
                continue

        if resolved_records:
            if verbose or extreme:
                print(f"Writing resolved records for domain: {domain}")

            if verbose:
                print(output_files["resolved"])

            with open(output_files["resolved"], "a", encoding="utf-8") as f:
                f.write(f"{domain}:\n")
                for record_type, records in resolved_records:
                    f.write(f"  {record_type}:\n")
                    for record in records:
                        f.write(f"    {record}\n")
                f.write("--------\n")
                if verbose or extreme:
                    print(
                        f"Written resolved records to file: {output_files['resolved']}"
                    )

            perform_csp_checks(
                domain,
                output_files,
                final_ips,
                gcp_ipv4,
                gcp_ipv6,
                aws_ipv4,
                aws_ipv6,
                azure_ipv4,
                azure_ipv6,
                verbose,
                extreme,
            )

            if perform_service_checks:
                perform_service_connectivity_checks(
                    domain, output_files, verbose, extreme
                )

    except dns.exception.DNSException as e:

        with open(output_files["unresolved"], "a", encoding="utf-8") as f:
            f.write(f"{domain}:\n")
            for record_type, records in resolved_records:
                f.write(f"  {record_type}:\n")
                for record in records:
                    f.write(f"    {record}\n")
            f.write("--------\n")

        if verbose or extreme:
            print(f"Failed to resolve {domain}: {e}")

    finally:
        pbar.update(1)
