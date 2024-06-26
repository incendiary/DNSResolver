"""
This module focuses on performing DNS record analyses for given domain names.
It provides functionality to resolve a domain's CNAME chain,
check for dangling CNAMEs, and resolve the
domain's 'A' (IPv4) and 'AAAA' (IPv6) records.

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

from imports.cloud_ip_ranges import is_in_ip_ranges
from imports.dns_based_checks import check_dangling_cname


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
):
    """
    Resolve the given domain and process the results.

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

            # Check if IPs are in cloud ranges
            in_gcp = any(
                is_in_ip_ranges(
                    ip, gcp_ipv4, gcp_ipv6, verbose=verbose, extreme=extreme
                )
                for ip in final_ips
            )
            in_aws = any(
                is_in_ip_ranges(
                    ip, aws_ipv4, aws_ipv6, verbose=verbose, extreme=extreme
                )
                for ip in final_ips
            )
            in_azure = any(
                is_in_ip_ranges(
                    ip, azure_ipv4, azure_ipv6, verbose=verbose, extreme=extreme
                )
                for ip in final_ips
            )

            if in_gcp:
                if verbose or extreme:
                    print(f"Writing GCP resolved IPs for domain: {domain}")
                with open(output_files["gcp"], "a", encoding="utf-8") as f:
                    f.write(f"{domain}: {final_ips}\n")
                if verbose or extreme:
                    print(f"Written GCP records to file: {output_files['gcp']}")
            if in_aws:
                if verbose or extreme:
                    print(f"Writing AWS resolved IPs for domain: {domain}")
                with open(output_files["aws"], "a", encoding="utf-8") as f:
                    f.write(f"{domain}: {final_ips}\n")
                if verbose or extreme:
                    print(f"Written AWS records to file: {output_files['aws']}")
            if in_azure:
                if verbose or extreme:
                    print(f"Writing Azure resolved IPs for domain: {domain}")
                with open(output_files["azure"], "a", encoding="utf-8") as f:
                    f.write(f"{domain}: {final_ips}\n")
                if verbose or extreme:
                    print(f"Written Azure records to file: {output_files['azure']}")

            if verbose or extreme:
                print(f"{domain} resolved to {resolved_records}")
                if in_gcp:
                    print(f"{domain} is in Google Cloud IP ranges.")
                if in_aws:
                    print(f"{domain} is in AWS IP ranges.")
                if in_azure:
                    print(f"{domain} is in Azure IP ranges.")

    except dns.exception.DNSException as e:
        if verbose or extreme:
            print(f"Failed to resolve {domain}: {e}")

    finally:
        pbar.update(1)
