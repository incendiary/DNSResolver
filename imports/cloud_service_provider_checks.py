import functools
import ipaddress


@functools.lru_cache(maxsize=None)
def parse_network(cidr):
    """Parse a CIDR string into an ip_network object, memoised for the run.

    The vendor CIDR lists are fixed for the whole run, so each distinct
    string only needs to be parsed once regardless of how many IPs/domains
    are checked against it.
    """
    return ipaddress.ip_network(cidr)


def perform_csp_checks(domain_context, env_manager, final_ips):
    domain = domain_context.get_domain()
    output_files = env_manager.output_files

    # Run-scoped set of CSP lines already written, to dedupe without
    # re-reading the output file. Owned on env_manager so it persists
    # across the many perform_csp_checks calls (one per domain) in a run.
    if not hasattr(env_manager, "_csp_written_lines"):
        env_manager._csp_written_lines = set()
    written_lines = env_manager._csp_written_lines

    vendor_ips_context_ipv4 = get_vendor_ips(domain_context, ip_version=4)
    vendor_ips_context_ipv6 = get_vendor_ips(domain_context, ip_version=6)

    matches_ipv4 = get_ip_matches(
        final_ips, vendor_ips_context_ipv4, domain_context, ip_version=4
    )
    matches_ipv6 = get_ip_matches(
        final_ips, vendor_ips_context_ipv6, domain_context, ip_version=6
    )

    matches = merge_matches(matches_ipv4, matches_ipv6, vendor_ips_context_ipv4)

    success = False

    for vendor, matched_ips in matches.items():
        if matched_ips:
            success = (
                log_and_write(
                    vendor,
                    matched_ips,
                    domain,
                    output_files,
                    domain_context,
                    written_lines,
                )
                or success
            )
        else:
            domain_context.log_info(f"No cloud IPs were resolved for {vendor}")

    return success


def get_vendor_ips(domain_context, ip_version):
    csp_ip_addresses = domain_context.get_csp_ip_addresses()
    if ip_version == 4:
        return {
            "gcp": csp_ip_addresses.get_gcp_ipv4(),
            "aws": csp_ip_addresses.get_aws_ipv4(),
            "azure": csp_ip_addresses.get_azure_ipv4(),
        }
    if ip_version == 6:
        return {
            "gcp": csp_ip_addresses.get_gcp_ipv6(),
            "aws": csp_ip_addresses.get_aws_ipv6(),
            "azure": csp_ip_addresses.get_azure_ipv6(),
        }
    return {}


def get_ip_matches(final_ips, vendor_ips_context, domain_context, ip_version):
    matches = {vendor: {} for vendor in vendor_ips_context}
    for ip in final_ips:
        if not is_ip_version(ip, ip_version):
            continue
        ip_obj = (
            ipaddress.IPv4Address(ip) if ip_version == 4 else ipaddress.IPv6Address(ip)
        )
        match_ip_with_vendors(ip_obj, vendor_ips_context, domain_context, matches)
    return matches


def is_ip_version(ip, ip_version):
    return (ip_version == 4 and "." in ip) or (ip_version == 6 and ":" in ip)


def match_ip_with_vendors(ip_obj, vendor_ips_context, domain_context, matches):
    for vendor, ips in vendor_ips_context.items():
        for ip_range in ips:
            try:
                network = parse_network(ip_range)
            except ValueError as e:
                domain_context.log_info(f"Error processing IP range {ip_range}: {e}")
                continue
            if ip_obj in network:
                domain_context.log_info(
                    f"IP {ip_obj} is in range {ip_range} for vendor {vendor}"
                )
                # Keep the prefix that matched — it is the key to the region and
                # service the provider published for it.
                matches[vendor][str(ip_obj)] = ip_range


def merge_matches(matches_ipv4, matches_ipv6, vendor_ips_context):
    return {
        vendor: {**matches_ipv4[vendor], **matches_ipv6[vendor]}
        for vendor in vendor_ips_context
    }


def log_and_write(
    vendor, matched_ips, domain, output_files, domain_context, written_lines
):
    """
    Write one line per matched address, as a handoff record for downstream
    tooling: domain|ip|provider|region|service|prefix

    One address per line, pipe-delimited, because this file is consumed by
    another tool rather than read as prose. Region and service come from the
    provider's own published ranges and are what make a match actionable — an
    address is only worth pursuing if you know where it is allocated from and
    what it belongs to.
    """
    csp_ip_addresses = domain_context.get_csp_ip_addresses()
    file_path = output_files["standard"]["csp"]
    wrote_any = False

    for ip, prefix in sorted(matched_ips.items()):
        region, service = csp_ip_addresses.describe(prefix)
        message = f"{domain}|{ip}|{vendor}|{region}|{service}|{prefix}"

        # Deduplicate against an in-memory, run-scoped set of lines already
        # written — avoids re-reading the whole output file on every call.
        if message in written_lines:
            continue

        with open(file_path, "a", encoding="utf-8") as file:
            file.write(message + "\n")
        written_lines.add(message)
        domain_context.log_info(message)
        wrote_any = True

    return wrote_any
