import ipaddress
import os


def perform_csp_checks(domain_context, env_manager, final_ips):
    domain = domain_context.get_domain()
    output_files = env_manager.output_files

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
                log_and_write(vendor, matched_ips, domain, output_files, domain_context)
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
    matches = {vendor: set() for vendor in vendor_ips_context}
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
                if ip_obj in ipaddress.ip_network(ip_range):
                    domain_context.log_info(
                        f"IP {ip_obj} is in range {ip_range} for vendor {vendor}"
                    )
                    matches[vendor].add(str(ip_obj))
            except ValueError as e:
                domain_context.log_info(f"Error processing IP range {ip_range}: {e}")


def merge_matches(matches_ipv4, matches_ipv6, vendor_ips_context):
    return {
        vendor: list(matches_ipv4[vendor] | matches_ipv6[vendor])
        for vendor in vendor_ips_context
    }


def log_and_write(vendor, matched_ips, domain, output_files, domain_context):
    if matched_ips:
        message = f"{domain} resolved to {vendor} IPs: {matched_ips}"
        file_path = output_files["standard"][vendor]

        # Deduplicate: skip write if this exact line already exists
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                if message in file.read():
                    return False

        with open(file_path, "a", encoding="utf-8") as file:
            file.write(message + "\n")

        domain_context.log_info(message)

        return True
    return False
