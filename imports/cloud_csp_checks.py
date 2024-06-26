import ipaddress


# Function to check if an IP address is within given IP ranges
def is_in_ip_ranges(ip_address, ipv4_ranges, ipv6_ranges, verbose=False, extreme=False):
    """
    Checks if the given IP address is within any of the specified IP ranges.

    :param ip_address: The IP address to check.
    :param ipv4_ranges: List of IPv4 ranges to check against.
    :param ipv6_ranges: List of IPv6 ranges to check against.
    :param verbose: (optional) If True, prints additional information about the search.
    Defaults to False.
    :param extreme: (optional) If True, prints additional information about invalid IP
    addresses. Defaults to False.
    :return: True if the IP address is within any of the ranges, False otherwise.

    """

    def check_ranges(ip, range_set, verbose=False, extreme=False):
        for cidr in range_set:
            if ip in ipaddress.ip_network(cidr):
                if verbose:
                    print(f"{ip} found in {cidr}")
                return True
            if extreme:
                print(f"{ip} not found in {cidr}")
        return False

    try:
        ip = ipaddress.ip_address(ip_address)
        range_sets = (
            (ipv4_ranges, ipv6_ranges)
            if ip.version == 4
            else (ipv6_ranges, ipv4_ranges)
        )
        for range_set in range_sets:
            if check_ranges(ip, range_set, verbose, extreme):
                return True
        if verbose:
            print(f"{ip} not found in any range")
        return False
    except ValueError:
        if verbose or extreme:
            print(f"Invalid IP: {ip_address}")
        return False


def check_ip_ranges(ip_ranges, final_ips, verbose, extreme):
    return any(
        is_in_ip_ranges(ip, *ip_ranges, verbose=verbose, extreme=extreme)
        for ip in final_ips
    )


def write_to_files(condition, domain, output_file, final_ips, verbose, extreme):
    if condition:
        if verbose or extreme:
            print(f"Writing resolved IPs for domain: {domain}")
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(f"{domain}: {final_ips}\n")
        if verbose or extreme:
            print(f"Written records to file: {output_file}")


def perform_csp_checks(
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
):
    in_gcp = check_ip_ranges((gcp_ipv4, gcp_ipv6), final_ips, verbose, extreme)
    in_aws = check_ip_ranges((aws_ipv4, aws_ipv6), final_ips, verbose, extreme)
    in_azure = check_ip_ranges((azure_ipv4, azure_ipv6), final_ips, verbose, extreme)

    # Write to files
    write_to_files(in_gcp, domain, output_files["gcp"], final_ips, verbose, extreme)
    write_to_files(in_aws, domain, output_files["aws"], final_ips, verbose, extreme)
    write_to_files(in_azure, domain, output_files["azure"], final_ips, verbose, extreme)

    # Further output
    if verbose or extreme:

        if in_gcp:
            print(f"{domain} is in Google Cloud IP ranges.")
        if in_aws:
            print(f"{domain} is in AWS IP ranges.")
        if in_azure:
            print(f"{domain} is in Azure IP ranges.")
