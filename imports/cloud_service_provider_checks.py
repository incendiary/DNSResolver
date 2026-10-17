import functools
import ipaddress

from classes.custom_exceptions import OutputWriteError
from classes.records import CspMatch


@functools.lru_cache(maxsize=None)
def parse_network(cidr):
    """Parse a CIDR string into an ip_network object, memoised for the run.

    The vendor CIDR lists are fixed for the whole run, so each distinct
    string only needs to be parsed once regardless of how many IPs/domains
    are checked against it.
    """
    return ipaddress.ip_network(cidr)


# The catalogues are fixed for a run, so a match depends only on (address,
# family). One slot, held by identity: a different catalogues object (the next
# run, or the next test) starts a fresh memo, and holding the reference stops
# its id being reused while the memo is live.
_memo_slot = (None, {})


def _match_memo(catalogues):
    global _memo_slot
    if _memo_slot[0] is not catalogues:
        _memo_slot = (catalogues, {})
    return _memo_slot[1]


def perform_csp_checks(domain_context, env_manager, final_ips, wildcard_verdict=None):
    domain = domain_context.get_domain()
    output_files = env_manager.output_files

    # Run-scoped set of CSP records already written, to dedupe without
    # re-reading the output file. Owned on env_manager so it persists
    # across the many perform_csp_checks calls (one per domain) in a run.
    written = env_manager._csp_written

    vendor_ips_context_ipv4 = get_vendor_ips(domain_context, ip_version=4)
    vendor_ips_context_ipv6 = get_vendor_ips(domain_context, ip_version=6)

    memo = _match_memo(domain_context.get_catalogues())
    matches_ipv4 = get_ip_matches(
        final_ips, vendor_ips_context_ipv4, domain_context, ip_version=4, memo=memo
    )
    matches_ipv6 = get_ip_matches(
        final_ips, vendor_ips_context_ipv6, domain_context, ip_version=6, memo=memo
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
                    written,
                    env_manager.records,
                    wildcard_verdict,
                )
                or success
            )
        else:
            domain_context.log_info(f"No cloud IPs were resolved for {vendor}")

    return success


def get_vendor_ips(domain_context, ip_version):
    catalogues = domain_context.get_catalogues()
    if ip_version == 4:
        return {name: c.ipv4_ranges for name, c in catalogues.items()}
    if ip_version == 6:
        return {name: c.ipv6_ranges for name, c in catalogues.items()}
    return {}


def describe(catalogues, provider, cidr):
    """
    Every region, service and network border group for a provider prefix.

    Unpublished fields read 'unknown' rather than being inferred — only AWS
    publishes a border group, and not every prefix carries a region.
    """
    entries = catalogues[provider].metadata.get(cidr)
    return entries or [("unknown", "unknown", "unknown")]


def get_ip_matches(
    final_ips, vendor_ips_context, domain_context, ip_version, memo=None
):
    """Match each address of one family; `memo` (from perform_csp_checks) caches per address."""
    matches = {vendor: {} for vendor in vendor_ips_context}
    for ip in final_ips:
        if not is_ip_version(ip, ip_version):
            continue
        key = (ip, ip_version)
        if memo is not None and key in memo:
            found = memo[key]
        else:
            ip_obj = (
                ipaddress.IPv4Address(ip)
                if ip_version == 4
                else ipaddress.IPv6Address(ip)
            )
            found = {vendor: {} for vendor in vendor_ips_context}
            match_ip_with_vendors(ip_obj, vendor_ips_context, domain_context, found)
            if memo is not None:
                memo[key] = found
        for vendor, by_address in found.items():
            for address, prefixes in by_address.items():
                matches[vendor].setdefault(address, set()).update(prefixes)
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
                matches[vendor].setdefault(str(ip_obj), set()).add(ip_range)


def merge_matches(matches_ipv4, matches_ipv6, vendor_ips_context):
    merged = {vendor: {} for vendor in vendor_ips_context}
    for vendor in vendor_ips_context:
        for family_matches in (matches_ipv4[vendor], matches_ipv6[vendor]):
            for address, prefixes in family_matches.items():
                merged[vendor].setdefault(address, set()).update(prefixes)
    return merged


def log_and_write(
    vendor,
    matched_ips,
    domain,
    output_files,
    domain_context,
    written,
    records,
    wildcard_verdict=None,
):
    """
    Write one line per published attribution, as a handoff record for downstream
    tooling:

        domain|ip|provider|region|service|prefix|border_group

    Each line is pipe-delimited because this file is consumed by another tool
    rather than read as prose. One address can produce several lines when it
    matches overlapping prefixes or a prefix has several published attributions.
    Region, service and border group
    come from the provider's own published ranges and are what make a match
    actionable — an address is only worth pursuing if you know where it is
    allocated from and what it belongs to.

    Records from a zone that answers for anything are prefixed with the verdict
    — `WILDCARD|` for a confirmed catch-all, `WILDCARD_ZONE|` where the zone is
    wildcarded but these addresses were not among those sampled. In both cases
    the address cannot be attributed to this domain rather than to the platform,
    so neither is a dependable target; without the marker a single wildcarded
    zone emits one record per enumerated subdomain and buries real findings.
    """
    catalogues = domain_context.get_catalogues()
    file_path = output_files["standard"]["csp"]
    wrote_any = False

    for ip, prefixes in sorted(matched_ips.items()):
        for prefix in sorted(prefixes):
            for region, service, border_group in sorted(
                describe(catalogues, vendor, prefix)
            ):
                match = CspMatch(
                    domain,
                    ip,
                    vendor,
                    region,
                    service,
                    prefix,
                    border_group,
                    wildcard_verdict or "",
                )

                # Deduplicate against an in-memory, run-scoped set of records already
                # written — avoids re-reading the whole output file on every call.
                if match in written:
                    continue

                try:
                    with open(file_path, "a", encoding="utf-8") as file:
                        file.write(match.pipe() + "\n")
                except OSError as error:
                    raise OutputWriteError(
                        f"Failed to write CSP attribution to {file_path}: {error}"
                    ) from error
                written.add(match)
                records.append(match)
                domain_context.log_info(match.pipe())
                wrote_any = True

    return wrote_any
