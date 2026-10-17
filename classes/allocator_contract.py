"""Publish the provider-aware allocator target contract from CSP match records."""

import ipaddress
from pathlib import Path

from classes.records import CspMatch
from classes.run_contract import CONTRACT_VERSION, _remove_output, _write_json_atomic

SUPPORTED_PROVIDERS = {"aws", "gcp", "azure"}


def publish_allocator_targets(records, output_dir):
    """Write allocator-targets-v1.json atomically and return its records."""
    destination = Path(output_dir) / "allocator-targets-v1.json"
    clear_allocator_targets(output_dir)
    grouped = {}
    for match in records:
        # Wildcard matches are the hosting platform's own addresses, not targets.
        if not isinstance(match, CspMatch) or match.wildcard:
            continue
        target = _target(match)
        identity = (
            target["provider"],
            target["hostname"],
            target["ip"],
            target["region"],
        )
        if identity not in grouped:
            grouped[identity] = target
            continue
        for field in ("services", "prefixes", "network_border_groups"):
            grouped[identity][field].update(target[field])

    targets = []
    for target in grouped.values():
        targets.append(
            {
                **target,
                "services": sorted(target["services"]),
                "prefixes": sorted(target["prefixes"]),
                "network_border_groups": sorted(target["network_border_groups"]),
            }
        )
    targets.sort(
        key=lambda item: (
            item["provider"],
            item["hostname"],
            item["ip"],
            item["region"],
        )
    )

    _write_json_atomic(targets, destination, what="allocator targets to")
    return targets


def clear_allocator_targets(output_dir):
    """Remove actionable output and its temporary file before a run starts."""
    destination = Path(output_dir) / "allocator-targets-v1.json"
    _remove_output(destination)
    _remove_output(destination.with_suffix(".json.tmp"))


def _target(match):
    """Validate one match against the contract and shape it as a target."""
    where = f"CSP match {match.domain}|{match.ip}"
    required = (match.domain, match.region, match.service, match.prefix)
    if not all(required) or not match.border_group:
        raise ValueError(f"Empty field in {where}")
    if match.provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unknown provider at {where}")
    try:
        address = ipaddress.ip_address(match.ip)
        prefix = ipaddress.ip_network(match.prefix)
    except ValueError as exc:
        raise ValueError(f"Invalid address or prefix at {where}") from exc
    if address not in prefix:
        raise ValueError(f"Address is outside its prefix at {where}")
    return {
        "contract_version": CONTRACT_VERSION,
        "hostname": match.domain,
        "ip": str(address),
        "provider": match.provider,
        "region": match.region,
        "services": {match.service},
        "prefixes": {str(prefix)},
        "network_border_groups": {match.border_group},
        "dns_record_type": "A" if address.version == 4 else "AAAA",
        "actionability": "actionable",
    }
