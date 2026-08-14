"""Publish the provider-aware allocator target contract from CSP match records."""

import ipaddress
import json
import os
from pathlib import Path

from classes.custom_exceptions import OutputWriteError

CONTRACT_VERSION = "1.0"
SUPPORTED_PROVIDERS = {"aws", "gcp", "azure"}
WILDCARD_PREFIXES = ("WILDCARD|", "WILDCARD_ZONE|")


def publish_allocator_targets(csp_path, output_dir):
    """Write allocator-targets-v1.json atomically and return its records."""
    destination = Path(output_dir) / "allocator-targets-v1.json"
    clear_allocator_targets(output_dir)
    grouped = {}
    for line_number, line in enumerate(_lines(csp_path), start=1):
        if line.startswith(WILDCARD_PREFIXES):
            continue
        target = _parse_target(line, line_number)
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

    temporary = destination.with_suffix(".json.tmp")
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(targets, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, destination)
    except OSError as error:
        raise OutputWriteError(
            f"Unable to publish allocator targets to {destination}: {error}"
        ) from error
    finally:
        _remove_output(temporary)
    return targets


def clear_allocator_targets(output_dir):
    """Remove actionable output and its temporary file before a run starts."""
    destination = Path(output_dir) / "allocator-targets-v1.json"
    _remove_output(destination)
    _remove_output(destination.with_suffix(".json.tmp"))


def _remove_output(path):
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        raise OutputWriteError(f"Unable to remove output {path}: {error}") from error


def _lines(path):
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    yield stripped
    except OSError as exc:
        raise ValueError(f"Unable to read CSP match output: {exc}") from exc


def _parse_target(line, line_number):
    fields = line.split("|")
    if len(fields) != 7 or any(not field for field in fields):
        raise ValueError(f"Malformed CSP match record at line {line_number}")
    hostname, address_text, provider, region, service, prefix_text, border_group = (
        fields
    )
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unknown provider at CSP match line {line_number}")
    try:
        address = ipaddress.ip_address(address_text)
        prefix = ipaddress.ip_network(prefix_text)
    except ValueError as exc:
        raise ValueError(
            f"Invalid address or prefix at CSP match line {line_number}"
        ) from exc
    if address not in prefix:
        raise ValueError(
            f"Address is outside its prefix at CSP match line {line_number}"
        )
    return {
        "contract_version": CONTRACT_VERSION,
        "hostname": hostname,
        "ip": str(address),
        "provider": provider,
        "region": region,
        "services": {service},
        "prefixes": {str(prefix)},
        "network_border_groups": {border_group},
        "dns_record_type": "A" if address.version == 4 else "AAAA",
        "actionability": "actionable",
    }
