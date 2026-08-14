"""Publish non-actionable DNS observations and the run completion manifest."""

import json
import os
from pathlib import Path

from classes.custom_exceptions import OutputWriteError

CONTRACT_VERSION = "1.0"
OBSERVATIONS_FILENAME = "dns-observations-v1.json"
MANIFEST_FILENAME = "run-manifest-v1.json"
TARGETS_FILENAME = "allocator-targets-v1.json"


def clear_run_documents(output_dir):
    """Remove stale run documents and their temporary files."""
    for filename in (OBSERVATIONS_FILENAME, MANIFEST_FILENAME):
        destination = Path(output_dir) / filename
        _remove_output(destination)
        _remove_output(destination.with_suffix(destination.suffix + ".tmp"))


def publish_dns_observations(
    output_files,
    output_dir,
    provider_failures=None,
    hostnames=None,
):
    """Build the excluded-observation contract from the run's text outputs."""
    grouped = {}
    standard = output_files.get("standard", {})

    for line in _lines(standard.get("resolved")):
        if line.startswith("WILDCARD|"):
            _add_observation(
                grouped,
                line,
                "WILDCARD",
                "wildcard",
                "DNS answer matched the zone wildcard probe",
            )
        elif line.startswith("WILDCARD_ZONE|"):
            _add_observation(
                grouped,
                line,
                "WILDCARD_ZONE",
                "wildcard_zone",
                "Parent zone answered random-label probes",
            )

    for line in _lines(standard.get("takeover")):
        fields = line.split("|")
        if line.startswith("DANGLING|") and len(fields) >= 3:
            _merge_observation(
                grouped,
                fields[1],
                "dangling_cname",
                [],
                [f"CNAME target did not resolve: {fields[2]}"],
            )
        elif line.startswith("NS_TAKEOVER|") and len(fields) >= 3:
            _merge_observation(
                grouped,
                fields[1],
                "ns_takeover",
                [],
                [f"Nameserver did not resolve: {fields[2]}"],
            )
        else:
            raise ValueError("Malformed takeover observation output")

    unresolved_prefix = "DNS resolution error for "
    for line in _lines(standard.get("unresolved")):
        if not line.startswith(unresolved_prefix):
            raise ValueError("Malformed unresolved observation output")
        hostname, separator, reason = line[len(unresolved_prefix) :].partition(": ")
        if not separator or not hostname or not reason:
            raise ValueError("Malformed unresolved observation output")
        _merge_observation(grouped, hostname, "unresolved", [], [reason])

    if provider_failures:
        reasons = [
            f"{provider} provider catalogue unusable: {reason}"
            for provider, reason in sorted(provider_failures.items())
        ]
        for hostname in sorted(set(hostnames or [])):
            _merge_observation(
                grouped,
                hostname,
                "provider_catalog_incomplete",
                [],
                reasons,
            )

    observations = []
    for (hostname, kind), entry in sorted(grouped.items()):
        observations.append(
            {
                "contract_version": CONTRACT_VERSION,
                "hostname": hostname,
                "kind": kind,
                "ips": sorted(entry["ips"]),
                "reasons": sorted(entry["reasons"]),
                "actionability": "excluded",
            }
        )

    _write_json_atomic(observations, Path(output_dir) / OBSERVATIONS_FILENAME)
    return observations


def publish_run_manifest(
    output_dir,
    run_id,
    status,
    started_at,
    completed_at,
    catalogues,
):
    """Publish the final run state after its referenced outputs are settled."""
    if status not in {"complete", "incomplete", "failed"}:
        raise ValueError(f"Unknown run status: {status}")
    if set(catalogues) != {"aws", "gcp", "azure"}:
        raise ValueError("Run manifest requires AWS, GCP, and Azure catalogues")

    manifest = {
        "contract_version": CONTRACT_VERSION,
        "run_id": run_id,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "provider_catalogs": {
            provider: catalogues[provider].manifest_entry()
            for provider in ("aws", "gcp", "azure")
        },
        "outputs": {
            "actionable_targets": TARGETS_FILENAME if status == "complete" else None,
            "observations": OBSERVATIONS_FILENAME,
        },
    }
    _write_json_atomic(manifest, Path(output_dir) / MANIFEST_FILENAME)
    return manifest


def _add_observation(grouped, line, marker, kind, reason):
    fields = line.split("|")
    if len(fields) < 3 or fields[0] != marker or not fields[1]:
        raise ValueError(f"Malformed {kind} observation output")
    _merge_observation(grouped, fields[1], kind, fields[2:], [reason])


def _merge_observation(grouped, hostname, kind, ips, reasons):
    entry = grouped.setdefault((hostname, kind), {"ips": set(), "reasons": set()})
    entry["ips"].update(ip for ip in ips if ip)
    entry["reasons"].update(reason for reason in reasons if reason)


def _lines(path):
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]
    except OSError as error:
        raise ValueError(
            f"Unable to read observation output {path}: {error}"
        ) from error


def _write_json_atomic(document, destination):
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    _remove_output(destination)
    _remove_output(temporary)
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, destination)
    except OSError as error:
        raise OutputWriteError(
            f"Unable to publish run document {destination}: {error}"
        ) from error
    finally:
        _remove_output(temporary)


def _remove_output(path):
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        raise OutputWriteError(f"Unable to remove output {path}: {error}") from error
