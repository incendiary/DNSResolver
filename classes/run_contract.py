"""Publish non-actionable DNS observations and the run completion manifest."""

import json
import os
from pathlib import Path

from classes.custom_exceptions import OutputWriteError
from classes.records import Dangling, NsTakeover, Resolution, Unresolved

CONTRACT_VERSION = "1.0"
OBSERVATIONS_FILENAME = "dns-observations-v1.json"
MANIFEST_FILENAME = "run-manifest-v1.json"
TARGETS_FILENAME = "allocator-targets-v1.json"
REPORT_FILENAME = "run-report.md"


def clear_run_documents(output_dir):
    """Remove stale run documents and their temporary files."""
    for filename in (OBSERVATIONS_FILENAME, MANIFEST_FILENAME, REPORT_FILENAME):
        destination = Path(output_dir) / filename
        _remove_output(destination)
        _remove_output(destination.with_suffix(destination.suffix + ".tmp"))


def publish_dns_observations(
    records,
    output_dir,
    provider_failures=None,
    hostnames=None,
):
    """Build the excluded-observation contract from the run's records."""
    grouped = {}

    for record in records:
        if isinstance(record, Resolution):
            if record.wildcard == "WILDCARD":
                kind, reason = "wildcard", "DNS answer matched the zone wildcard probe"
            elif record.wildcard == "WILDCARD_ZONE":
                kind, reason = (
                    "wildcard_zone",
                    "Parent zone answered random-label probes",
                )
            else:
                continue
            _merge_observation(grouped, record.domain, kind, record.ips, [reason])
        elif isinstance(record, Dangling):
            _merge_observation(
                grouped,
                record.origin,
                "dangling_cname",
                [],
                [f"CNAME target did not resolve: {record.target}"],
            )
        elif isinstance(record, NsTakeover):
            _merge_observation(
                grouped,
                record.origin,
                "ns_takeover",
                [],
                [
                    "Name has NS records but no address records"
                    if record.nameserver == "-"
                    else f"Nameserver did not resolve: {record.nameserver}"
                ],
            )
        elif isinstance(record, Unresolved):
            _merge_observation(
                grouped, record.domain, "unresolved", [], [record.reason]
            )

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


def _merge_observation(grouped, hostname, kind, ips, reasons):
    entry = grouped.setdefault((hostname, kind), {"ips": set(), "reasons": set()})
    entry["ips"].update(ip for ip in ips if ip)
    entry["reasons"].update(reason for reason in reasons if reason)


def _write_json_atomic(document, destination, what="run document"):
    def write(handle):
        json.dump(document, handle, indent=2)
        handle.write("\n")

    _write_atomic(write, destination, what)


def _write_text_atomic(text, destination, what="run document"):
    _write_atomic(lambda handle: handle.write(text), destination, what)


def _write_atomic(write, destination, what):
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    _remove_output(destination)
    _remove_output(temporary)
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            write(handle)
        os.replace(temporary, destination)
    except OSError as error:
        raise OutputWriteError(
            f"Unable to publish {what} {destination}: {error}"
        ) from error
    finally:
        _remove_output(temporary)


def _remove_output(path):
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        raise OutputWriteError(f"Unable to remove output {path}: {error}") from error
