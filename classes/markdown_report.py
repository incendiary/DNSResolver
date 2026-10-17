"""Render the published run documents as a compact Markdown view.

The JSON documents stay canonical; this view is never parsed back and holds
nothing that is not in them.
"""

MAX_HOSTNAMES = 20


def render(targets, observations, manifest):
    """Return run-report.md text from the three published documents."""
    status = manifest["status"]
    usable = status == "complete"
    title = f"# DNSResolver run: {status.upper()}"
    if not usable:
        title += ", NO ACTIONABLE TARGETS PUBLISHED"
    lines = [
        title,
        "",
        f"- run: {manifest['run_id']}",
        f"- contract: {manifest['contract_version']}",
        f"- started: {manifest['started_at']}",
        f"- completed: {manifest['completed_at']}",
    ]
    if usable:
        lines.append(f"- actionable targets: {len(targets)}")
    lines.append(f"- excluded observations: {len(observations)}")
    if usable:
        lines += ["", "## Actionable targets", ""] + _targets(targets)
    lines += ["", "## Excluded observations", ""] + _observations(observations)
    lines += ["", "## Provider catalogues", ""]
    for provider, entry in sorted(manifest["provider_catalogs"].items()):
        snapshot = (entry.get("snapshot_id") or "-")[:12]
        lines.append(
            f"- {provider}: {entry['status']}, snapshot {snapshot}, "
            f"retrieved {entry.get('retrieved_at') or '-'}"
        )
    return "\n".join(lines) + "\n"


def _targets(targets):
    groups = {}
    for target in targets:
        groups.setdefault((target["provider"], target["region"]), []).append(target)
    if not groups:
        return ["None."]
    lines = []
    for (provider, region), rows in sorted(groups.items()):
        if lines:
            lines.append("")
        lines += [
            f"### {provider} / {region}",
            "",
            "hostname | ip | services | prefix",
            "--- | --- | --- | ---",
        ]
        for row in sorted(rows, key=lambda r: (r["hostname"], r["ip"])):
            lines.append(
                f"{row['hostname']} | {row['ip']} | "
                f"{', '.join(row['services'])} | {', '.join(row['prefixes'])}"
            )
    return lines


def _observations(observations):
    kinds = {}
    for observation in observations:
        kinds.setdefault(observation["kind"], set()).add(observation["hostname"])
    if not kinds:
        return ["None."]
    lines = ["kind | count", "--- | ---"]
    lines += [f"{kind} | {len(kinds[kind])}" for kind in sorted(kinds)]
    for kind in sorted(kinds):
        hostnames = sorted(kinds[kind])
        lines += ["", f"### {kind}", ""]
        lines += [f"- {name}" for name in hostnames[:MAX_HOSTNAMES]]
        if len(hostnames) > MAX_HOSTNAMES:
            lines.append(f"... and {len(hostnames) - MAX_HOSTNAMES} more")
    return lines
