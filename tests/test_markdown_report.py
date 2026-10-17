"""Layout tests for the Markdown run report, from small hand-built documents."""

from classes.markdown_report import MAX_HOSTNAMES, render


def _manifest(status="complete"):
    entry = {
        "status": "complete",
        "usable": True,
        "retrieved_at": "2026-01-01T00:00:00Z",
        "snapshot_id": "0123456789abcdef",
    }
    return {
        "contract_version": "1.0",
        "run_id": "run-1",
        "status": status,
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:05Z",
        "provider_catalogs": {
            "gcp": {**entry, "status": "failed", "usable": False, "snapshot_id": None},
            "aws": entry,
            "azure": entry,
        },
    }


def _observation(hostname, kind="unresolved"):
    return {"hostname": hostname, "kind": kind, "ips": [], "reasons": ["x"]}


def _target(hostname, provider="aws", region="eu-west-2"):
    return {
        "hostname": hostname,
        "ip": "198.18.0.1",
        "provider": provider,
        "region": region,
        "services": ["EC2", "AMAZON"],
        "prefixes": ["198.18.0.0/24"],
    }


def test_complete_layout_groups_by_provider_and_region():
    targets = [
        _target("b.example.com"),
        _target("a.example.com", "gcp", "europe-west2"),
    ]
    text = render(targets, [], _manifest())
    lines = text.splitlines()
    assert lines[0] == "# DNSResolver run: COMPLETE"
    assert text.index("### aws / eu-west-2") < text.index("### gcp / europe-west2")
    assert "b.example.com | 198.18.0.1 | EC2, AMAZON | 198.18.0.0/24" in lines
    assert "contract_version" not in text
    assert "- gcp: failed, snapshot -, retrieved 2026-01-01T00:00:00Z" in lines
    assert "- aws: complete, snapshot 0123456789ab, retrieved" in text
    assert text.index("## Actionable") < text.index("## Excluded")
    assert text.index("## Excluded") < text.index("## Provider catalogues")
    assert text == render(targets[::-1], [], _manifest())


def test_incomplete_and_failed_say_so_first_and_omit_targets():
    for status in ("incomplete", "failed"):
        text = render([], [_observation("a.example.com")], _manifest(status))
        first = text.splitlines()[0]
        assert status.upper() in first and "NO ACTIONABLE TARGETS" in first
        assert "## Actionable targets" not in text
        assert "- a.example.com" in text
        assert "## Provider catalogues" in text


def test_hostnames_truncate_at_twenty_with_remainder():
    names = [f"h{i:02d}.example.com" for i in range(MAX_HOSTNAMES + 5)]
    text = render([], [_observation(name) for name in names], _manifest())
    assert f"unresolved | {len(names)}" in text
    assert f"- {names[MAX_HOSTNAMES - 1]}" in text
    assert f"- {names[MAX_HOSTNAMES]}" not in text
    assert "... and 5 more" in text


def test_exactly_twenty_hostnames_print_no_remainder():
    observations = [_observation(f"h{i:02d}.example.com") for i in range(MAX_HOSTNAMES)]
    assert "more" not in render([], observations, _manifest())
