"""Tests for RunSummary — verifies stdout output using capsys and tmp_path."""

import pytest

from classes.run_summary import RunSummary


def _make_summary(tmp_path, files=None):
    """Build a RunSummary backed by real temp files populated with given lines."""
    standard = {
        "resolved": tmp_path / "resolved.txt",
        "unresolved": tmp_path / "unresolved.txt",
        "dangling": tmp_path / "dangling.txt",
        "ns_takeover": tmp_path / "ns_takeover.txt",
        "aws": tmp_path / "aws.txt",
        "gcp": tmp_path / "gcp.txt",
        "azure": tmp_path / "azure.txt",
    }
    for key, path in standard.items():
        content = files.get(key, "") if files else ""
        path.write_text(content, encoding="utf-8")

    output_files = {"standard": {k: str(v) for k, v in standard.items()}}
    return RunSummary(output_files, str(tmp_path))


# ---------------------------------------------------------------------------
# Clean run — no candidates
# ---------------------------------------------------------------------------


def test_no_candidates_prints_clean_message(tmp_path, capsys):
    summary = _make_summary(
        tmp_path,
        {
            "resolved": "example.com|1.2.3.4\nfoo.com|5.6.7.8\n",
        },
    )
    summary.print(total_input=2, failed_count=0)

    out = capsys.readouterr().out
    assert "No takeover candidates detected." in out
    assert "[!]" not in out


def test_counts_are_accurate(tmp_path, capsys):
    summary = _make_summary(
        tmp_path,
        {
            "resolved": "a.com|1.1.1.1\nb.com|2.2.2.2\n",
            "unresolved": "DNS resolution error for c.com: timeout\n",
            "aws": "a.com|1.1.1.1\n",
            "gcp": "b.com|2.2.2.2\nb2.com|3.3.3.3\n",
        },
    )
    summary.print(total_input=5, failed_count=1)

    out = capsys.readouterr().out
    assert "5" in out  # total input
    assert "AWS: 1" in out
    assert "GCP: 2" in out
    assert "Azure: 0" in out


# ---------------------------------------------------------------------------
# Dangling CNAMEs
# ---------------------------------------------------------------------------


def test_dangling_cname_flagged(tmp_path, capsys):
    dangling = "root.example.com|app.s3.amazonaws.com|aws_s3|Remove the CNAME|https://evidence.link\n"
    summary = _make_summary(tmp_path, {"dangling": dangling})
    summary.print(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "[!]" in out
    assert "TAKEOVER CANDIDATE" in out
    assert "Dangling CNAMEs (1)" in out
    assert "[aws_s3]" in out
    assert "app.s3.amazonaws.com" in out
    assert "Remove the CNAME" in out
    assert "https://evidence.link" in out


def test_dangling_cnames_grouped_by_category(tmp_path, capsys):
    dangling = (
        "a.com|a.herokudns.com|heroku|Remove it|https://heroku.example\n"
        "b.com|b.herokudns.com|heroku|Remove it|https://heroku.example\n"
        "c.com|c.s3.amazonaws.com|aws_s3|Remove the CNAME|https://aws.example\n"
    )
    summary = _make_summary(tmp_path, {"dangling": dangling})
    summary.print(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "Dangling CNAMEs (3)" in out
    # aws_s3 sorts before heroku alphabetically
    aws_pos = out.index("[aws_s3]")
    heroku_pos = out.index("[heroku]")
    assert aws_pos < heroku_pos


def test_dangling_line_missing_fields_skipped_gracefully(tmp_path, capsys):
    """A malformed dangling line (< 5 fields) should not crash the summary."""
    summary = _make_summary(tmp_path, {"dangling": "only|two\n"})
    summary.print(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    # The line is silently skipped; candidate block still shown but empty category
    assert "Dangling CNAMEs (1)" in out


# ---------------------------------------------------------------------------
# NS takeover
# ---------------------------------------------------------------------------


def test_ns_takeover_flagged(tmp_path, capsys):
    ns = "vuln.example.com|ns1.orphaned-registrar.com\n"
    summary = _make_summary(tmp_path, {"ns_takeover": ns})
    summary.print(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "[!]" in out
    assert "NS Takeover candidates (1)" in out
    assert "vuln.example.com -> NS: ns1.orphaned-registrar.com" in out


def test_both_dangling_and_ns_takeover_total_count(tmp_path, capsys):
    dangling = "a.com|a.herokudns.com|heroku|Remove|https://h.example\n"
    ns = "b.com|ns1.dead.example\nc.com|ns2.dead.example\n"
    summary = _make_summary(tmp_path, {"dangling": dangling, "ns_takeover": ns})
    summary.print(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "3 TAKEOVER CANDIDATE(S)" in out


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_missing_file_treated_as_empty(tmp_path, capsys):
    """If an output file is absent, _lines() returns [] without crashing."""
    output_files = {
        "standard": {
            "resolved": "/nonexistent/resolved.txt",
            "unresolved": "/nonexistent/unresolved.txt",
            "dangling": "/nonexistent/dangling.txt",
            "ns_takeover": "/nonexistent/ns_takeover.txt",
            "aws": "/nonexistent/aws.txt",
            "gcp": "/nonexistent/gcp.txt",
            "azure": "/nonexistent/azure.txt",
        }
    }
    summary = RunSummary(output_files, "/tmp/output")
    summary.print(total_input=0, failed_count=0)

    out = capsys.readouterr().out
    assert "No takeover candidates detected." in out
