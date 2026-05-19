"""Tests for RunSummary — verifies stdout output using capsys and tmp_path."""

from classes.run_summary import RunSummary


def _make_summary(tmp_path, files=None):
    """Build a RunSummary backed by real temp files populated with given lines."""
    standard = {
        "resolved": tmp_path / "resolved.txt",
        "unresolved": tmp_path / "unresolved.txt",
        "takeover": tmp_path / "takeover.txt",
        "csp": tmp_path / "csp.txt",
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
    summary.display(total_input=2, failed_count=0)

    out = capsys.readouterr().out
    assert "No takeover candidates detected." in out
    assert "[!]" not in out


def test_counts_are_accurate(tmp_path, capsys):
    summary = _make_summary(
        tmp_path,
        {
            "resolved": "a.com|1.1.1.1\nb.com|2.2.2.2\n",
            "unresolved": "DNS resolution error for c.com: timeout\n",
            "csp": (
                "a.com resolved to aws IPs: ['1.1.1.1']\n"
                "b.com resolved to gcp IPs: ['2.2.2.2']\n"
                "b2.com resolved to gcp IPs: ['3.3.3.3']\n"
            ),
        },
    )
    summary.display(total_input=5, failed_count=1)

    out = capsys.readouterr().out
    assert "5" in out  # total input
    assert "AWS: 1" in out
    assert "GCP: 2" in out
    assert "Azure: 0" in out


# ---------------------------------------------------------------------------
# Classified dangling CNAMEs — shown in full
# ---------------------------------------------------------------------------


def test_classified_dangling_cname_shown_in_full(tmp_path, capsys):
    dangling = "DANGLING|root.example.com|app.s3.amazonaws.com|aws_s3|Remove the CNAME|https://evidence.link\n"
    summary = _make_summary(tmp_path, {"takeover": dangling})
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "[!]" in out
    assert "TAKEOVER CANDIDATE" in out
    assert "Classified dangling CNAMEs (1)" in out
    assert "[aws_s3]" in out
    assert "app.s3.amazonaws.com" in out
    assert "Remove the CNAME" in out
    assert "https://evidence.link" in out


def test_classified_cnames_grouped_by_category(tmp_path, capsys):
    dangling = (
        "DANGLING|a.com|a.herokudns.com|heroku|Remove it|https://heroku.example\n"
        "DANGLING|b.com|b.herokudns.com|heroku|Remove it|https://heroku.example\n"
        "DANGLING|c.com|c.s3.amazonaws.com|aws_s3|Remove the CNAME|https://aws.example\n"
    )
    summary = _make_summary(tmp_path, {"takeover": dangling})
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "Classified dangling CNAMEs (3)" in out
    # aws_s3 sorts before heroku alphabetically
    assert out.index("[aws_s3]") < out.index("[heroku]")


# ---------------------------------------------------------------------------
# Unclassified dangling CNAMEs — collapsed to a count
# ---------------------------------------------------------------------------


def test_unclassified_cnames_shown_individually(tmp_path, capsys):
    """Unclassified entries must appear individually with CNAME target and risk context."""
    dangling = (
        "DANGLING|a.com|mystery-target.example.com|unknown|Unclassified|N/A\n"
        "DANGLING|b.com|another-unknown.example.com|unknown|Unclassified|N/A\n"
    )
    summary = _make_summary(tmp_path, {"takeover": dangling})
    summary.display(total_input=2, failed_count=0)

    out = capsys.readouterr().out
    assert "[!]" in out
    assert "Unclassified dangling CNAMEs (2)" in out
    assert "mystery-target.example.com" in out
    assert "another-unknown.example.com" in out
    assert "Risk" in out
    assert "Action" in out
    assert "Classified dangling CNAMEs" not in out


def test_unclassified_count_included_in_total_banner(tmp_path, capsys):
    """Unclassified dangles must count toward the [!] total."""
    dangling = (
        "DANGLING|a.com|known.herokudns.com|heroku|Remove it|https://h.example\n"
        "DANGLING|b.com|unknown1.example.com|unknown|Unclassified|N/A\n"
        "DANGLING|c.com|unknown2.example.com|unknown|Unclassified|N/A\n"
    )
    summary = _make_summary(tmp_path, {"takeover": dangling})
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    # 1 classified + 2 unclassified = 3
    assert "3 TAKEOVER CANDIDATE(S)" in out
    assert "Classified dangling CNAMEs (1)" in out
    assert "Unclassified dangling CNAMEs (2)" in out


def test_classified_and_unclassified_split(tmp_path, capsys):
    """Classified entries are shown in full; unclassified shown individually with context."""
    dangling = (
        "DANGLING|a.com|app.herokudns.com|heroku|Remove the app|https://heroku.example\n"
        "DANGLING|b.com|noise.example.com|unknown|Unclassified|N/A\n"
    )
    summary = _make_summary(tmp_path, {"takeover": dangling})
    summary.display(total_input=2, failed_count=0)

    out = capsys.readouterr().out
    assert "Classified dangling CNAMEs (1)" in out
    assert "app.herokudns.com" in out
    assert "Unclassified dangling CNAMEs (1)" in out
    assert "noise.example.com" in out


# ---------------------------------------------------------------------------
# NS takeover
# ---------------------------------------------------------------------------


def test_ns_takeover_flagged(tmp_path, capsys):
    ns = "NS_TAKEOVER|vuln.example.com|ns1.orphaned-registrar.com\n"
    summary = _make_summary(tmp_path, {"takeover": ns})
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "[!]" in out
    assert "NS Takeover candidates (1)" in out
    assert "vuln.example.com -> NS: ns1.orphaned-registrar.com" in out
    assert "Why" in out
    assert "DNS control" in out


def test_both_dangling_and_ns_takeover_total_count(tmp_path, capsys):
    takeover = (
        "DANGLING|a.com|a.herokudns.com|heroku|Remove|https://h.example\n"
        "NS_TAKEOVER|b.com|ns1.dead.example\n"
        "NS_TAKEOVER|c.com|ns2.dead.example\n"
    )
    summary = _make_summary(tmp_path, {"takeover": takeover})
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "3 TAKEOVER CANDIDATE(S)" in out


# ---------------------------------------------------------------------------
# CNAME chain depth tracking
# ---------------------------------------------------------------------------


def test_classified_cname_chain_shown_when_depth_gt_zero(tmp_path, capsys):
    """A classified dangling CNAME with depth > 0 must show the full hop chain."""
    dangling = (
        "DANGLING|sub.victim.com|c.cdn.com|aws_s3|Remove CNAME|https://evidence.link|2"
        "|sub.victim.com -> b.cdn.com -> c.cdn.com\n"
    )
    summary = _make_summary(tmp_path, {"takeover": dangling})
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "Chain (2 hops)" in out
    assert "sub.victim.com -> b.cdn.com -> c.cdn.com" in out


def test_unclassified_cname_chain_shown_when_depth_gt_zero(tmp_path, capsys):
    """An unclassified dangling CNAME with depth > 0 must show the full hop chain."""
    dangling = (
        "DANGLING|sub.victim.com|mystery.example.com|unknown|Unclassified|N/A|1"
        "|sub.victim.com -> mystery.example.com\n"
    )
    summary = _make_summary(tmp_path, {"takeover": dangling})
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "Chain (1 hop)" in out
    assert "sub.victim.com -> mystery.example.com" in out


def test_legacy_dangling_line_no_depth_still_parses(tmp_path, capsys):
    """A DANGLING line without depth/chain fields (pre-v1.11 format) parses without error."""
    dangling = "DANGLING|root.example.com|app.s3.amazonaws.com|aws_s3|Remove the CNAME|https://evidence.link\n"
    summary = _make_summary(tmp_path, {"takeover": dangling})
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "Classified dangling CNAMEs (1)" in out
    assert "app.s3.amazonaws.com" in out
    assert "Chain" not in out  # no chain line for depth=0 / missing fields


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_dangling_line_missing_fields_skipped_gracefully(tmp_path, capsys):
    """A malformed dangling line (< 5 fields) should not crash and is silently ignored."""
    summary = _make_summary(tmp_path, {"takeover": "DANGLING|only|two\n"})
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "No takeover candidates detected." in out


def test_missing_file_treated_as_empty(tmp_path, capsys):
    """If an output file is absent, _lines() returns [] without crashing."""
    output_files = {
        "standard": {
            "resolved": "/nonexistent/resolved.txt",
            "unresolved": "/nonexistent/unresolved.txt",
            "takeover": "/nonexistent/takeover.txt",
            "csp": "/nonexistent/csp.txt",
        }
    }
    summary = RunSummary(output_files, "/tmp/output")
    summary.display(total_input=0, failed_count=0)

    out = capsys.readouterr().out
    assert "No takeover candidates detected." in out
