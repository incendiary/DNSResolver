"""Tests for RunSummary: verifies stdout output from in-memory records using capsys."""

from classes.records import CspMatch, Dangling, NsTakeover, Resolution, Unresolved
from classes.run_summary import RunSummary


def _summary(records=()):
    return RunSummary(list(records), "/tmp/output")


def _dangling(origin, target, category, recommendation, evidence, hops=0, chain=""):
    return Dangling(origin, target, category, recommendation, evidence, hops, chain)


def _csp(domain, ip, provider, region, service, wildcard=""):
    return CspMatch(
        domain, ip, provider, region, service, f"{ip}/32", "unknown", wildcard
    )


# ---------------------------------------------------------------------------
# Clean run — no candidates
# ---------------------------------------------------------------------------


def test_no_candidates_prints_clean_message(capsys):
    summary = _summary(
        [Resolution("example.com", ("1.2.3.4",)), Resolution("foo.com", ("5.6.7.8",))]
    )
    summary.display(total_input=2, failed_count=0)

    out = capsys.readouterr().out
    assert "No takeover candidates detected." in out
    assert "[!]" not in out


def test_counts_are_accurate(capsys):
    summary = _summary(
        [
            Resolution("a.com", ("1.1.1.1",)),
            Resolution("b.com", ("2.2.2.2",)),
            Unresolved("c.com", "timeout"),
            _csp("a.com", "1.1.1.1", "aws", "eu-west-2", "EC2"),
            _csp("b.com", "2.2.2.2", "gcp", "europe-west2", "Google Cloud"),
            _csp("b2.com", "3.3.3.3", "gcp", "us-central1", "Google Cloud"),
        ]
    )
    summary.display(total_input=5, failed_count=1)

    out = capsys.readouterr().out
    assert "Input domains        :      5" in out
    assert "Resolved             :      2" in out
    assert "Unresolved errors    :      1" in out
    assert "Failed (all retries) :      1" in out
    assert "AWS: 1" in out
    assert "GCP: 2" in out
    assert "Azure: 0" in out


def test_wildcard_resolutions_are_counted_separately(capsys):
    summary = _summary(
        [
            Resolution("a.com", ("1.1.1.1",), "WILDCARD"),
            Resolution("b.com", ("2.2.2.2",), "WILDCARD_ZONE"),
            Resolution("c.com", ("3.3.3.3",)),
        ]
    )
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "Resolved             :      3" in out
    assert "confirmed catch-all:      1" in out
    assert "in catch-all zone  :      1" in out


# ---------------------------------------------------------------------------
# Classified dangling CNAMEs — shown in full
# ---------------------------------------------------------------------------


def test_classified_dangling_cname_shown_in_full(capsys):
    summary = _summary(
        [
            _dangling(
                "root.example.com",
                "app.s3.amazonaws.com",
                "aws_s3",
                "Remove the CNAME",
                "https://evidence.link",
            )
        ]
    )
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "[!]" in out
    assert "TAKEOVER CANDIDATE" in out
    assert "Classified dangling CNAMEs (1)" in out
    assert "[aws_s3]" in out
    assert "app.s3.amazonaws.com" in out
    assert "Remove the CNAME" in out
    assert "https://evidence.link" in out


def test_classified_cnames_grouped_by_category(capsys):
    summary = _summary(
        [
            _dangling(
                "a.com", "a.herokudns.com", "heroku", "Remove it", "https://h.example"
            ),
            _dangling(
                "b.com", "b.herokudns.com", "heroku", "Remove it", "https://h.example"
            ),
            _dangling(
                "c.com",
                "c.s3.amazonaws.com",
                "aws_s3",
                "Remove the CNAME",
                "https://aws.example",
            ),
        ]
    )
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "Classified dangling CNAMEs (3)" in out
    # aws_s3 sorts before heroku alphabetically
    assert out.index("[aws_s3]") < out.index("[heroku]")


# ---------------------------------------------------------------------------
# Unclassified dangling CNAMEs
# ---------------------------------------------------------------------------


def test_unclassified_cnames_shown_individually(capsys):
    """Unclassified entries must appear individually with CNAME target and risk context."""
    summary = _summary(
        [
            _dangling(
                "a.com", "mystery-target.example.com", "unknown", "Unclassified", "N/A"
            ),
            _dangling(
                "b.com",
                "another-unknown.example.com",
                "unknown",
                "Unclassified",
                "N/A",
            ),
        ]
    )
    summary.display(total_input=2, failed_count=0)

    out = capsys.readouterr().out
    assert "[!]" in out
    assert "Unclassified dangling CNAMEs (2)" in out
    assert "mystery-target.example.com" in out
    assert "another-unknown.example.com" in out
    assert "Risk" in out
    assert "Action" in out
    assert "Classified dangling CNAMEs" not in out


def test_unclassified_count_included_in_total_banner(capsys):
    """Unclassified dangles must count toward the [!] total."""
    summary = _summary(
        [
            _dangling(
                "a.com", "known.herokudns.com", "heroku", "Remove it", "https://h"
            ),
            _dangling("b.com", "unknown1.example.com", "unknown", "Unclassified", "-"),
            _dangling("c.com", "unknown2.example.com", "unknown", "Unclassified", "-"),
        ]
    )
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    # 1 classified + 2 unclassified = 3
    assert "3 TAKEOVER CANDIDATE(S)" in out
    assert "Classified dangling CNAMEs (1)" in out
    assert "Unclassified dangling CNAMEs (2)" in out


def test_classified_and_unclassified_split(capsys):
    """Classified entries are shown in full; unclassified shown individually with context."""
    summary = _summary(
        [
            _dangling(
                "a.com",
                "app.herokudns.com",
                "heroku",
                "Remove the app",
                "https://heroku.example",
            ),
            _dangling("b.com", "noise.example.com", "unknown", "Unclassified", "N/A"),
        ]
    )
    summary.display(total_input=2, failed_count=0)

    out = capsys.readouterr().out
    assert "Classified dangling CNAMEs (1)" in out
    assert "app.herokudns.com" in out
    assert "Unclassified dangling CNAMEs (1)" in out
    assert "noise.example.com" in out


# ---------------------------------------------------------------------------
# NS takeover
# ---------------------------------------------------------------------------


def test_ns_takeover_flagged(capsys):
    summary = _summary(
        [
            NsTakeover(
                "vuln.example.com", "vuln.example.com", "ns1.orphaned-registrar.com"
            )
        ]
    )
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "[!]" in out
    assert "NS Takeover candidates (1)" in out
    assert (
        "vuln.example.com -> NS: vuln.example.com "
        "(nameserver ns1.orphaned-registrar.com)"
    ) in out
    assert "Why" in out
    assert "DNS control" in out


def test_ns_takeover_without_nameserver_is_described_accurately(capsys):
    summary = _summary([NsTakeover("deleg.example.com", "deleg.example.com", "-")])
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "deleg.example.com -> NS: deleg.example.com" in out
    assert "(nameserver" not in out
    assert "Name has NS records but no address records" in out
    assert "DNS control" not in out


def test_both_dangling_and_ns_takeover_total_count(capsys):
    summary = _summary(
        [
            _dangling("a.com", "a.herokudns.com", "heroku", "Remove", "https://h"),
            NsTakeover("b.com", "b.com", "ns1.dead.example"),
            NsTakeover("c.com", "c.com", "ns2.dead.example"),
        ]
    )
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "3 TAKEOVER CANDIDATE(S)" in out


# ---------------------------------------------------------------------------
# CNAME chain depth tracking
# ---------------------------------------------------------------------------


def test_classified_cname_chain_shown_when_depth_gt_zero(capsys):
    """A classified dangling CNAME with depth > 0 must show the full hop chain."""
    summary = _summary(
        [
            _dangling(
                "sub.victim.com",
                "c.cdn.com",
                "aws_s3",
                "Remove CNAME",
                "https://evidence.link",
                2,
                "sub.victim.com -> b.cdn.com -> c.cdn.com",
            )
        ]
    )
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "Chain (2 hops)" in out
    assert "sub.victim.com -> b.cdn.com -> c.cdn.com" in out


def test_unclassified_cname_chain_shown_when_depth_gt_zero(capsys):
    """An unclassified dangling CNAME with depth > 0 must show the full hop chain."""
    summary = _summary(
        [
            _dangling(
                "sub.victim.com",
                "mystery.example.com",
                "unknown",
                "Unclassified",
                "N/A",
                1,
                "sub.victim.com -> mystery.example.com",
            )
        ]
    )
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "Chain (1 hop)" in out
    assert "sub.victim.com -> mystery.example.com" in out


def test_no_chain_line_at_depth_zero(capsys):
    summary = _summary(
        [
            _dangling(
                "root.example.com",
                "app.s3.amazonaws.com",
                "aws_s3",
                "Remove the CNAME",
                "https://evidence.link",
            )
        ]
    )
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "Classified dangling CNAMEs (1)" in out
    assert "app.s3.amazonaws.com" in out
    assert "Chain" not in out


def test_no_records_prints_clean_summary(capsys):
    _summary().display(total_input=0, failed_count=0)

    out = capsys.readouterr().out
    assert "No takeover candidates detected." in out
    assert "No cloud-hosted addresses found." in out


# ---------------------------------------------------------------------------
# Cloud matches
# ---------------------------------------------------------------------------


def test_csp_breakdown_shows_region_and_service(capsys):
    """
    A provider tally alone is not actionable. An operator needs the region an
    address is allocated from and the service it belongs to.
    """
    summary = _summary(
        [
            _csp("a.com", "1.1.1.1", "aws", "eu-west-2", "EC2"),
            _csp("b.com", "1.1.1.2", "aws", "eu-west-2", "EC2"),
            _csp("c.com", "9.9.9.9", "aws", "us-east-1", "AMAZON"),
        ]
    )
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "by region and service" in out
    assert "aws  eu-west-2  EC2" in out
    assert "aws  us-east-1  AMAZON" in out
    # The busiest grouping is listed first.
    assert out.index("eu-west-2") < out.index("us-east-1")


def test_wildcard_cloud_records_are_excluded_from_targets(capsys):
    """
    Wildcard cloud records are the hosting platform's own addresses. They are
    reported for transparency but must not inflate the target counts, or a
    single wildcarded zone would dominate the summary.
    """
    summary = _summary(
        [
            _csp("a.com", "1.1.1.1", "aws", "eu-west-2", "EC2"),
            _csp("b.com", "2.2.2.2", "gcp", "europe-west2", "Google Cloud", "WILDCARD"),
            _csp("c.com", "2.2.2.2", "gcp", "europe-west2", "Google Cloud", "WILDCARD"),
        ]
    )
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "AWS: 1" in out
    assert "GCP: 0" in out, "wildcard records must not count as GCP targets"
    assert "excluded (wildcard) :    2" in out


def test_cloud_targets_get_headline_billing(capsys):
    """
    Cloud reclaim targets are one of the tool's two jobs, so they are announced
    rather than reported as a footnote under the takeover banner.
    """
    summary = _summary([_csp("a.com", "1.1.1.1", "aws", "eu-west-2", "EC2")])
    summary.display(total_input=1, failed_count=0)

    out = capsys.readouterr().out
    assert "1 CLOUD-HOSTED ADDRESS(ES)" in out


def test_no_cloud_addresses_says_so_explicitly(capsys):
    """Silence would read as 'not checked'; say the check ran and found nothing."""
    _summary().display(total_input=1, failed_count=0)

    assert "No cloud-hosted addresses found." in capsys.readouterr().out


def test_catch_all_zone_records_are_also_excluded_from_targets(capsys):
    """
    Both verdicts are excluded from the target count. A catch-all served from a
    pool larger than the probe sampled is still a catch-all. Counting it as a
    target is the failure this two-tier reporting exists to prevent.
    """
    summary = _summary(
        [
            _csp("a.com", "1.1.1.1", "aws", "eu-west-2", "EC2"),
            _csp("b.com", "2.2.2.2", "aws", "eu-west-1", "EC2", "WILDCARD"),
            _csp("c.com", "3.3.3.3", "aws", "us-east-1", "EC2", "WILDCARD_ZONE"),
        ]
    )
    summary.display(total_input=3, failed_count=0)

    out = capsys.readouterr().out
    assert "AWS: 1" in out, "only the non-wildcard address is a target"
    assert "excluded (wildcard) :    2" in out
