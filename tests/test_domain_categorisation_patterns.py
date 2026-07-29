"""
Tests for the takeover fingerprints in config.json.

These guard the pattern set itself rather than the matching code. A fingerprint
that silently stops matching leaves a real takeover candidate reported as
'unknown', which is exactly the outcome the pattern set exists to prevent.

Matching is first-match-wins, so these also catch a new pattern shadowing an
existing one.
"""

import json
import os

import pytest

from classes.domain_categoriser import DomainCategoriser

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="module")
def patterns():
    with open(os.path.join(REPO_ROOT, "config.json"), encoding="utf-8") as f:
        return json.load(f)["domain_categorisation"]


# One representative target per fingerprint. Kept explicit rather than generated
# from the regex, so a broken regex cannot make its own test pass.
SAMPLES = [
    ("app.herokuapp.com.", "heroku"),
    ("user.github.io.", "github"),
    ("lb-1234.eu-west-2.elb.amazonaws.com.", "aws_elb"),
    ("bucket.s3.amazonaws.com.", "aws_s3"),
    ("site.azurewebsites.net.", "azure"),
    ("x.impervadns.net.", "incapsula"),
    ("x.proxy-ssl.webflow.com.", "webflow"),
    ("x.helpjuice.com.", "helpjuice"),
    ("x.helpscoutdocs.com.", "helpscout"),
    ("x.cargocollective.com.", "cargo_collective"),
    ("x.uservoice.com.", "uservoice"),
    ("x.tilda.ws.", "tilda"),
    ("x.bigcartel.com.", "bigcartel"),
    ("x.createsend.com.", "campaign_monitor"),
    ("x.custom.intercom.help.", "intercom"),
    ("x.thinkific.com.", "thinkific"),
    ("x.canny.io.", "canny"),
    ("x.endpoint.mykajabi.com.", "kajabi"),
    ("x.furyns.com.", "gemfury"),
    ("x.frontify.com.", "frontify"),
    ("x.ideas.aha.io.", "aha"),
    ("x.brightcovegallery.com.", "brightcove"),
    ("x.wishpond.com.", "wishpond"),
    ("x.gr8.com.", "getresponse"),
    ("x.agilecrm.com.", "agile_crm"),
    ("x.readme.io.", "readme_io"),
    ("x.hatenablog.com.", "hatenablog"),
    ("x.domains.smugmug.com.", "smugmug"),
    ("x.privatedomain.sgizmo.com.", "surveygizmo"),
    ("x.redirect.feedpress.me.", "feedpress"),
    ("x.simplebooklet.com.", "simplebooklet"),
    ("x.vendhq.com.", "vend"),
    ("x.myjetbrains.com.", "jetbrains"),
    ("x.kinsta.cloud.", "kinsta"),
    ("x.cname.short.io.", "short_io"),
    ("x.stats.pingdom.com.", "pingdom"),
]


@pytest.mark.parametrize("target,expected", SAMPLES)
def test_target_classifies_to_expected_category(target, expected, patterns):
    category, _, _ = DomainCategoriser.categorise_domain(target, patterns)
    assert category == expected, (
        f"{target} classified as '{category}', expected '{expected}' — "
        "a pattern is missing, broken, or shadowed by an earlier one"
    )


def test_unrecognised_target_is_unknown(patterns):
    """An unmatched target must be reported honestly, not guessed at."""
    category, recommendation, _ = DomainCategoriser.categorise_domain(
        "something.entirely-unrecognised-xyzzy.example.", patterns
    )
    assert category == "unknown"
    assert recommendation == "Unclassified"


def test_every_pattern_is_well_formed(patterns):
    """Each fingerprint must carry the three fields the output line depends on."""
    for name, entry in patterns.items():
        assert "regex" in entry, f"{name} has no regex"
        assert entry.get("recommendation"), f"{name} has no recommendation"
        assert entry.get("evidence"), f"{name} has no evidence link"


def test_every_pattern_compiles(patterns):
    import re

    for name, entry in patterns.items():
        try:
            re.compile(entry["regex"])
        except re.error as e:
            pytest.fail(f"{name} has an invalid regex: {e}")
