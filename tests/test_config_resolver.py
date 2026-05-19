"""
Tests for ConfigResolver argument parsing.

ConfigResolver calls argparse.parse_args() which reads sys.argv.  We patch
sys.argv directly so we can exercise the parser without subprocesses.

_validate_args checks that the domains file exists on disk, so we use
tmp_path to create a real (empty) file for each test.

Only the --resolvers alias is tested here; the broader EnvironmentManager
integration is covered in test_lambda_environment_manager.py.
"""

import sys
from unittest.mock import patch

import pytest

from classes.config_resolver import ConfigResolver


def _parse(domains_file, extra_argv=None):
    """Run ConfigResolver with a fake sys.argv and return the parsed args."""
    extra_argv = extra_argv or []
    fake_argv = ["resolver.py", str(domains_file)] + extra_argv
    with patch("sys.argv", fake_argv), patch(
        "builtins.open", side_effect=IOError("no config")
    ):
        cfg = ConfigResolver()
    return cfg.args


def test_nameservers_flag_parsed(tmp_path):
    f = tmp_path / "domains.txt"
    f.write_text("")
    args = _parse(f, ["--nameservers", "8.8.8.8,1.1.1.1"])
    assert args.nameservers == "8.8.8.8,1.1.1.1"


def test_resolvers_alias_parsed(tmp_path):
    """--resolvers must be accepted and stored in args.nameservers."""
    f = tmp_path / "domains.txt"
    f.write_text("")
    args = _parse(f, ["--resolvers", "9.9.9.9,149.112.112.112"])
    assert args.nameservers == "9.9.9.9,149.112.112.112"


def test_resolvers_and_nameservers_are_equivalent(tmp_path):
    """Both flags should produce identical args.nameservers values."""
    f = tmp_path / "domains.txt"
    f.write_text("")
    ns_args = _parse(f, ["--nameservers", "8.8.8.8"])
    rs_args = _parse(f, ["--resolvers", "8.8.8.8"])
    assert ns_args.nameservers == rs_args.nameservers


def test_nameservers_default_is_none(tmp_path):
    """When neither flag is given, args.nameservers must be None (fall back to system)."""
    f = tmp_path / "domains.txt"
    f.write_text("")
    args = _parse(f)
    assert args.nameservers is None
