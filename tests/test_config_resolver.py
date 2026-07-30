"""
Tests for ConfigResolver argument parsing.

ConfigResolver calls argparse.parse_args() which reads sys.argv.  We patch
sys.argv directly so we can exercise the parser without subprocesses.

_validate_args checks that the domains file exists on disk, so we use
tmp_path to create a real (empty) file for each test.

Only the --resolvers alias is tested here; the broader EnvironmentManager
integration is covered in test_lambda_environment_manager.py.
"""

from unittest.mock import patch

from classes.config_resolver import ConfigResolver


def _parse(domains_file, extra_argv=None):
    """Run ConfigResolver with a fake sys.argv and return the parsed args."""
    extra_argv = extra_argv or []
    fake_argv = ["resolver.py", str(domains_file)] + extra_argv
    with (
        patch("sys.argv", fake_argv),
        patch("builtins.open", side_effect=IOError("no config")),
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


def _parse_with_real_config(domains_file, config, extra_argv=None):
    """Run ConfigResolver against a real config.json written to disk."""
    import json

    config_path = domains_file.parent / "config.json"
    config_path.write_text(json.dumps({"config": config}))
    extra_argv = extra_argv or []
    fake_argv = [
        "resolver.py",
        str(domains_file),
        "--config-file",
        str(config_path),
    ] + extra_argv
    with patch("sys.argv", fake_argv):
        cfg = ConfigResolver()
    return cfg.args


def test_cli_value_overrides_config_value(tmp_path):
    """A CLI-provided value must win over the config file's value."""
    f = tmp_path / "domains.txt"
    f.write_text("")
    args = _parse_with_real_config(f, {"max_threads": 5}, ["--max-threads", "50"])
    assert args.max_threads == 50


def test_config_value_fills_unset_cli_arg(tmp_path):
    """When a CLI arg is not provided, the config file's value should be used."""
    f = tmp_path / "domains.txt"
    f.write_text("")
    args = _parse_with_real_config(f, {"max_threads": 5})
    assert args.max_threads == 5


def test_bad_config_file_is_tolerated(tmp_path):
    """A malformed config.json must not crash ConfigResolver; args fall back to None."""
    f = tmp_path / "domains.txt"
    f.write_text("")
    config_path = tmp_path / "config.json"
    config_path.write_text("{not valid json")
    fake_argv = ["resolver.py", str(f), "--config-file", str(config_path)]
    with patch("sys.argv", fake_argv):
        cfg = ConfigResolver()
    assert cfg.args.max_threads is None


def test_missing_config_file_is_tolerated(tmp_path):
    """A config file path that doesn't exist must not crash ConfigResolver."""
    f = tmp_path / "domains.txt"
    f.write_text("")
    fake_argv = [
        "resolver.py",
        str(f),
        "--config-file",
        str(tmp_path / "nonexistent.json"),
    ]
    with patch("sys.argv", fake_argv):
        cfg = ConfigResolver()
    assert cfg.args.max_threads is None


def test_resolvers_alias_maps_to_nameservers_with_config_fallback(tmp_path):
    """--resolvers alias must populate args.nameservers, overriding the config value."""
    f = tmp_path / "domains.txt"
    f.write_text("")
    args = _parse_with_real_config(
        f, {"nameservers": "9.9.9.9"}, ["--resolvers", "8.8.8.8"]
    )
    assert args.nameservers == "8.8.8.8"
