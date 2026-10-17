"""
Tests for ConfigResolver argument parsing.

ConfigResolver calls argparse.parse_args() which reads sys.argv.  We patch
sys.argv directly so we can exercise the parser without subprocesses.

_validate_args checks that the domains file exists on disk, so we use
tmp_path to create a real (empty) file for each test.

Only the --resolvers alias is tested here; the broader EnvironmentManager
integration is covered in test_environment_manager.py.
"""

import json
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from classes.config_resolver import OPTIONS, ConfigResolver


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


FLAGS = ("verbose", "extreme", "evidence")


def _bool_args(tmp_path, config, argv=None):
    f = tmp_path / "domains.txt"
    f.write_text("")
    return _parse_with_real_config(f, config, argv)


def test_evidence_true_in_config_applies_without_flag(tmp_path):
    """Regression: store_true defaults of False used to mask config.json."""
    assert _bool_args(tmp_path, {"evidence": True}).evidence is True


def test_no_evidence_beats_config_true(tmp_path):
    args = _bool_args(tmp_path, {"evidence": True}, ["--no-evidence"])
    assert args.evidence is False


def test_evidence_flag_beats_config_false(tmp_path):
    args = _bool_args(tmp_path, {"evidence": False}, ["--evidence"])
    assert args.evidence is True


def test_verbose_true_in_config_applies_without_flag(tmp_path):
    assert _bool_args(tmp_path, {"verbose": True}).verbose is True


def test_no_verbose_beats_config_true(tmp_path):
    args = _bool_args(tmp_path, {"verbose": True}, ["--no-verbose"])
    assert args.verbose is False


def test_verbose_flag_beats_config_false(tmp_path):
    args = _bool_args(tmp_path, {"verbose": False}, ["--verbose"])
    assert args.verbose is True


def test_extreme_true_in_config_applies_without_flag(tmp_path):
    assert _bool_args(tmp_path, {"extreme": True}).extreme is True


def test_no_extreme_beats_config_true(tmp_path):
    args = _bool_args(tmp_path, {"extreme": True}, ["--no-extreme"])
    assert args.extreme is False


def test_extreme_flag_beats_config_false(tmp_path):
    args = _bool_args(tmp_path, {"extreme": False}, ["--extreme"])
    assert args.extreme is True


def test_short_flags_still_work(tmp_path):
    args = _bool_args(tmp_path, {}, ["-v", "-e"])
    assert args.verbose is True and args.extreme is True


def test_extreme_implies_verbose(tmp_path):
    args = _bool_args(tmp_path, {"verbose": False}, ["--extreme"])
    assert args.extreme is True and args.verbose is True


def test_extreme_from_config_implies_verbose(tmp_path):
    assert _bool_args(tmp_path, {"extreme": True}).verbose is True


def test_boolean_flags_default_false_without_flag_or_config(tmp_path):
    args = _bool_args(tmp_path, {})
    assert [getattr(args, flag) for flag in FLAGS] == [False, False, False]


def test_boolean_flags_default_false_when_config_unreadable(tmp_path):
    f = tmp_path / "domains.txt"
    f.write_text("")
    args = _parse(f)
    assert [getattr(args, flag) for flag in FLAGS] == [False, False, False]


def test_shipped_config_leaves_evidence_verbose_and_extreme_off():
    # The committed defaults must stay quiet: evidence capture is opt-in.
    import os

    path = os.path.join(os.path.dirname(__file__), "..", "config.json")
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)["config"]
    assert (config["evidence"], config["verbose"], config["extreme"]) == (
        False,
        False,
        False,
    )


# ---------------------------------------------------------------------------
# Environment layer: CLI flag > DNSRESOLVER_* variable > config.json > default
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent


def _resolve(tmp_path, config=None, argv=None, with_file=True):
    f = tmp_path / "domains.txt"
    f.write_text("")
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"config": config or {}}))
    fake_argv = ["resolver.py"] + ([str(f)] if with_file else [])
    fake_argv += ["--config-file", str(config_path)] + (argv or [])
    with patch("sys.argv", fake_argv):
        return ConfigResolver().args


ENV_CASES = [
    ("output_dir", "DNSRESOLVER_OUTPUT_DIR", "/o", "/o", "from-config"),
    ("nameservers", "DNSRESOLVER_NAMESERVERS", "9.9.9.9", "9.9.9.9", "from-config"),
    ("max_threads", "DNSRESOLVER_MAX_THREADS", "7", 7, 99),
    ("timeout", "DNSRESOLVER_TIMEOUT", "3", 3, 99),
    ("retries", "DNSRESOLVER_RETRIES", "4", 4, 99),
    ("verbose", "DNSRESOLVER_VERBOSE", "yes", True, False),
    ("evidence", "DNSRESOLVER_EVIDENCE", "1", True, False),
    ("record_external_ip", "DNSRESOLVER_RECORD_EXTERNAL_IP", "true", True, False),
]


@pytest.mark.parametrize("dest,var,raw,expected,_cfg", ENV_CASES)
def test_each_variable_applies(tmp_path, monkeypatch, dest, var, raw, expected, _cfg):
    monkeypatch.setenv(var, raw)
    assert getattr(_resolve(tmp_path), dest) == expected


@pytest.mark.parametrize("dest,var,raw,expected,cfg", ENV_CASES)
def test_environment_beats_config_json(
    tmp_path, monkeypatch, dest, var, raw, expected, cfg
):
    monkeypatch.setenv(var, raw)
    assert getattr(_resolve(tmp_path, {dest: cfg}), dest) == expected


def test_extreme_variable_applies_and_implies_verbose(tmp_path, monkeypatch):
    monkeypatch.setenv("DNSRESOLVER_EXTREME", "ON")
    args = _resolve(tmp_path, {"extreme": False})
    assert args.extreme is True and args.verbose is True


def test_config_json_beats_builtin_default(tmp_path):
    args = _resolve(tmp_path, {"timeout": 8, "record_external_ip": True})
    assert (args.timeout, args.record_external_ip) == (8, True)


def test_cli_beats_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("DNSRESOLVER_TIMEOUT", "3")
    monkeypatch.setenv("DNSRESOLVER_EVIDENCE", "true")
    args = _resolve(tmp_path, argv=["--timeout", "9", "--no-evidence"])
    assert (args.timeout, args.evidence) == (9, False)


def test_boolean_values_are_case_insensitive(tmp_path, monkeypatch):
    for raw, expected in (("TRUE", True), ("Off", False), ("No", False), ("1", True)):
        monkeypatch.setenv("DNSRESOLVER_VERBOSE", raw)
        assert _resolve(tmp_path).verbose is expected


def test_empty_variable_is_treated_as_unset(tmp_path, monkeypatch):
    monkeypatch.setenv("DNSRESOLVER_TIMEOUT", "")
    assert _resolve(tmp_path, {"timeout": 8}).timeout == 8


def test_bad_boolean_variable_exits_naming_it(tmp_path, monkeypatch):
    monkeypatch.setenv("DNSRESOLVER_EVIDENCE", "maybe")
    with pytest.raises(SystemExit) as exc:
        _resolve(tmp_path)
    assert exc.value.code != 0 and "DNSRESOLVER_EVIDENCE" in str(exc.value.code)


def test_bad_integer_variable_exits_naming_it(tmp_path, monkeypatch):
    monkeypatch.setenv("DNSRESOLVER_TIMEOUT", "fast")
    with pytest.raises(SystemExit) as exc:
        _resolve(tmp_path)
    assert exc.value.code != 0 and "DNSRESOLVER_TIMEOUT" in str(exc.value.code)


@pytest.mark.parametrize("key,value", [("verbose", "yes"), ("evidence", 1)])
def test_non_boolean_config_value_exits_naming_key(tmp_path, key, value):
    with pytest.raises(SystemExit) as exc:
        _resolve(tmp_path, {key: value})
    assert exc.value.code != 0 and key in str(exc.value.code)


def test_non_integer_config_value_exits_naming_key(tmp_path):
    with pytest.raises(SystemExit) as exc:
        _resolve(tmp_path, {"timeout": "3"})
    assert "timeout" in str(exc.value.code)


def test_domains_file_from_environment(tmp_path, monkeypatch):
    f = tmp_path / "from-env.txt"
    f.write_text("")
    monkeypatch.setenv("DNSRESOLVER_DOMAINS_FILE", str(f))
    assert _resolve(tmp_path, with_file=False).domains_file == str(f)


def test_missing_domains_file_everywhere_is_a_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        _resolve(tmp_path, with_file=False)
    assert exc.value.code != 0
    assert "DNSRESOLVER_DOMAINS_FILE" in capsys.readouterr().err


def test_nonexistent_domains_file_from_environment_exits(tmp_path, monkeypatch):
    monkeypatch.setenv("DNSRESOLVER_DOMAINS_FILE", str(tmp_path / "nope.txt"))
    with pytest.raises(SystemExit) as exc:
        _resolve(tmp_path, with_file=False)
    assert exc.value.code != 0


def test_config_file_from_environment(tmp_path, monkeypatch):
    f = tmp_path / "domains.txt"
    f.write_text("")
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"config": {"retries": 6}}))
    monkeypatch.setenv("DNSRESOLVER_CONFIG_FILE", str(other))
    with patch("sys.argv", ["resolver.py", str(f)]):
        assert ConfigResolver().args.retries == 6


def test_envrc_example_lists_exactly_the_variables_the_code_reads():
    example = (ROOT / ".envrc.example").read_text(encoding="utf-8")
    assert example.splitlines()[0] == "# Copy to .envrc, then run: direnv allow"
    in_example = set(re.findall(r"^# (DNSRESOLVER_[A-Z_]+)=", example, re.M))
    in_code = {var for var, _ in OPTIONS.values()}
    assert in_example == in_code
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert all(f"`{var}`" in readme for var in in_code)


def test_envrc_files_are_git_ignored():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert ".envrc" in ignored and ".env" in ignored
