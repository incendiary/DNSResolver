"""Tests for LambdaEnvironmentManager."""

import json
import logging
import os

from classes.lambda_environment_manager import LambdaEnvironmentManager


def _make_manager(tmp_path, domains_file=None, **kwargs):
    """Helper: construct a LambdaEnvironmentManager with sensible test defaults."""
    if domains_file is None:
        d = tmp_path / "domains.txt"
        d.write_text("example.com\n")
        domains_file = str(d)

    config = {
        "config": {
            "timeout": 5,
            "retries": 2,
            "max_threads": 10,
            "output_dir": str(tmp_path),
        },
        "domain_categorisation": {},
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))

    return LambdaEnvironmentManager(
        domains_file=domains_file,
        output_dir=str(tmp_path / "output"),
        config_file=str(config_path),
        **kwargs,
    )


def test_init_sets_domains_file(tmp_path):
    mgr = _make_manager(tmp_path)
    assert mgr.domains_file.endswith("domains.txt")


def test_init_evidence_always_disabled(tmp_path):
    mgr = _make_manager(tmp_path)
    assert mgr.evidence is False


def test_init_extreme_always_disabled(tmp_path):
    mgr = _make_manager(tmp_path)
    assert mgr.extreme is False


def test_init_applies_config_defaults_for_timeout(tmp_path):
    mgr = _make_manager(tmp_path)
    assert mgr.timeout == 5


def test_init_applies_config_defaults_for_retries(tmp_path):
    mgr = _make_manager(tmp_path)
    assert mgr.retries == 2


def test_init_applies_config_defaults_for_max_threads(tmp_path):
    mgr = _make_manager(tmp_path)
    assert mgr.max_threads == 10


def test_explicit_params_override_config_defaults(tmp_path):
    mgr = _make_manager(tmp_path, timeout=30, retries=5, max_threads=100)
    assert mgr.timeout == 30
    assert mgr.retries == 5
    assert mgr.max_threads == 100


def test_nameservers_set_when_provided(tmp_path):
    mgr = _make_manager(tmp_path, nameservers=["8.8.8.8", "1.1.1.1"])
    assert mgr.nameservers == ["8.8.8.8", "1.1.1.1"]


def test_nameservers_none_when_not_provided(tmp_path):
    mgr = _make_manager(tmp_path)
    assert mgr.nameservers is None


def test_get_config_file_returns_configured_path(tmp_path):
    mgr = _make_manager(tmp_path)
    assert mgr.get_config_file().endswith("config.json")


def test_logger_has_no_file_handler(tmp_path):
    mgr = _make_manager(tmp_path)
    handler_types = [type(h) for h in mgr.logger.handlers]
    assert logging.FileHandler not in handler_types


def test_logger_has_stream_handler(tmp_path):
    mgr = _make_manager(tmp_path)
    assert any(isinstance(h, logging.StreamHandler) for h in mgr.logger.handlers)


def test_output_files_created(tmp_path):
    mgr = _make_manager(tmp_path)
    output_files = mgr.get_output_files()
    assert "standard" in output_files
    for key, path in output_files["standard"].items():
        if key != "environment":  # JSON written separately
            assert os.path.exists(path), f"Missing output file: {path}"


def test_missing_config_file_uses_empty_config(tmp_path):
    d = tmp_path / "domains.txt"
    d.write_text("example.com\n")
    mgr = LambdaEnvironmentManager(
        domains_file=str(d),
        output_dir=str(tmp_path / "output"),
        config_file=str(tmp_path / "nonexistent.json"),
    )
    assert mgr.config == {}


def test_environment_info_records_lambda_command(tmp_path):
    mgr = _make_manager(tmp_path)
    assert mgr.environment_info["command_executed"] == "lambda"
