import argparse
import json
import logging
import os
import sys

from version import __version__

# Every option: argparse dest -> (environment variable, type). The one table
# the environment layer, the validation and the .envrc.example test all read.
OPTIONS = {
    "domains_file": ("DNSRESOLVER_DOMAINS_FILE", str),
    "output_dir": ("DNSRESOLVER_OUTPUT_DIR", str),
    "nameservers": ("DNSRESOLVER_NAMESERVERS", str),
    "max_threads": ("DNSRESOLVER_MAX_THREADS", int),
    "timeout": ("DNSRESOLVER_TIMEOUT", int),
    "retries": ("DNSRESOLVER_RETRIES", int),
    "verbose": ("DNSRESOLVER_VERBOSE", bool),
    "extreme": ("DNSRESOLVER_EXTREME", bool),
    "evidence": ("DNSRESOLVER_EVIDENCE", bool),
    "config_file": ("DNSRESOLVER_CONFIG_FILE", str),
}

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")


def _from_env(raw, kind, var):
    """Parse an environment value; anything unparseable exits non-zero."""
    text = raw.strip()
    if kind is bool:
        if text.lower() in _TRUE:
            return True
        if text.lower() in _FALSE:
            return False
        sys.exit(
            f"{var}={raw!r} is not a boolean (use 1/true/yes/on or 0/false/no/off)"
        )
    if kind is int:
        try:
            return int(text)
        except ValueError:
            sys.exit(f"{var}={raw!r} is not an integer")
    return text


def _from_config(value, kind, key):
    """Check a config.json value has the option's type; no string coercion."""
    if isinstance(value, bool) is (kind is bool) and isinstance(value, kind):
        return value
    sys.exit(f"config.json key {key!r} must be {kind.__name__}, got {value!r}")


class ConfigResolver:
    """Resolves options: CLI flag, then DNSRESOLVER_* variable, then config.json."""

    def __init__(self):
        self._logger = logging.getLogger("DNSResolver")
        self.args = self._parse_args()
        config = self._load_config()
        for dest in OPTIONS:
            if dest != "config_file":
                setattr(self.args, dest, self._resolve(dest, config))
        for dest, (_, kind) in OPTIONS.items():
            # Tri-state flags stay None until here so every layer can fill them.
            if kind is bool and getattr(self.args, dest) is None:
                setattr(self.args, dest, False)
        for key, value in config.items():  # keys outside the table pass through
            if key not in OPTIONS and getattr(self.args, key, None) is None:
                setattr(self.args, key, value)
        if self.args.domains_file is None:
            self._parser.error(
                "a domains file is required (argument or DNSRESOLVER_DOMAINS_FILE)"
            )
        self._validate_args()
        if self.args.extreme:
            self.args.verbose = True

    def _resolve(self, dest, config):
        """CLI flag, then environment variable, then config.json, else None."""
        var, kind = OPTIONS[dest]
        value = getattr(self.args, dest)
        if value is not None:
            return value
        raw = os.environ.get(var, "").strip()
        if raw:
            return _from_env(raw, kind, var)
        if dest in config:
            return _from_config(config[dest], kind, dest)
        return None

    def _parse_args(self):
        parser = self._parser = argparse.ArgumentParser(
            description="Resolve DNS records for domains and check against "
            "cloud provider IP ranges."
        )
        parser.add_argument(
            "--version",
            action="version",
            version=f"DNSResolver {__version__}",
        )
        parser.add_argument(
            "domains_file",
            nargs="?",
            type=str,
            help="Path to the file containing domains, one per line "
            "(or set DNSRESOLVER_DOMAINS_FILE)",
        )
        parser.add_argument(
            "--config-file",
            type=str,
            help="Path to the configuration file (default: config.json)",
        )
        parser.add_argument(
            "--output-dir",
            "-o",
            type=str,
            help="Directory to save output files (overrides config file)",
        )
        parser.add_argument(
            "--verbose",
            "-v",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Enable verbose mode to display more information",
        )
        parser.add_argument(
            "--extreme",
            "-e",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Enable extreme mode to display extensive information (including IP ranges)",
        )
        parser.add_argument(
            "--nameservers",
            "--resolvers",
            dest="nameservers",
            type=str,
            help=(
                "Comma-separated list of custom nameservers to use for all queries. "
                "Falls back to system resolvers when omitted. "
                "(--resolvers is an accepted alias)"
            ),
        )
        parser.add_argument(
            "--max-threads",
            "-mt",
            type=int,
            help="Max number of threads to use for domain processing (overrides config file)",
        )
        parser.add_argument(
            "--timeout",
            "-t",
            type=int,
            help="Timeout for DNS resolution process in seconds (overrides config file)",
        )
        parser.add_argument(
            "--retries",
            type=int,
            help="Number of retry attempts for timeouts (overrides config file)",
        )
        parser.add_argument(
            "--evidence",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Enable evidence collection for DNS queries (overrides config file)",
        )
        return parser.parse_args()

    def _validate_args(self):
        if self.args.domains_file and not os.path.isfile(self.args.domains_file):
            self._logger.error(
                "Provided domains file does not exist: %s", self.args.domains_file
            )
            sys.exit(1)

    def _load_config(self):
        path = self._resolve("config_file", {}) or "config.json"
        self.args.config_file = path
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f).get("config", {})
        except (IOError, json.JSONDecodeError) as e:
            self._logger.error("Error loading config file: %s", e)
            return {}
