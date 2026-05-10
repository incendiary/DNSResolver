import argparse
import json
import logging
import os
import sys

from version import __version__


class ConfigResolver:
    """Parses CLI arguments and merges them with values from config.json."""

    def __init__(self):
        self._logger = logging.getLogger("DNSResolver")
        self.args = self._parse_args()
        self._validate_args()
        self._merge_config()
        if self.args.extreme:
            self.args.verbose = True

    def _parse_args(self):
        parser = argparse.ArgumentParser(
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
            type=str,
            help="Path to the file containing domains (one per line)",
        )
        parser.add_argument(
            "--config-file",
            type=str,
            default="config.json",
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
            action="store_true",
            help="Enable verbose mode to display more information",
        )
        parser.add_argument(
            "--extreme",
            "-e",
            action="store_true",
            help="Enable extreme mode to display extensive information (including IP ranges)",
        )
        parser.add_argument(
            "--nameservers",
            type=str,
            help="Comma-separated list of custom nameservers. Overrides system resolvers.",
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
            action="store_true",
            help="Enable evidence collection for DNS queries (overrides config file)",
        )
        return parser.parse_args()

    def _validate_args(self):
        if self.args.domains_file and not os.path.isfile(self.args.domains_file):
            self._logger.error(
                "Provided domains file does not exist: %s", self.args.domains_file
            )
            sys.exit(1)

    def _merge_config(self):
        if not self.args.config_file:
            return
        try:
            with open(self.args.config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            self._logger.error("Error loading config file: %s", e)
            config = {}

        for key, value in config.get("config", {}).items():
            if getattr(self.args, key, None) is None:
                setattr(self.args, key, value)
