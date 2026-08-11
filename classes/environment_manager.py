import json
import logging
import os
import random
import re
import sys
from datetime import datetime

import requests
from requests import RequestException
from tqdm import tqdm

from classes.config_resolver import ConfigResolver
from classes.output_manager import OutputManager


class TqdmLoggingHandler(logging.StreamHandler):
    """Routes log output through tqdm.write() so the progress bar stays pinned."""

    def emit(self, record):
        try:
            tqdm.write(self.format(record))
        except Exception:
            self.handleError(record)


def fetch_external_ip(timeout=10):
    try:
        response = requests.get("https://ifconfig.io/ip", timeout=timeout)
        return response.text.strip()
    except RequestException as error:
        return f"An error occurred while trying to retrieve the external ip: {error}"


def setup_logger(log_file="dnsresolver.log", verbose=False):
    logger = logging.getLogger("DNSResolver")
    logger.setLevel(logging.INFO)
    if logger.hasHandlers():
        logger.handlers.clear()
    ch = TqdmLoggingHandler()
    ch.setLevel(logging.INFO if verbose else logging.CRITICAL)
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger.addHandler(ch)
    logger.addHandler(fh)
    logger.info("Logger initialized.")
    return logger


class EnvironmentManager:
    """Thin orchestrator: wires ConfigResolver, OutputManager, logging, and domain I/O."""

    def __init__(self):
        self.logger = setup_logger()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.domains = set()
        self.patterns = None
        self.environment_info = {}

        cfg = ConfigResolver()
        self.args = cfg.args
        self._config_file = cfg.args.config_file
        self.domains_file = cfg.args.domains_file
        self.output_dir = cfg.args.output_dir
        self.verbose = cfg.args.verbose
        self.extreme = cfg.args.extreme
        self.nameservers = (
            [
                nameserver.strip()
                for nameserver in cfg.args.nameservers.split(",")
                if nameserver.strip()
            ]
            if cfg.args.nameservers
            else None
        )
        self.max_threads = cfg.args.max_threads
        self.timeout = cfg.args.timeout
        self.retries = cfg.args.retries
        self.evidence = cfg.args.evidence

        self.log_effective_configuration()
        if self.verbose:
            self.update_logger()

        om = OutputManager(self.output_dir, self.timestamp, self.evidence)
        self.output_dir = om.output_dir
        self.output_files = om.output_files
        self.write_to_file = om.write_to_file

        self._populate_environment_info()
        self.save_environment_info()
        self.load_patterns()
        self.logger.info("EnvironmentManager initialized.")

    def get_config_file(self):
        return self._config_file

    def get_random_nameserver(self):
        if self.nameservers:
            return random.choice(self.nameservers)
        return None

    def update_logger(self):
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.INFO)
        self.logger.info("Logger updated based on verbosity.")

    def log_effective_configuration(self):
        self.logger.info("Effective Configuration: %s", vars(self.args))
        banner = """
░▒▓███████▓▒░░▒▓████████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░    ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓███████▓▒░░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░    ░▒▓█▓▒▒▓█▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓██▓▒░  ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░
        """
        print(banner)
        print("Effective Configuration:")
        for key, value in vars(self.args).items():
            print(f"{key:20}: {value}")

    def _populate_environment_info(self):
        external_ip = fetch_external_ip()
        self.environment_info = {
            "command_executed": " ".join(sys.argv),
            "external_ip": external_ip,
            "run_in_docker": os.path.exists("/.dockerenv"),
        }

    def save_environment_info(self):
        env_path = self.output_files["standard"]["environment"]
        with open(env_path, "w", encoding="utf-8") as f:
            json.dump(self.environment_info, f, indent=4)

    def load_patterns(self):
        try:
            with open(self._config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            self.patterns = config.get("domain_categorisation", {})
        except (IOError, json.JSONDecodeError):
            self.patterns = {}

    def set_domains(self):
        with open(self.domains_file, "r", encoding="utf-8") as f:
            raw_domains = f.read().splitlines()
        self.domains = set(self.clean_domains(raw_domains))

    def clean_domains(self, domains):
        return [d for d in domains if d and self.is_valid_domain(d)]

    @staticmethod
    def is_valid_domain(domain):
        regex = re.compile(
            r"^(?=.{1,253}$)"
            r"(?:(?!\d+$)[a-zA-Z\d]([a-zA-Z\d-]{0,61}[a-zA-Z\d])?\.)+"
            r"[a-zA-Z\d]([a-zA-Z\d-]{0,61}[a-zA-Z\d])?$"
        )
        return bool(regex.match(domain))

    def log_info(self, message, *args):
        self.logger.info(message, *args)

    def log_error(self, message, *args):
        self.logger.error(message, *args)
