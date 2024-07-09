import argparse
import json
import os
import sys
from datetime import datetime
import requests
from requests import RequestException
import logging


def setup_logger():
    logger = logging.getLogger("DNSResolver")
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler("dns_resolver.log")
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


class EnvironmentManager:
    def __init__(self):
        self.config = {}
        self.logger = self.setup_logger()
        self.domains_file = None
        self.output_dir = None
        self.verbose = None
        self.extreme = None
        self.resolvers = None
        self.service_checks = None
        self.max_threads = None
        self.timeout = None
        self.retries = None
        self.evidence = None

    def setup_logger(self):
        logger = logging.getLogger("DNSResolver")
        logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler("dns_resolver.log")
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger

    def get_logger(self):
        return self.logger

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description="Resolve DNS records for domains and check against cloud provider IP ranges."
        )
        parser.add_argument(
            "domains_file",
            type=str,
            help="Path to the file containing domains (one per line)",
        )
        parser.add_argument(
            "--config-file",
            type=str,
            default=None,
            help="Path to the configuration file (default: None)",
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
            "--resolvers",
            "-r",
            type=str,
            help="Comma-separated list of custom resolvers. Overrides system resolvers.",
        )
        parser.add_argument(
            "--service-checks",
            "-sc",
            action="store_true",
            help="Perform Service Checks (overrides config file)",
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

        args = parser.parse_args()

        if args.config_file:
            with open(args.config_file, "r", encoding="utf-8") as f:
                self.config = json.load(f)

            config_args = self.config.get("config", {})
            for key, value in config_args.items():
                if getattr(args, key, None) is None:
                    setattr(args, key, value)

        # If extreme is set, set verbose as well
        if args.extreme:
            args.verbose = True

        self.log_effective_configuration(args)
        self.set_arguments(args)

    def log_effective_configuration(self, args):
        self.logger.info(f"Effective Configuration: {vars(args)}")
        print(f"Effective Configuration: {vars(args)}")

    def set_arguments(self, args):
        self.domains_file = args.domains_file
        self.output_dir = args.output_dir
        self.verbose = args.verbose
        self.extreme = args.extreme
        self.resolvers = args.resolvers
        self.service_checks = args.service_checks
        self.max_threads = args.max_threads
        self.timeout = args.timeout
        self.retries = args.retries
        self.evidence = args.evidence

    def get_environment_info(self):
        command_executed = " ".join(sys.argv)
        running_in_docker = os.path.exists("/.dockerenv")

        try:
            response = requests.get("https://ifconfig.io/ip", timeout=10)
            external_ip = response.text.strip()
        except RequestException as error:
            external_ip = (
                f"An error occurred while trying to retrieve the external ip: {error}"
            )

        environment_info = {
            "command_executed": command_executed,
            "external_ip": external_ip,
            "run_in_docker": running_in_docker,
        }

        return environment_info

    def create_empty_file_or_directory(self, filename):
        if not isinstance(filename, str):
            raise ValueError("filename must be a string")

        name, extension = os.path.splitext(filename)

        try:
            if not extension:
                os.makedirs(filename, exist_ok=True)
            else:
                with open(filename, "w", encoding="utf-8"):
                    pass
        except (IOError, OSError) as e:
            self.logger.error(
                f"Unable to create file or directory {filename}. Error: {e}"
            )

    def create_empty_files_or_directories(self, output_files, perform_service_checks):
        for key, value in output_files.get("standard", {}).items():
            self.create_empty_file_or_directory(value)

        if perform_service_checks:
            for key, value in output_files.get("service_checks", {}).items():
                self.create_empty_file_or_directory(value)

        if "evidence" in output_files:
            for value in output_files["evidence"].values():
                self.create_empty_file_or_directory(value)

    def initialize_environment(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(self.output_dir, timestamp)
        os.makedirs(output_dir, exist_ok=True)

        output_files = {
            "standard": {
                "resolved": os.path.join(
                    output_dir, f"resolution_results_{timestamp}.txt"
                ),
                "unresolved": os.path.join(
                    output_dir, f"unresolved_results_{timestamp}.txt"
                ),
                "gcp": os.path.join(output_dir, f"gcp_results_{timestamp}.txt"),
                "aws": os.path.join(output_dir, f"aws_results_{timestamp}.txt"),
                "azure": os.path.join(output_dir, f"azure_results_{timestamp}.txt"),
                "dangling": os.path.join(
                    output_dir, f"dangling_cname_results_{timestamp}.txt"
                ),
                "ns_takeover": os.path.join(
                    output_dir, f"ns_takeover_results_{timestamp}.txt"
                ),
                "environment": os.path.join(
                    output_dir, f"environment_results_{timestamp}.json"
                ),
                "timeout": os.path.join(output_dir, f"timeout_results_{timestamp}.txt"),
            },
            "service_checks": {
                "ssl_tls_failure_file": os.path.join(
                    output_dir, f"ssl_tls_failure_results_{timestamp}.txt"
                ),
                "http_failure_file": os.path.join(
                    output_dir, f"http_failure_results_{timestamp}.txt"
                ),
                "tcp_common_ports_unreachable_file": os.path.join(
                    output_dir, f"tls_common_ports_unreachable_{timestamp}.txt"
                ),
                "screenshot_dir": os.path.join(
                    output_dir, f"screenshot_results_{timestamp}"
                ),
                "screenshot_failures": os.path.join(
                    output_dir, f"failure_results_{timestamp}.txt"
                ),
            },
        }

        if self.evidence:
            output_files["evidence"] = {
                "dig": os.path.join(output_dir, "evidence", "dig"),
            }

        self.create_empty_files_or_directories(output_files, self.service_checks)
        return timestamp, output_dir, output_files

    def save_environment_info(self, environment_file, environment_info):
        with open(environment_file, "w", encoding="utf-8") as json_file:
            json_file.write(json.dumps(environment_info, indent=4))

    def read_domains(self, domains_file):
        with open(domains_file, "r", encoding="utf-8") as f:
            return f.read().splitlines()
