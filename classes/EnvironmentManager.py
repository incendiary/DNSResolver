import argparse
import json
import os
import sys
from datetime import datetime

import requests
from requests import RequestException
import logging

from classes.Exceptions import (
    FileDoesNotExistError,
    NotAnIntegerError,
    InvalidNameserversError,
)


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
        self.args = None
        self.logger = setup_logger()
        self.domains_file = None
        self.output_dir = None
        self.verbose = None
        self.extreme = None
        self.nameservers = None
        self.service_checks = None
        self.max_threads = None
        self.timeout = None
        self.retries = None
        self.evidence = None
        self.output_files = None
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.environment_info = {
            "command_executed": None,
            "external_ip": None,
            "run_in_docker": None,
        }
        self.domains = None

        # Default Actions
        """# Get our arguments
        self.argument_parsing()
        # validate arguments
        self.validate_arguments()
        # Cross compare with config file arguments and resolve
        self.resolve_effective_configuration()
        # log the effective arguments
        self.log_effective_configuration()
        # Transfer the arguments to class attributes
        self.set_arguments()
        # Setup the environment
        self.initialise_environment()
        # save our environment json file for future reference
        self.save_environment_info()"""

        self.argument_parsing()
        self.validate_arguments()
        self.resolve_effective_configuration()
        self.log_effective_configuration()
        self.set_arguments()
        self.initialise_environment()
        self.save_environment_info()

    def argument_parsing(self):
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
            default="output",
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
            "--nameservers",
            type=str,
            help="Comma-separated list of custom nameservers. Overrides system resolvers.",
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
        self.args = parser.parse_args()

    def validate_arguments(self):
        try:
            if self.args.domains_file and not os.path.isfile(self.args.domains_file):
                raise FileDoesNotExistError(
                    f"Provided domains file does not exist: {self.args.domains_file}"
                )
            if self.args.max_threads and not isinstance(self.args.max_threads, int):
                raise NotAnIntegerError(
                    f"Provided max threads is not an integer: {self.args.max_threads}"
                )
            if self.args.timeout and not isinstance(self.args.timeout, int):
                raise NotAnIntegerError(
                    f"Provided timeout is not an integer: {self.args.timeout}"
                )
            if self.args.retries and not isinstance(self.args.retries, int):
                raise NotAnIntegerError(
                    f"Provided retries is not an integer: {self.args.retries}"
                )
            if self.args.nameservers and not all(
                isinstance(i, str) for i in self.args.nameservers.split(",")
            ):
                raise InvalidNameserversError(
                    f"Provided nameservers are not all strings: {self.args.nameservers}"
                )
        except Exception as e:
            self.logger.error(str(e))
            sys.exit(1)

    def resolve_effective_configuration(self):
        # This function prioritizes command line arguments, falling back to
        # config file values if corresponding CLI arguments are not set

        # Check if a config file is specified in the command line arguments
        if self.args.config_file:
            # Attempt to open and read the config file
            try:
                with open(self.args.config_file, "r", encoding="utf-8") as f:
                    try:
                        # Load the JSON data from the config file
                        self.config = json.load(f)
                    except json.JSONDecodeError as err:
                        # If an error occurs during JSON loading, log the error and assign
                        # an empty dictionary to self.config
                        self.logger.error(f"Error parsing JSON: {err}")
                        self.config = {}

            # Handle file opening errors
            except IOError as e:
                self.logger.error(f"Error opening file: {e}")
                self.config = {}

            # Retrieve the configuration parameters from the loaded configuration file.
            config_args = self.config.get("config", {})

            # Iterate over each item in the configuration data
            for key, value in config_args.items():
                # Check if the argument was provided as a command line argument.
                # If not, use the value from the configuration file.
                if getattr(self.args, key, None) is None:
                    setattr(self.args, key, value)

        # If the 'extreme' argument is provided, also set 'verbose' to True
        if self.args.extreme:
            self.args.verbose = True

    def log_effective_configuration(self):
        self.logger.info(f"Effective Configuration: {vars(self.args)}")
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

    def set_arguments(self):
        self.domains_file = self.args.domains_file
        self.output_dir = self.args.output_dir
        self.verbose = self.args.verbose
        self.extreme = self.args.extreme
        self.service_checks = self.args.service_checks
        self.max_threads = self.args.max_threads
        self.timeout = self.args.timeout
        self.retries = self.args.retries
        self.evidence = self.args.evidence
        if self.args.nameservers:
            self.nameservers = self.args.nameservers.split(",")

    def initialise_environment(self):

        self.output_dir = os.path.join(self.output_dir, self.timestamp)

        os.makedirs(self.output_dir, exist_ok=True)

        output_files = {
            "standard": {
                "resolved": os.path.join(
                    self.output_dir, f"resolution_results_{self.timestamp}.txt"
                ),
                "unresolved": os.path.join(
                    self.output_dir, f"unresolved_results_{self.timestamp}.txt"
                ),
                "gcp": os.path.join(
                    self.output_dir, f"gcp_results_{self.timestamp}.txt"
                ),
                "aws": os.path.join(
                    self.output_dir, f"aws_results_{self.timestamp}.txt"
                ),
                "azure": os.path.join(
                    self.output_dir, f"azure_results_{self.timestamp}.txt"
                ),
                "dangling": os.path.join(
                    self.output_dir,
                    f"dangling_cname_results_{self.timestamp}.txt",
                ),
                "ns_takeover": os.path.join(
                    self.output_dir, f"ns_takeover_results_{self.timestamp}.txt"
                ),
                "environment": os.path.join(
                    self.output_dir, f"environment_results_{self.timestamp}.json"
                ),
                "timeout": os.path.join(
                    self.output_dir, f"timeout_results_{self.timestamp}.txt"
                ),
            },
            "service_checks": {
                "ssl_tls_failure_file": os.path.join(
                    self.output_dir,
                    f"ssl_tls_failure_results_{self.timestamp}.txt",
                ),
                "http_failure_file": os.path.join(
                    self.output_dir, f"http_failure_results_{self.timestamp}.txt"
                ),
                "tcp_common_ports_unreachable_file": os.path.join(
                    self.output_dir,
                    f"tls_common_ports_unreachable_{self.timestamp}.txt",
                ),
                "screenshot_dir": os.path.join(
                    self.output_dir, f"evidence/screenshot_results_{self.timestamp}"
                ),
                "screenshot_failures": os.path.join(
                    self.output_dir, f"failure_results_{self.timestamp}.txt"
                ),
            },
        }

        if self.evidence:
            output_files["evidence"] = {
                "dig": os.path.join(self.output_dir, "evidence", "dig"),
            }

        self.output_files = output_files
        self.create_empty_files_or_directories()

    def save_environment_info(self):
        self.get_environment_info()
        with open(
            self.output_files["standard"]["environment"], "w", encoding="utf-8"
        ) as json_file:
            json_file.write(json.dumps(self.environment_info, indent=4))

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

        self.environment_info = environment_info

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

    def create_empty_files_or_directories(
        self,
    ):
        for key, value in self.output_files.get("standard", {}).items():
            self.create_empty_file_or_directory(value)

        if self.service_checks:
            for key, value in self.output_files.get("service_checks", {}).items():
                self.create_empty_file_or_directory(value)

        if "evidence" in self.output_files:
            for value in self.output_files["evidence"].values():
                self.create_empty_file_or_directory(value)

    def set_domains(self):
        with open(self.domains_file, "r", encoding="utf-8") as f:
            self.domains = f.read().splitlines()

    def log_info(self, message, *args):
        if self.logger:
            self.logger.info(message, *args)
        else:
            print(f"INFO: {message % args}")

    # Simple Getters and setters

    def get_output_files(self):
        return self.output_files

    def get_logger(self):
        return self.logger

    def get_domains(self):
        return self.domains

    def get_domains_file(self):
        return self.domains_file

    def set_domains_file(self, domains_file):
        self.domains_file = domains_file

    def get_output_dir(self):
        return self.output_dir

    def set_output_dir(self, output_dir):
        self.output_dir = output_dir

    def get_verbose(self):
        return self.verbose

    def set_verbose(self, verbose):
        self.verbose = verbose

    def get_extreme(self):
        return self.extreme

    def set_extreme(self, extreme):
        self.extreme = extreme

    def get_resolvers(self):
        return self.nameservers

    def set_resolvers(self, resolvers):
        self.nameservers = resolvers

    def get_service_checks(self):
        return self.service_checks

    def set_service_checks(self, service_checks):
        self.service_checks = service_checks

    def get_max_threads(self):
        return self.max_threads

    def set_max_threads(self, max_threads):
        self.max_threads = max_threads

    def get_timeout(self):
        return self.timeout

    def set_timeout(self, timeout):
        self.timeout = timeout

    def get_retries(self):
        return self.retries

    def set_retries(self, retries):
        self.retries = retries

    def get_evidence(self):
        return self.evidence

    def set_evidence(self, evidence):
        self.evidence = evidence

    def get_timestamp(self):
        return self.timestamp

    def set_timestamp(self, timestamp):
        self.timestamp = timestamp
