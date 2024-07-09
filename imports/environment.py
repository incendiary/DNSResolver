"""
This module provides utility functions for retrieving environment information
and file management.

Functions:
---------
- get_environment_info: Gathers and returns information about the current
environment basis.
  It returns the command executed, an indication of whether the script runs
  in a docker environment,
  and the external IP address of the machine.

- create_empty_files: Takes a dictionary with file names as keys and their
corresponding paths as values.
  It uses this information to create empty files at the specified locations.

- create_empty_file: Creates an empty file at the specified filename.
"""

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


def parse_arguments():
    """
    Parse command line arguments.

    :return: argparse.Namespace containing the parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Resolve DNS records for domains and check against cloud provider IP ranges."
    )
    parser.add_argument(
        "domains_file",
        type=str,
        help="Path to the file containing domains (one per line)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="output",
        help="Directory to save output files (default: output)",
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
        default=False,
        help="Perform Service Checks",
    )
    parser.add_argument(
        "--max-threads",
        "-mt",
        type=int,
        help="Max number of threads to use for domain processing (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=int,
        default=10,  # default timeout in seconds
        help="Timeout for DNS resolution process in seconds",
    )
    parser.add_argument(
        "--retries", type=int, default=3, help="Number of retry attempts for timeouts"
    )
    parser.add_argument(
        "--evidence",
        action="store_true",
        help="Enable evidence collection for DNS queries",
    )

    args = parser.parse_args()
    # If extreme is set, set verbose as well
    if args.extreme:
        args.verbose = True
    return args


def get_environment_info():
    """
    Returns information about the current environment.

    :return: A dictionary containing the following information:
             - command_executed: The command executed to run the script.
             - external_ip: The external IP address.
             - run_in_docker: Boolean value indicating if the script is running inside a Docker container.
    """
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


def create_empty_file_or_directory(filename, logger):
    """
    Create an empty file or directory.

    :param filename: A string representing the filename or directory path.
    :type filename: str
    :param logger: Logger instance for logging errors.
    :raises ValueError: If the provided filename is not a string.
    """
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
        logger.error(f"Unable to create file or directory {filename}. Error: {e}")


def create_empty_files_or_directories(output_files, perform_service_checks, logger):
    """
    :param output_files: A dictionary containing the paths of the output files or directories. It should have the
    following structure:
    :param perform_service_checks: A boolean value indicating whether service checks should be performed or not.
    :param logger: Logger instance for logging errors.
    :return: None

    This function creates empty files or directories based on the provided output file paths. It loops through the
    "standard" paths first and creates empty files or directories using the corresponding values.
    If perform_service_checks is True, it then loops through the "service_checks" paths and creates
    empty files or directories. Finally, if "evidence" is present in output_files, it loops through the
     "evidence" paths and creates empty files or directories.
    """
    for key, value in output_files.get("standard", {}).items():
        create_empty_file_or_directory(value, logger)

    if perform_service_checks:
        for key, value in output_files.get("service_checks", {}).items():
            create_empty_file_or_directory(value, logger)

    if "evidence" in output_files:
        for value in output_files["evidence"].values():
            create_empty_file_or_directory(value, logger)


def initialize_environment(
    output_dir, perform_service_checks, evidence_enabled, logger
):
    """ """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(output_dir, timestamp)
    os.makedirs(output_dir, exist_ok=True)

    output_files = {
        "standard": {
            "resolved": os.path.join(output_dir, f"resolution_results_{timestamp}.txt"),
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

    if evidence_enabled:
        output_files["evidence"] = {
            "dig": os.path.join(output_dir, "evidence", "dig"),
        }

    create_empty_files_or_directories(output_files, perform_service_checks, logger)
    return timestamp, output_dir, output_files


def save_environment_info(environment_file, environment_info):
    """
    Save Environment Info

    This method is used to save the environment information to a JSON file.

    :param environment_file: The file path where the environment information will be saved.
    :type environment_file: str

    :param environment_info: The environment information that needs to be saved.
    :type environment_info: dict

    :return: None

    """
    with open(environment_file, "w", encoding="utf-8") as json_file:
        json_file.write(json.dumps(environment_info, indent=4))


def read_domains(domains_file):
    """
    Read the domain names"""
    with open(domains_file, "r", encoding="utf-8") as f:
        return f.read().splitlines()
