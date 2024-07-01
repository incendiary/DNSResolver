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

import os
import sys
import argparse

import requests
from requests import RequestException


def parse_arguments():
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

    args = parser.parse_args()
    # If extreme is set, set verbose as well
    if args.extreme:
        args.verbose = True
    return args


def get_environment_info():
    """
    Returns information about the current environment.

    :return: a dictionary containing the following information:
             - command_executed: a string representing the command
                executed to run the script
             - external_ip: a string representing the external IP
                address of the current machine
             - run_in_docker: a boolean indicating whether the
                script is running inside a Docker container
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


def create_empty_files_or_directories(output_files, perform_service_checks):
    """
    Create empty files or directories.

    :param output_files: A dictionary containing file names as keys
        and their corresponding paths as values.
    :type output_files: dict
    :param perform_service_checks: A boolean indicating whether to create
        service check related files.
    :type perform_service_checks: bool
    :return: None
    """
    # Create standard files or directories
    for key, value in output_files.get("standard", {}).items():
        create_empty_file_or_directory(value)

    # Create service check files or directories if perform_service_checks is True
    if perform_service_checks:
        for key, value in output_files.get("service_checks", {}).items():
            create_empty_file_or_directory(value)


def create_empty_file_or_directory(filename):
    """
    Create an empty file or directory with the given filename.
    If filename has extension (e.g.txt), file will be created;
    otherwise a directory will be created.
    :param filename: The name of the file or directory to create.
    :type filename: str
    :return: None
    """
    if not isinstance(filename, str):
        raise ValueError("filename must be a string")

    name, extension = os.path.splitext(filename)

    try:
        if not extension:
            os.mkdir(filename)
        else:
            with open(filename, "w", encoding="utf-8") as f:
                pass
    except (IOError, OSError) as e:
        print(f"Unable to create file or directory {filename}. Error: {e}")
