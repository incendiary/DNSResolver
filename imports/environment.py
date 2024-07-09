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


def parse_arguments():
    """
    Parses the command line arguments for the script.

    :return: The parsed command line arguments.
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

    args = parser.parse_args()
    # If extreme is set, set verbose as well
    if args.extreme:
        args.verbose = True
    return args


def get_environment_info():
    """
    Get information about the current environment.

    :return: A dictionary containing the following information:
        * command_executed (str) - The command executed to run the script.
        * external_ip (str) - The external IP address of the machine running the script.
        * run_in_docker (bool) - True if script is running in a Docker container, False otherwise.
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
    .. function:: create_empty_files_or_directories(output_files, perform_service_checks)
       :param output_files: A dictionary containing the paths of the files or directories to be created. The keys are the types of files ("standard" or "service_checks"), and the values are dictionaries with the filenames as keys and the file paths as values.
       :param perform_service_checks: A boolean indicating whether to create service check files or directories.
       :return: None

       This function takes a dictionary of file paths and creates empty files or directories based on the specified paths. It first creates standard files or directories by iterating over the items in the "standard" key of the output_files dictionary. Then, if perform_service_checks is True, it creates service check files or directories by iterating over the items in the "service_checks" key of the output_files dictionary.

       Example usage:

       .. code-block:: python

          output_files = {
             "standard": {
                "file1": "/path/to/file1",
                "file2": "/path/to/file2"
             },
             "service_checks": {
                "file3": "/path/to/file3",
                "file4": "/path/to/file4"
             }
          }
          perform_service_checks = True

          create_empty_files_or_directories(output_files, perform_service_checks)
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
    Create an empty file or directory.

    :param filename: The name of the file or directory to be created.
    :return: None

    Raises:
        ValueError: If the `filename` is not a string.
        IOError: If an input/output error occurs while creating the file or directory.
        OSError: If an operating system error occurs while creating the file or directory.
    """
    if not isinstance(filename, str):
        raise ValueError("filename must be a string")

    name, extension = os.path.splitext(filename)

    try:
        if not extension:
            os.mkdir(filename)
        else:
            with open(filename, "w", encoding="utf-8"):
                pass
    except (IOError, OSError) as e:
        print(f"Unable to create file or directory {filename}. Error: {e}")


def initialize_environment(output_dir, perform_service_checks):
    """
    Initialize the environment for the tool.

    :param output_dir: The directory where the output files will be stored.
    :param perform_service_checks: Flag indicating whether to perform service checks or not.
    :return: A tuple containing the timestamp, output directory, and a dictionary of output files.

    The output directory will be created with the current timestamp appended to it.
    The output files dictionary will contain paths to different types of output files.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(output_dir, timestamp)
    os.makedirs(output_dir, exist_ok=True)

    # Output files
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

    create_empty_files_or_directories(output_files, perform_service_checks)
    return timestamp, output_dir, output_files


def save_environment_info(environment_file, environment_info):
    """
    Save environment information to a JSON file.

    :param environment_file: Path to the JSON file to be saved.
    :param environment_info: Dictionary containing the environment information to be saved.
    :return: None
    """
    with open(environment_file, "w", encoding="utf-8") as json_file:
        json_file.write(json.dumps(environment_info, indent=4))


def read_domains(domains_file):
    """
    Reads a text file containing a list of domains and returns a list of domain names.

    :param domains_file: The path to the text file containing domain names.
    :return: A list of domain names read from the file.
    """
    with open(domains_file, "r", encoding="utf-8") as f:
        return f.read().splitlines()
