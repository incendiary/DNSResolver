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

import sys
import os
import requests
from requests import RequestException


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


def create_empty_files(output_files):
    """
    Create empty files.

    :param output_files: a dictionary containing file names as keys
        and their corresponding paths as values
    :type output_files: dict
    :return: None
    """
    for key, value in output_files.items():
        create_empty_file(value)


def create_empty_file(filename):
    """
    Create an empty file with the given filename.

    :param filename: The name of the file to create.
    :type filename: str
    :return: None
    """
    if not isinstance(filename, str):
        raise ValueError("filename must be a string")
    try:
        with open(filename, "w", encoding="utf-8") as f:
            pass
    except IOError as e:
        print(f"Unable to create file {filename}. Error: {e}")
