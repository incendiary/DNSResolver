import os
import socket
import requests
import json
import sys

from requests import RequestException


def get_environment_info():
    command_executed = " ".join(sys.argv)
    internal_ip = socket.gethostbyname(socket.gethostname())
    running_in_docker = os.path.exists("/.dockerenv")

    try:
        response = requests.get("https://ifconfig.io/ip")
        external_ip = response.text.strip()
    except RequestException as error:
        external_ip = (
            f"An error occurred while trying to retrieve the external ip: {error}"
        )

    environment_info = {
        "command_executed": command_executed,
        "internal_ip": internal_ip,
        "external_ip": external_ip,
        "run_in_docker": running_in_docker,
    }

    return environment_info


def create_empty_files(output_files):
    for key, value in output_files.items():
        create_empty_file(value)


def create_empty_file(filename):
    with open(filename, "w") as f:
        pass
