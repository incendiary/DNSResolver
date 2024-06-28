"""
This Python module provides a collection of functions to perform various
network-related checks on a given server or host.

The checks available in this module are as follows:

1. `is_port_reachable(hostname, port, timeout=5)`: Checks if a port on a
specified host is reachable.

2. `take_screenshot(hostname, screenshot_dir, verbose=False)`: Takes a
screenshot of a website by its hostname and saves to a specified directory.

3. `check_ssl_tls_certificate(hostname, verbose)`: Checks the SSL/TLS
certificate for a given hostname across various ports.

4. `check_port_ssl_certificate(hostname, port, verbose)`: Verifies the SSL
certificate of a particular port on a given hostname.

5. `check_http_service(hostname, verbose)`: Checks the HTTP service for a
given hostname across different ports

6. `check_http_port(hostname, port, verbose=False)`: Checks if an HTTP
service is available and matches the given hostname on a specified port.

7. `perform_service_connectivity_checks(hostname, output_files, verbose,
extreme)`: Performs multiple service connectivity checks (SSL/TLS and HTTP)
 on a given hostname, and logs the results to specified output files.

In order to use these functions, one would need to import the required
modules and execute the appropriate function with the required parameters.
"""

import json
import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from selenium import webdriver


def is_port_reachable(hostname, port, timeout=5):
    """Check if a port on a specific host is reachable.

    :param hostname: The hostname or IP address of the remote host.
    :param port: The port number to check for reachability.
    :param timeout: The timeout (in seconds) for the connection attempt.
        Defaults to 5 seconds.
    :return: True if the port is reachable, False otherwise.
    """
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error):
        return False


def take_screenshot(hostname, screenshot_dir, verbose=False):
    """Takes a screenshot of a given hostname and saves it to the specified
    screenshot directory.

    :param hostname: The hostname of the website to take a screenshot
        of.
    :param screenshot_dir: The directory to save the screenshot in.
    :param verbose: (Optional) If True, prints additional information
        during execution. Defaults to False.
    :return: None
    """

    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=options)

        # List of URLs to check along with their respective ports
        urls_and_ports = [(f"http://{hostname}", 80), (f"https://{hostname}", 443)]

        for url, port in urls_and_ports:
            if is_port_reachable(hostname, port):
                try:
                    driver.set_page_load_timeout(10)
                    driver.get(url)
                    screenshot_path = os.path.join(
                        screenshot_dir, f"{hostname}_{url.split(':')[0]}.png"
                    )
                    driver.save_screenshot(screenshot_path)

                    if verbose:
                        print(f"Screenshot saved to {screenshot_path}")
                except Exception as e:
                    if verbose:
                        print(f"Failed to take screenshot of {hostname} at {url}: {e}")
            else:
                if verbose:
                    print(f"Port {port} on {hostname} is not reachable.")

        driver.quit()
    except Exception as e:
        if verbose:
            print(f"Failed to take screenshot of {hostname}: {e}")


def check_ssl_tls_certificate(hostname, verbose):
    """
    :param hostname: The hostname for which to check SSL/TLS certificates.
    :param verbose: Set to True if additional information should be printed
     during the check.
    :return: A dictionary containing the results of the SSL/TLS certificate
     check for each port. The keys are the ports, and the values are Boolean
    values indicating whether the certificate is valid or not.
    """
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print("Config file not found.")
        return False

    ssl_tls_ports = config["ssl_tls_ports"]

    results = {}
    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(check_port_ssl_certificate, hostname, port, verbose): port
            for port in ssl_tls_ports
        }

        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                results[port] = result
            except Exception as e:
                if verbose:
                    print(
                        f"Failed to verify SSL certificate for {hostname} on port {port}: {e}"
                    )
                results[port] = False

    return results


def check_port_ssl_certificate(hostname, port, verbose):
    """Check the SSL certificate of a given port on a specified hostname.

    :param hostname: The hostname of the server to check.
    :param port: The port number to check.
    :param verbose: If True, print verbose output. Default is False.
    :return: True if the SSL certificate is valid for the hostname and
        port, False otherwise.
    """
    if not is_port_reachable(hostname, port):
        if verbose:
            print(f"Port {port} on {hostname} is not reachable.")
        return False

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            sock.settimeout(5.0)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if verbose:
            print(f"Certificate for {hostname} on port {port}: {cert}")

        # Extract SANs
        san = cert.get("subjectAltName", ())
        dns_names = [entry[1] for entry in san if entry[0].lower() == "dns"]

        # Extract CN
        cn = next(
            (entry[0][1] for entry in cert["subject"] if entry[0][0] == "commonName"),
            None,
        )
        if cn:
            dns_names.append(cn)

        if verbose:
            print(
                f"DNS Names in certificate for {hostname} on port {port}: {dns_names}"
            )

        # Check if hostname matches any of the DNS names in the certificate
        for name in dns_names:
            if re.fullmatch(name.replace("*", "[^.]*"), hostname, re.IGNORECASE):
                if verbose:
                    print(
                        f"Hostname {hostname} matches DNS name {name} in "
                        f"certificate on port {port}."
                    )
                return True

        if verbose:
            print(
                f"Hostname {hostname} does not match any DNS names in the "
                f"certificate on port {port}."
            )
        return False

    except Exception as e:
        if verbose:
            print(
                f"Failed to verify SSL certificate for {hostname} on port {port}: {e}"
            )
        return False


def check_http_service(hostname, verbose):
    """Check HTTP service for a given hostname.

    :param hostname: The hostname to check.
    :param verbose: Whether to display verbose output.
    :return: A dictionary containing the results of the HTTP service
        check for each port.
    """
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print("Config file not found.")
        return False

    http_ports = config["http_ports"]

    results = {}
    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(check_http_port, hostname, port, verbose): port
            for port in http_ports
        }

        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                results[port] = result
            except Exception as e:
                if verbose:
                    print(
                        f"Failed to check HTTP service for {hostname} on port {port}: {e}"
                    )
                results[port] = False

    return results


def check_http_port(hostname, port, verbose=False):
    """Check if an HTTP service is available and matches the given hostname.

    :param hostname: The hostname or IP address of the server.
    :param port: The port number of the HTTP service.
    :param verbose: (Optional) If True, print detailed output. Default
        is False.
    :return: True if the HTTP service is available and matches the
        hostname, False otherwise.
    """
    url = f"http://{hostname}:{port}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            if hostname in response.text:
                if verbose:
                    print(
                        f"HTTP service on {hostname}:{port} is available and matches the hostname."
                    )
                return True
            else:
                if verbose:
                    print(
                        f"HTTP service on {hostname}:{port} is available but does not match the hostname."
                    )
                return False
        else:
            if verbose:
                print(
                    f"HTTP service on {hostname}:{port} returned status code {response.status_code}."
                )
            return False
    except requests.RequestException as e:
        if verbose:
            print(f"Failed to check HTTP service for {hostname} on port {port}: {e}")
        return False


def perform_service_connectivity_checks(hostname, output_files, verbose, extreme):
    """
    :param hostname: A string representing the hostname to perform connectivity checks on.
    :param output_files: A dictionary containing the output file paths.
        - "screenshot_dir": A string representing the directory path to save the screenshot.
        - "failures": A string representing the file path to save the failures.
    :param verbose: A boolean indicating whether to print detailed information during the checks.
    :param extreme: A boolean indicating whether to perform extreme checks.

    :return: None

    Performs service connectivity checks on the specified hostname. The method checks the SSL/TLS certificate
    and HTTP service for the hostname. If any failures are found in the certificate or HTTP service,
    a screenshot is taken and saved in the specified screenshot directory. If no failures are found,
    the hostname is appended to the failures file.

    Note: This method depends on the following helper methods:
    - check_ssl_tls_certificate(hostname, verbose): Checks the SSL/TLS certificate for the hostname and returns a dictionary of results.
    - check_http_service(hostname, verbose): Checks the HTTP service for the hostname and returns a dictionary of results.
    - take_screenshot(hostname, screenshot_dir, verbose): Takes a screenshot of the hostname and saves it in the specified directory.

    Example usage:
        perform_service_connectivity_checks("example.com", {"screenshot_dir": "/path/to/screenshots", "failures": "/path/to/failures.txt"}, True, False)
    """
    certificate_results = check_ssl_tls_certificate(hostname, verbose)
    http_results = check_http_service(hostname, verbose)

    if any(certificate_results.values()) or any(http_results.values()):
        take_screenshot(
            hostname, output_files["service_checks"]["screenshot_dir"], verbose
        )
    else:
        with open(
            output_files["service_checks"]["screenshot_failures"], "a", encoding="utf-8"
        ) as file:
            file.write(f"{hostname}\n")
            file.write("--------\n")
