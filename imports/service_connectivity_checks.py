"""
Provides service connectivity checks
"""

import json
import socket
import ssl
import re


def check_ssl_certificate(hostname, verbose=False):
    """
    Check if the SSL certificate of the hostname has a matching SAN/CN/DN on the given ports.

    :param hostname: The hostname to check.
    :param verbose: Whether to print debug information.
    :return: Dictionary with port as key and True/False indicating certificate match.
    """

    try:
        with open("config.json", "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print("Config file not found.")
        return False

    ssl_tls_ports = config["ssl_tls_ports"]

    results = {}
    for port in ssl_tls_ports:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            if verbose:
                print(f"Certificate for {hostname} on port {port}: {cert}")

            # Extract SANs
            san = cert.get("subjectAltName", ())
            dns_names = [entry[1] for entry in san if entry[0].lower() == "dns"]

            # Extract CN
            cn = next(
                (
                    entry[0][1]
                    for entry in cert["subject"]
                    if entry[0][0] == "commonName"
                ),
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
                            f"Hostname {hostname} matches DNS name {name} in certificate on port {port}."
                        )
                    results[port] = True
                    break
            else:
                results[port] = False

            if verbose and not results[port]:
                print(
                    f"Hostname {hostname} does not match any DNS names in the certificate on port {port}."
                )

        except Exception as e:
            if verbose:
                print(
                    f"Failed to verify SSL certificate for {hostname} on port {port}: {e}"
                )
            results[port] = False

    return results
