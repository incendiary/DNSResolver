import asyncio
import json
import os
import platform
import re
import subprocess

import aiodns

# Define constants for DNS error codes
NXDOMAIN = 3
SERVFAIL = 2
NO_DATA = 1
TIMEOUT = 4
REFUSED = 5


class DNSHandler:
    def __init__(self, env_manager):
        self.env_manager = env_manager
        self.resolver = aiodns.DNSResolver()

    @staticmethod
    def is_dns_error_present(error, error_types):
        """
        Checks if a DNS error is of certain types.

        :param error: The occurred DNS error.
        :param error_types: A list of error types to check against.
        :return: Boolean value indicating if the error is of certain types.
        """
        return error.args[0] in error_types

    async def collect_evidence(self, domain, reason, output_files):
        """
        Collects DNS evidence using either nslookup or dig, depending on system availability.

        :param domain: The domain name to perform the DNS lookup for.
        :param reason: The reason for performing the DNS lookup.
        :param output_files: The output files configuration from the environment manager.
        :return: None
        """
        evidence_enabled = self.env_manager.get_evidence()
        if evidence_enabled:
            tasks = [
                self.perform_dns_evidence(
                    domain,
                    nameserver,
                    reason,
                    output_files["evidence"]["dns"],
                )
                for nameserver in self.env_manager.get_resolvers()
            ]

            await asyncio.gather(*tasks)

    async def check_ns_takeover(self, domain_context, domain):
        """
        Asynchronously check if the NS records for the given domain are pointing to nameservers
        that are not resolvable (potential nameserver takeover).

        :param domain_context: The domain context instance.
        :param domain: The domain to check.
        :return: True if potential nameserver takeover is detected, False otherwise.
        """
        original_domain = domain_context.get_domain()
        output_files = self.env_manager.get_output_files()

        try:
            ns_records = await self.resolver.query(domain, "NS")
            for ns in ns_records:
                ns_domain = str(ns.host).strip(".")
                try:
                    await self.resolver.query(ns_domain, "A")
                except aiodns.error.DNSError as e:
                    if self.is_dns_error_present(e, [NXDOMAIN, SERVFAIL]):
                        await self.env_manager.write_to_file(
                            output_files["standard"]["ns_takeover"],
                            f"{original_domain}|{domain}",
                        )
                        self.env_manager.log_info(
                            f"NS takeover possible for domain {domain}"
                        )

                        await self.collect_evidence(domain, "ns_takeover", output_files)

                        return True
        except aiodns.error.DNSError as e:
            if self.is_dns_error_present(e, [NXDOMAIN, SERVFAIL]):
                pass
        return False

    @staticmethod
    async def load_domain_categorisation_patterns(config_file="config.json"):
        """
        Load domain categorization patterns from the given config file.

        :param config_file: The path to the config file. Defaults to "config.json".
        :type config_file: str
        :return: A dictionary of domain categorization patterns.
        :rtype: dict
        """
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        return config.get("domain_categorization", {})

    @staticmethod
    def categorise_domain(domain, patterns):
        """
        Categorizes a domain based on a set of patterns.

        :param domain: The domain to categorize.
        :param patterns: A dictionary containing patterns to match against the domain.
        :return: A tuple containing the category, recommendation, and evidence link.
        """
        for category, pattern in patterns.items():
            if re.search(pattern["regex"], domain):
                return category, pattern["recommendation"], pattern["evidence"]
        return "unknown", "Unclassified", "N/A"

    @staticmethod
    async def is_dangling_record_async(resolver, domain, record_type):
        """
        Asynchronously checks if a specified DNS record for a given domain is a dangling record or not.

        :param resolver: The aiodns resolver instance.
        :param domain: The domain to check.
        :param record_type: The type of DNS record to check (e.g., A, AAAA, MX, NS).
        :return: True if the record is dangling, False otherwise.
        """
        try:
            await resolver.query(domain, record_type)
            return False
        except aiodns.error.DNSError as e:
            return DNSHandler.is_dns_error_present(e, [NXDOMAIN, SERVFAIL])

    @staticmethod
    def check_tools_availability():
        """
        Check the availability of nslookup and dig tools in the system path.

        :return: Tuple indicating the availability of nslookup and dig (nslookup_available, dig_available).
        """
        if platform.system() == "Windows":
            nslookup_available = (
                subprocess.run(
                    ["where", "nslookup"], capture_output=True, text=True
                ).returncode
                == 0
            )
            dig_available = (
                subprocess.run(
                    ["where", "dig"], capture_output=True, text=True
                ).returncode
                == 0
            )
        else:
            nslookup_available = (
                subprocess.run(
                    ["which", "nslookup"], capture_output=True, text=True
                ).returncode
                == 0
            )
            dig_available = (
                subprocess.run(
                    ["which", "dig"], capture_output=True, text=True
                ).returncode
                == 0
            )

        return nslookup_available, dig_available

    async def handle_domain_resolution_errors(
        self, domain_context, current_domain, error
    ):
        if self.is_dns_error_present(error, [NXDOMAIN]):
            self.env_manager.log_info(
                f"{current_domain} not found, checking for dangling CNAME."
            )
            if await self.handle_takeover_checks(domain_context, current_domain):
                return True, []
        elif self.is_dns_error_present(error, [SERVFAIL]):
            await self.log_and_write_dns_error(
                current_domain, error, "Could not contact DNS servers"
            )
        else:
            await self.log_and_write_dns_error(current_domain, error)
        return False, []

    async def handle_takeover_checks(self, domain_context, current_domain):
        is_dangling = await self.check_dangling_cname_async(
            domain_context, current_domain
        )
        is_nstakeover = await self.check_ns_takeover(domain_context, current_domain)
        if is_dangling or is_nstakeover:
            domain_context.add_dangling_domain_to_domains(current_domain)
        return is_dangling or is_nstakeover

    async def log_and_write_dns_error(self, domain, error, additional_message=""):
        message = f"DNS resolution error for {domain}: {error}"
        if additional_message:
            message += f"|{additional_message}"
        self.env_manager.log_error(message)
        await self.env_manager.write_to_file(
            self.env_manager.get_output_files()["standard"]["unresolved"],
            message,
        )

    async def resolve_domain_async(self, domain_context):
        """
        Asynchronously resolves a domain and returns a success status and the final IP addresses.

        :param domain_context: The domain context instance.
        :return: Tuple containing a boolean success status and a list of resolved IP addresses.
        """
        resolved_records = []
        current_domain = domain_context.get_domain()
        random_nameserver = self.env_manager.get_random_nameserver()
        if random_nameserver:
            self.resolver.nameservers = [random_nameserver]
            self.env_manager.log_info(
                f"Using nameserver {random_nameserver} for resolving {current_domain}"
            )
        try:
            answers = await self.resolver.query(current_domain, "A")
            final_ips = [answer.host for answer in answers]
            resolved_records.append(("A", final_ips))
            await self.handle_takeover_checks(domain_context, current_domain)
            return True, final_ips
        except aiodns.error.DNSError as e:
            return await self.handle_domain_resolution_errors(
                domain_context, current_domain, e
            )

    async def save_and_log_dns_result(
        self, result, domain, nameserver, reason, evidence_dir, command_name
    ):
        """
        Save and log the result of a DNS query command.

        :param result: The subprocess result object.
        :param domain: The domain name queried.
        :param nameserver: The nameserver used for the query.
        :param reason: The reason for performing the query.
        :param evidence_dir: The directory to save the evidence file.
        :param command_name: The name of the DNS query command (e.g., nslookup, dig).
        :return: None
        """
        stdout, stderr = await result.communicate()
        content = stdout.decode() + "\n" + stderr.decode()
        filename = os.path.join(evidence_dir, f"{domain}_{reason}_{nameserver}.txt")
        await self.env_manager.write_to_file(filename, content)
        self.env_manager.log_info(
            f"{command_name} result saved for domain {domain} using nameserver {nameserver}"
        )

    async def perform_nslookup(self, domain, nameserver, reason, evidence_dir):
        """
        Perform a DNS lookup using the nslookup command and save the output to a file.

        :param domain: The domain name to query.
        :param nameserver: The nameserver to use for the query.
        :param reason: The reason for performing the query.
        :param evidence_dir: The directory to save the evidence file.
        :return: None
        """
        try:
            result = await asyncio.create_subprocess_exec(
                "nslookup",
                domain,
                nameserver,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await self.save_and_log_dns_result(
                result, domain, nameserver, reason, evidence_dir, "nslookup"
            )
        except Exception as e:
            self.env_manager.log_error(f"Command failed with error: {e}")
            raise e from None

    async def perform_dig(self, domain, nameserver, reason, evidence_dir):
        """
        Perform a DNS lookup using the dig command and save the output to a file.

        :param domain: The domain name to query.
        :param nameserver: The nameserver to use for the query.
        :param reason: The reason for performing the query.
        :param evidence_dir: The directory to save the evidence file.
        :return: None
        """
        try:
            result = await asyncio.create_subprocess_exec(
                "dig",
                f"@{nameserver}",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await self.save_and_log_dns_result(
                result, domain, nameserver, reason, evidence_dir, "dig"
            )
        except Exception as e:
            self.env_manager.log_error(f"Command failed with error: {e}")
            raise e from None

    async def perform_dns_evidence(self, domain, nameserver, reason, evidence_dir):
        """
        Perform a DNS lookup using either nslookup or dig, depending on the system.

        :param domain: The domain name to perform the DNS lookup for.
        :param nameserver: The nameserver to use for the DNS lookup.
        :param reason: The reason for performing the DNS lookup.
        :param evidence_dir: The directory where the output file will be saved.
        :return: None
        """
        nslookup_available, dig_available = self.check_tools_availability()

        if platform.system() == "Windows":
            if nslookup_available:
                await self.perform_nslookup(domain, nameserver, reason, evidence_dir)
            else:
                self.env_manager.log_error(
                    f"nslookup not available on Windows system for domain {domain}"
                )
        else:
            if dig_available:
                await self.perform_dig(domain, nameserver, reason, evidence_dir)
            elif nslookup_available:
                await self.perform_nslookup(domain, nameserver, reason, evidence_dir)
            else:
                self.env_manager.log_error(
                    f"Neither dig nor nslookup available on non-Windows system for domain {domain}"
                )

    async def check_dangling_cname_async(self, domain_context, current_domain):
        """
        Asynchronously checks if a domain is a dangling CNAME, returning a boolean result.

        :param domain_context: The domain context instance.
        :param current_domain: The current domain to check.
        :return: True if the domain is a dangling CNAME, False otherwise.
        """
        original_domain = domain_context.get_domain()
        output_files = self.env_manager.get_output_files()

        random_nameserver = self.env_manager.get_random_nameserver()
        if random_nameserver:
            self.resolver.nameservers = [random_nameserver]
            self.env_manager.log_info(
                f"Using nameserver {random_nameserver} for resolving {current_domain}"
            )

        for record_type in ["A", "AAAA", "MX"]:
            if not await self.is_dangling_record_async(
                self.resolver, current_domain, record_type
            ):
                return False

        if not await self.is_dangling_record_async(self.resolver, current_domain, "NS"):
            await self.env_manager.write_to_file(
                output_files["standard"]["ns_takeover"],
                f"{original_domain}|{current_domain}",
            )
            self.env_manager.log_info(
                f"NS takeover possible for domain {current_domain}"
            )
            return False

        patterns = self.env_manager.get_patterns()
        category, recommendation, evidence_link = self.categorise_domain(
            current_domain, patterns
        )
        await self.env_manager.write_to_file(
            output_files["standard"]["dangling"],
            f"{original_domain}|{current_domain}|{category}|{recommendation}|{evidence_link}",
        )
        self.env_manager.log_info(
            f"Domain {current_domain} is a dangling CNAME with category: {category}"
        )

        await self.collect_evidence(current_domain, "dangling", output_files)

        return True
