import asyncio
import json
import re

import aiodns
import dns.resolver
import dns.exception

from classes.evidence_collector import EvidenceCollector

# Define constants for DNS error codes
NXDOMAIN = 3
SERVFAIL = 2
NO_DATA = 1
TIMEOUT = 4
REFUSED = 5


class DNSHandler:
    def __init__(self, env_manager):
        self.env_manager = env_manager
        self.aiodns_resolver = aiodns.DNSResolver()
        self.dnspython_resolver = dns.resolver.Resolver()
        self.evidence_collector = EvidenceCollector(env_manager)

        random_nameserver = self.env_manager.get_random_nameserver()
        if random_nameserver:
            self.aiodns_resolver.nameservers = [random_nameserver]
            self.dnspython_resolver.nameservers = [random_nameserver]

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
                self.evidence_collector.perform_dns_evidence(
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

        self.env_manager.log_info(f"Checking NS takeover for domain: {domain}")

        try:
            ns_records = await self.aiodns_resolver.query(domain, "NS")
            for ns in ns_records:
                ns_domain = str(ns.host).strip(".")
                self.env_manager.log_info(f"NS record found: {ns_domain}")
                try:
                    await self.aiodns_resolver.query(ns_domain, "A")
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
            self.env_manager.log_info(f"Error querying NS records for {domain}: {e}")
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

    async def is_dangling_record_async(self, domain, record_type):
        """
        Asynchronously checks if a specified DNS record for a given domain is a dangling record or not.

        :param domain: The domain to check.
        :param record_type: The type of DNS record to check (e.g., A, AAAA, MX, NS).
        :return: True if the record is dangling, False otherwise.
        """
        try:
            await self.aiodns_resolver.query(domain, record_type)
            self.env_manager.log_info(
                f"Domain {domain} has a valid {record_type} record."
            )
            return False
        except aiodns.error.DNSError as e:
            self.env_manager.log_info(f"Error querying {record_type} for {domain}: {e}")
            return self.is_dns_error_present(e, [NXDOMAIN, SERVFAIL])

    async def handle_domain_resolution_errors(
        self, domain_context, current_domain, error, final_retry
    ):
        """
        Handle domain resolution errors.

        :param domain_context: The domain context instance.
        :param current_domain: The current domain being processed.
        :param error: The DNS error that occurred.
        :param final_retry: Whether this is the final retry.
        :return: Tuple containing a boolean success status and a list of resolved IP addresses.
        """

        self.env_manager.log_info(
            f"Handling DNS error for {current_domain}: {error} | final_retry={final_retry}"
        )

        if self.is_dns_error_present(error, [NXDOMAIN]):
            self.env_manager.log_info(
                f"{current_domain} not found, checking for dangling CNAME."
            )
            if await self.handle_takeover_checks(domain_context, current_domain):
                return True, []

        if final_retry:
            if self.is_dns_error_present(error, [SERVFAIL]):
                await self.log_and_write_dns_error(
                    current_domain, error, "Could not contact DNS servers"
                )
            else:
                await self.log_and_write_dns_error(current_domain, error)
            self.env_manager.log_error(
                f"DNS resolution error for {current_domain}: {error} | final_retry={final_retry}"
            )

        # Use dnspython_resolver for better error handling
        try:
            self.dnspython_resolver.resolve(current_domain, "A")
            self.env_manager.log_info(
                f"Domain {current_domain} resolved successfully with dnspython_resolver."
            )
            return True, []
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
        ) as e:
            self.env_manager.log_info(
                f"DNS error with dnspython_resolver for {current_domain}: {e}"
            )
            if isinstance(e, dns.resolver.NXDOMAIN):
                self.env_manager.log_info(
                    f"{current_domain} not found, checking for dangling CNAME."
                )
                if await self.handle_takeover_checks(domain_context, current_domain):
                    return True, []

        return False, []

    async def handle_takeover_checks(self, domain_context, current_domain):
        self.env_manager.log_info(
            f"Running takeover checks for domain: {current_domain}"
        )

        is_dangling = await self.check_dangling_cname_async(
            domain_context, current_domain
        )
        self.env_manager.log_info(
            f"Dangling CNAME check for {current_domain}: {is_dangling}"
        )

        is_nstakeover = await self.check_ns_takeover(domain_context, current_domain)
        self.env_manager.log_info(
            f"NS takeover check for {current_domain}: {is_nstakeover}"
        )

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
        retries = self.env_manager.get_retries()

        self.env_manager.log_info(
            f"Starting DNS resolution for {current_domain} with {retries + 1} attempts."
        )

        for attempt in range(retries + 1):
            self.env_manager.log_info(
                f"Attempt {attempt + 1} for resolving {current_domain}"
            )

            try:
                answers = await self.aiodns_resolver.query(current_domain, "A")
                final_ips = [answer.host for answer in answers]
                resolved_records.append(("A", final_ips))
                self.env_manager.log_info(
                    f"Successfully resolved {current_domain} to {final_ips}"
                )
                await self.handle_takeover_checks(domain_context, current_domain)
                return True, final_ips
            except aiodns.error.DNSError as e:
                self.env_manager.log_info(
                    f"DNS error on attempt {attempt + 1} of {retries + 1} for {current_domain}: {e}"
                )
                final_retry = attempt == retries
                await self.handle_domain_resolution_errors(
                    domain_context, current_domain, e, final_retry
                )
                if final_retry:
                    self.env_manager.log_info(
                        f"Failed to resolve {current_domain} after {retries + 1} attempts."
                    )
                    return False, []

        return False, []

    async def check_dangling_cname_async(self, domain_context, current_domain):
        """
        Asynchronously checks if a domain is a dangling CNAME, returning a boolean result.

        :param domain_context: The domain context instance.
        :param current_domain: The current domain to check.
        :return: True if the domain is a dangling CNAME, False otherwise.
        """
        original_domain = domain_context.get_domain()
        output_files = self.env_manager.get_output_files()

        self.env_manager.log_info(
            f"Checking for dangling CNAME for domain: {current_domain}"
        )

        # Check if the domain is a CNAME
        try:
            cname_answer = await self.aiodns_resolver.query(current_domain, "CNAME")
            self.env_manager.log_info(
                f"CNAME query response for {current_domain}: {cname_answer}"
            )
            if cname_answer:
                self.env_manager.log_info(f"Domain {current_domain} is a CNAME record.")
                target = cname_answer.cname
                self.env_manager.log_info(f"CNAME target: {target}")
                if await self.check_dangling_cname_async(domain_context, target):
                    return True
        except aiodns.error.DNSError as e:
            self.env_manager.log_info(f"Error querying CNAME for {current_domain}: {e}")
            if not self.is_dns_error_present(e, [NXDOMAIN]):
                return False

        # Check for dangling A, AAAA, MX records
        for record_type in ["A", "AAAA", "MX"]:
            try:
                self.dnspython_resolver.resolve(current_domain, record_type)
                self.env_manager.log_info(
                    f"Domain {current_domain} has a valid {record_type} record."
                )
                return False
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.exception.Timeout,
            ) as e:
                self.env_manager.log_info(
                    f"Error querying {record_type} for {current_domain}: {e}"
                )
                if isinstance(e, dns.resolver.NoAnswer):
                    continue
                if isinstance(e, dns.exception.Timeout):
                    return False

        # Check NS records for original domain
        try:
            self.dnspython_resolver.resolve(original_domain, "NS")
            await self.env_manager.write_to_file(
                output_files["standard"]["ns_takeover"],
                f"{original_domain}|{current_domain}",
            )
            self.env_manager.log_info(
                f"NS takeover possible for domain {current_domain}"
            )
            return False
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
        ) as e:
            self.env_manager.log_info(f"Error querying NS for {original_domain}: {e}")
            if isinstance(e, dns.resolver.NoAnswer):
                pass

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
