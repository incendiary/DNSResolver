"""
This module contains the DomainProcessingContext class.

This class provides a contextual environment for domain processing activities,
including DNS resolution, pattern matching, and handling different cloud platforms.
It provides tunable parameters and methods to manage the domain processing workflow.
"""

import dns.resolver


class DomainProcessingContext:
    """
    Class representing the context for domain processing.

    Attributes:
        resolver (dns.resolver.Resolver): DNS resolver object.
        domain: The root domain to which this context applies.
        current_domain: The current domain being processed.
        nameservers: List of nameservers for DNS resolution.
        output_files: List of output files to write the results to.
        verbose: Flag indicating the status of verbose mode.
        extreme: Flag indicating the status of extreme mode.
        gcp_ipv4: Google Cloud Platform IPv4 address.
        gcp_ipv6: Google Cloud Platform IPv6 address.
        aws_ipv4: Amazon Web Services IPv4 address.
        aws_ipv6: Amazon Web Services IPv6 address.
        azure_ipv4: Microsoft Azure IPv4 address.
        azure_ipv6: Microsoft Azure IPv6 address.
        perform_service_checks: Flag indicating the status of service checks.
        timeout: DNS resolution timeout value.
        retries: Number of retries for DNS resolution.
        patterns: List of domain name matching patterns.
        dangling_domains: Set of discovered dangling domains.
        failed_domains: Set of failed domains.
        evidence_enabled: Flag indicating the status of evidence collection.
        logger: The logger object.

    Methods:
        create_resolver: Create and configure a DNS resolver object.
        log_info: Log an info message or print to stdout if logger is not available.
        get_resolver: Retrieve the DNS resolver.
        get_domain: Get the root domain to which this context applies.
        set_domain: Set the root domain to which this context applies.
        get_current_domain: Retrieve the current domain being processed.
        set_current_domain: Set the current domain to be processed.
        get_nameservers: Get the list of nameservers for DNS resolution.
        set_nameservers: Set the list of nameservers for DNS resolution.
        get_output_files: Get the list of output files to write the results to.
        set_output_files: Set the list of output files to write the results to.
        get_verbose: Get the status of verbose mode.
        set_verbose: Set the status of verbose mode.
        get_extreme: Get the status of extreme mode.
        set_extreme: Set the status of extreme mode.
        set_gcp_ip: Set both IPv4 and IPv6 addresses of Google Cloud Platform.
        get_gcp_ipv6: Retrieve the Google Cloud Platform IPv6 address.
        get_aws_ipv4: Get the Amazon Web Services IPv4 address.
        set_aws_ip: Set both IPv4 and IPv6 addresses of Amazon Web Services.
        get_aws_ipv6: Get the Amazon Web Services IPv6 address.
        get_azure_ipv4: Get the Microsoft Azure IPv4 address.
        set_azure_ip: Set both IPv4 and IPv6 addresses of Microsoft Azure.
        get_azure_ipv6: Get the Microsoft Azure IPv6 address.
        set_azure_ipv6: Sets the Azure IPv6.
        get_perform_service_checks: Get the status of service checks.
        set_perform_service_checks: Sets the status of service checks.
        get_timeout: Get the DNS resolution timeout value.
        set_timeout: Set the DNS resolution timeout value.
        get_retries: Get the number of retries for DNS resolution.
        set_retries: Set the number of retries for DNS resolution.
        get_patterns: Get the list of domain name matching patterns.
        set_patterns: Set the domain name matching patterns.
        get_dangling_domains: Get the set of discovered dangling domains.
        set_dangling_domains: Set the set of discovered dangling domains.
        add_dangling_domain_to_domains: Add a dangling domain to the set of
            dangling domains.
        get_failed_domains: Get the set of failed domains.
        set_failed_domains: Set the set of failed domains.
        get_evidence_enabled: Get the status of evidence collection.
        set_evidence_enabled: Set the status of evidence collection.
        get_logger: Get the logger object.
        set_logger: Set the logger object.
    """

    def __init__(self, env_manager):
        """Initialize DomainProcessingContext instance."""
        self.nameservers = None
        self.output_files = None
        self.verbose = False
        self.extreme = False
        self.gcp_ipv4 = None
        self.gcp_ipv6 = None
        self.aws_ipv4 = None
        self.aws_ipv6 = None
        self.azure_ipv4 = None
        self.azure_ipv6 = None
        self.perform_service_checks = False
        self.timeout = None
        self.retries = None
        self.patterns = None
        self.dangling_domains = None
        self.failed_domains = None
        self.evidence_enabled = False
        self.logger = env_manager.get_logger()
        self.resolver = None
        self.domain = None
        self.current_domain = None

    def create_resolver(self):
        """Create and configure a DNS resolver object."""
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = self.timeout
        self.resolver.timeout = self.timeout
        if self.nameservers:
            self.resolver.nameservers = self.nameservers

    def log_info(self, message, *args):
        """Log an info message or print to stdout if logger is not available."""
        if self.logger:
            self.logger.info(message, *args)
        else:
            print(f"INFO: {message % args}")

    def get_resolver(self):
        """Retrieve DNS resolver."""
        return self.resolver

    def get_domain(self):
        """Get root Domain to which this context applies."""
        return self.domain

    def set_domain(self, domain):
        """Set root Domain to which this context applies."""
        self.domain = domain

    def get_current_domain(self):
        """Retrieve the current Domain being processed."""
        return self.current_domain

    def set_current_domain(self, domain):
        """Set current Domain to be processed."""
        self.current_domain = domain

    def get_nameservers(self):
        """Get list of nameservers for DNS resolution."""
        return self.nameservers

    def set_nameservers(self, nameservers):
        """Set list of nameservers for DNS resolution."""
        self.nameservers = nameservers

    def get_output_files(self):
        """Get list of output files to write the results to."""
        return self.output_files

    def set_output_files(self, output_files):
        """Set list of output files to write the results to."""
        self.output_files = output_files

    def get_verbose(self):
        """
        Get the status of the verbose mode.
        """
        return self.verbose

    def set_verbose(self, verbose):
        """
        Set the status of the verbose mode.
        """
        self.verbose = verbose

    def get_extreme(self):
        """
        Get the status of the extreme mode.
        """
        return self.extreme

    def set_extreme(self, extreme):
        """
        Set the status of the extreme mode.
        """
        self.extreme = extreme

    def set_gcp_ip(self, gcp_ipv4, gcp_ipv6):
        """
        Set both IPv4 and IPv6 addresses of Google Cloud Platform.
        """
        self.gcp_ipv4 = gcp_ipv4
        self.gcp_ipv6 = gcp_ipv6

    def get_gcp_ipv6(self):
        """
        Retrieve the Google Cloud Platform IPV6 address.
        """
        return self.gcp_ipv6

    def get_gcp_ipv4(self):
        """
        Retrieve the Google Cloud Platform IPV4 address.
        """
        return self.gcp_ipv6

    def get_aws_ipv4(self):
        """
        Get the Amazon Web Services IPV4 address.
        """
        return self.aws_ipv4

    def get_aws_ipv6(self):
        """
        Get the Amazon Web Services IPV4 address.
        """
        return self.aws_ipv6

    def set_aws_ip(self, aws_ipv4, aws_ipv6):
        """
        Set both IPv4 and IPv6 addresses of Amazon Web Services.
        """
        self.aws_ipv4 = aws_ipv4
        self.aws_ipv6 = aws_ipv6

    def set_azure_ip(self, azure_ipv4, azure_ipv6):
        """
        Set both IPv4 and IPv6 addresses of Microsoft Azure.
        """
        self.azure_ipv4 = azure_ipv4
        self.azure_ipv6 = azure_ipv6

    def get_azure_ipv4(self):
        """
        Get the Microsoft Azure IPV4 address.
        """
        return self.azure_ipv4

    def get_azure_ipv6(self):
        """
        Get the Microsoft Azure IPV6 address.
        """
        return self.azure_ipv6

    def set_azure_ipv6(self, azure_ipv6):
        """
        Sets the Azure IPV6.
        """
        self.azure_ipv6 = azure_ipv6

    def get_perform_service_checks(self):
        """
        Get the status of service checks.
        """
        return self.perform_service_checks

    def set_perform_service_checks(self, perform_service_checks):
        """
        Sets the status of service checks.
        """
        self.perform_service_checks = perform_service_checks

    def get_timeout(self):
        """
        Get DNS resolution timeout value.
        """
        return self.timeout

    def set_timeout(self, timeout):
        """
        Set the DNS resolution timeout value.
        """
        self.timeout = timeout

    def get_retries(self):
        """
        Get number of retries for DNS resolution.
        """
        return self.retries

    def set_retries(self, retries):
        """
        Set the retries for DNS resolution.
        """
        self.retries = retries

    def get_patterns(self):
        """
        Get list of domain name matching patterns.
        """
        return self.patterns

    def set_patterns(self, patterns):
        """
        Set the domain name matching patterns.
        """
        self.patterns = patterns

    def get_dangling_domains(self):
        """
        Get set of discovered dangling domains.
        """
        return self.dangling_domains

    def set_dangling_domains(self, dangling_domains):
        """
        Set the set of discovered dangling domains.
        """
        self.dangling_domains = dangling_domains

    def add_dangling_domain_to_domains(self, domain):
        """
        Add a dangling domain to the set of dangling domains.
        :param domain: Dangling domain to be added.
        """
        self.dangling_domains.add(domain)

    def get_failed_domains(self):
        """
        Get the set of failed domains.
        """
        return self.failed_domains

    def set_failed_domains(self, failed_domains):
        """
        Set the set of failed domains.
        :param failed_domains: Set of failed domains.
        """
        self.failed_domains = failed_domains

    def get_evidence_enabled(self):
        """
        Get the status of evidence collection.
        """
        return self.evidence_enabled

    def set_evidence_enabled(self, evidence_enabled):
        """
        Set the evidence_enabled flag.
        """
        self.evidence_enabled = evidence_enabled

    def get_logger(self):
        """
        Get the logger object.
        """
        return self.logger

    def set_logger(self, logger):
        """
        Set the logger object.
        """
        self.logger = logger
