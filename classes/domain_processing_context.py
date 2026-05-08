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
        env_manager (EnvironmentManager): The environment manager object.
        resolver (dns.resolver.Resolver): DNS resolver object.
        domain: The root domain to which this context applies.
        current_domain: The current domain being processed.
        dangling_domains: Set of discovered dangling domains.
        failed_domains: Set of failed domains.

    Methods:
        create_resolver: Create and configure a DNS resolver object.
        log_info: Log an info message or print to stdout if logger is not available.
        get_resolver: Retrieve the DNS resolver.
        get_domain: Get the root domain to which this context applies.
        set_domain: Set the root domain to which this context applies.
        get_current_domain: Retrieve the current domain being processed.
        set_current_domain: Set the current domain to be processed.
    """

    def __init__(self, env_manager, csp_ip_addresses):
        """Initialize DomainProcessingContext instance."""
        self.env_manager = env_manager
        self.resolver = None
        self.csp_ip_addresses = csp_ip_addresses
        self.domain = None
        self.current_domain = None
        self.dangling_domains = set()
        self.failed_domains = set()

    def create_resolver(self):
        """Create and configure a DNS resolver object."""
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = self.env_manager.get_timeout()
        self.resolver.timeout = self.env_manager.get_timeout()
        nameservers = self.env_manager.get_resolvers()
        if nameservers:
            self.resolver.nameservers = nameservers

    def log_info(self, message, *args):
        """Log an info message or print to stdout if logger is not available."""
        logger = self.env_manager.get_logger()
        if logger:
            logger.info(message, *args)
        else:
            print(f"INFO: {message % args}")

    def get_csp_ip_addresses(self):
        """returns the csp ip address class"""
        return self.csp_ip_addresses

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

    def get_dangling_domains(self):
        """Get set of discovered dangling domains."""
        return self.dangling_domains

    def set_dangling_domains(self, dangling_domains):
        """Set the set of discovered dangling domains."""
        self.dangling_domains = dangling_domains

    def add_dangling_domain_to_domains(self, domain):
        """Add a dangling domain to the set of dangling domains."""
        self.dangling_domains.add(domain)

    def get_failed_domains(self):
        """Get the set of failed domains."""
        return self.failed_domains

    def set_failed_domains(self, failed_domains):
        """Set the set of failed domains."""
        self.failed_domains = failed_domains
