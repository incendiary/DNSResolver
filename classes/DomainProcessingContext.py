import dns.resolver


class DomainProcessingContext:
    """
    DomainProcessingContext

    Class representing the context for domain processing.

    Attributes:
    - nameservers (list): The list of nameservers to be used for DNS resolution.
    - output_files (list): The list of output files to store the results.
    - verbose (bool): Flag indicating whether to enable verbose mode or not.
    - extreme (bool): Flag indicating whether to enable extreme mode or not.
    - gcp_ipv4 (str): The IPv4 address for GCP (Google Cloud Platform).
    - gcp_ipv6 (str): The IPv6 address for GCP (Google Cloud Platform).
    - aws_ipv4 (str): The IPv4 address for AWS (Amazon Web Services).
    - aws_ipv6 (str): The IPv6 address for AWS (Amazon Web Services).
    - azure_ipv4 (str): The IPv4 address for Azure (Microsoft Azure).
    - azure_ipv6 (str): The IPv6 address for Azure (Microsoft Azure).
    - perform_service_checks (bool): Flag indicating whether to perform service checks or not.
    - timeout (int): The timeout value for DNS resolution.
    - retries (int): The number of retries for DNS resolution.
    - patterns (list): The list of patterns to match against resolved domain names.
    - dangling_domains (set): Set of dangling domains.
    - failed_domains (set): Set of failed domains.
    - evidence_enabled (bool): Flag indicating whether to enable evidence collection or not.
    - logger: The logger object for logging.
    - resolver: The resolver object for DNS resolution.
    - domain: The root domain that this context applies to.
    - current_domain: The current domain being resolved.

    Methods:
    - create_resolver: Creates the resolver object with the specified parameters.
    - get_resolver: Returns the resolver object.
    - get_domain: Returns the root domain.
    - set_domain: Sets the root domain.
    - get_current_domain: Returns the current domain.
    - set_current_domain: Sets the current domain.
    - get_nameservers: Returns the nameservers.
    - set_nameservers: Sets the nameservers.
    - get_output_files: Returns the output files.
    - set_output_files: Sets the output files.
    - get_verbose: Returns the verbose flag.
    - set_verbose: Sets the verbose flag.
    - get_extreme: Returns the extreme flag.
    - set_extreme: Sets the extreme flag.
    - get_gcp_ipv4: Returns the GCP IPv4 address.
    - set_gcp_ipv4: Sets the GCP IPv4 address.
    - get_gcp_ipv6: Returns the GCP IPv6 address.
    - set_gcp_ipv6: Sets the GCP IPv6 address.
    - get_aws_ipv4: Returns the AWS IPv4 address.
    - set_aws_ipv4: Sets the AWS IPv4 address.
    - get_aws_ipv6: Returns the AWS IPv6 address.
    - set_aws_ipv6: Sets the AWS IPv6 address.
    - get_azure_ipv4: Returns the Azure IPv4 address.
    - set_azure_ipv4: Sets the Azure IPv4 address.
    - get_azure_ipv6: Returns the Azure IPv6 address.
    - set_azure_ipv6: Sets the Azure IPv6 address.
    - get_perform_service_checks: Returns the perform_service_checks flag.
    - set_perform_service_checks: Sets the perform_service_checks flag.
    - get_timeout: Returns the timeout value.
    - set_timeout: Sets the timeout value.
    - get_retries: Returns the number of retries.
    - set_retries: Sets the number of retries.
    - get_patterns: Returns the patterns.
    - set_patterns: Sets the patterns.
    - get_dangling_domains: Returns the set of dangling domains.
    - set_dangling_domains: Sets the set of dangling domains.
    - add_dangling_domain_to_domains: Adds a dangling domain to the set of dangling domains.
    - get_failed_domains: Returns the set of failed domains.
    - set_failed_domains: Sets the set of failed domains.
    - get_evidence_enabled: Returns the evidence_enabled flag.
    - set_evidence_enabled: Sets the evidence_enabled flag.
    - get_logger: Returns the logger object.
    - set_logger: Sets the logger object.
    """

    def __init__(self, env_manager):

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
        # The root Domain that this context applies to
        self.domain = None
        # The current Domain that maybe being resolved
        self.current_domain = None

    def create_resolver(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = self.timeout
        self.resolver.timeout = self.timeout
        if self.nameservers:
            self.resolver.nameservers = self.nameservers

    def log_info(self, message, *args):
        if self.logger:
            self.logger.info(message, *args)
        else:
            print(f"INFO: {message % args}")

    # Simple Getters and Setters for each attribute

    def get_resolver(self):
        return self.resolver

    def get_domain(self):
        return self.domain

    def set_domain(self, domain):
        self.domain = domain

    def get_current_domain(self):
        return self.domain

    def set_current_domain(self, domain):
        self.domain = domain

    def get_nameservers(self):
        return self.nameservers

    def set_nameservers(self, nameservers):
        self.nameservers = nameservers

    def get_output_files(self):
        return self.output_files

    def set_output_files(self, output_files):
        self.output_files = output_files

    def get_verbose(self):
        return self.verbose

    def set_verbose(self, verbose):
        self.verbose = verbose

    def get_extreme(self):
        return self.extreme

    def set_extreme(self, extreme):
        self.extreme = extreme

    def get_gcp_ipv4(self):
        return self.gcp_ipv4

    def set_gcp_ipv4(self, gcp_ipv4):
        self.gcp_ipv4 = gcp_ipv4

    def get_gcp_ipv6(self):
        return self.gcp_ipv6

    def set_gcp_ipv6(self, gcp_ipv6):
        self.gcp_ipv6 = gcp_ipv6

    def get_aws_ipv4(self):
        return self.aws_ipv4

    def set_aws_ipv4(self, aws_ipv4):
        self.aws_ipv4 = aws_ipv4

    def get_aws_ipv6(self):
        return self.aws_ipv6

    def set_aws_ipv6(self, aws_ipv6):
        self.aws_ipv6 = aws_ipv6

    def get_azure_ipv4(self):
        return self.azure_ipv4

    def set_azure_ipv4(self, azure_ipv4):
        self.azure_ipv4 = azure_ipv4

    def get_azure_ipv6(self):
        return self.azure_ipv6

    def set_azure_ipv6(self, azure_ipv6):
        self.azure_ipv6 = azure_ipv6

    def get_perform_service_checks(self):
        return self.perform_service_checks

    def set_perform_service_checks(self, perform_service_checks):
        self.perform_service_checks = perform_service_checks

    def get_timeout(self):
        return self.timeout

    def set_timeout(self, timeout):
        self.timeout = timeout

    def get_retries(self):
        return self.retries

    def set_retries(self, retries):
        self.retries = retries

    def get_patterns(self):
        return self.patterns

    def set_patterns(self, patterns):
        self.patterns = patterns

    def get_dangling_domains(self):
        return self.dangling_domains

    def set_dangling_domains(self, dangling_domains):
        self.dangling_domains = dangling_domains

    def add_dangling_domain_to_domains(self, domain):
        self.dangling_domains.add(domain)

    def get_failed_domains(self):
        return self.failed_domains

    def set_failed_domains(self, failed_domains):
        self.failed_domains = failed_domains

    def get_evidence_enabled(self):
        return self.evidence_enabled

    def set_evidence_enabled(self, evidence_enabled):
        self.evidence_enabled = evidence_enabled

    def get_logger(self):
        return self.logger

    def set_logger(self, logger):
        self.logger = logger
