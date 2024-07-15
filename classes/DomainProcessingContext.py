import dns.resolver


class DomainProcessingContext:
    def __init__(self):

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
        self.logger = None
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

    # Getters and Setters for each attribute

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
