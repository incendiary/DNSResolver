class DomainProcessingContext:
    def __init__(self, env_manager, csp_ip_addresses):
        self.env_manager = env_manager
        self.csp_ip_addresses = csp_ip_addresses
        self.domain = None
        self.dangling_domains = set()

    def get_csp_ip_addresses(self):
        return self.csp_ip_addresses

    def get_domain(self):
        return self.domain

    def set_domain(self, domain):
        self.domain = domain

    def add_dangling_domain_to_domains(self, domain):
        self.dangling_domains.add(domain)

    def log_info(self, message, *args):
        self.env_manager.log_info(message, *args)
