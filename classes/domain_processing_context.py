class DomainProcessingContext:
    def __init__(self, env_manager, catalogues):
        self.env_manager = env_manager
        self.catalogues = catalogues
        self.domain = None

    def get_catalogues(self):
        return self.catalogues

    def get_domain(self):
        return self.domain

    def set_domain(self, domain):
        self.domain = domain

    def log_info(self, message, *args):
        self.env_manager.log_info(message, *args)
