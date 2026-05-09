class CSPIPAddresses:
    def __init__(self, gcp_ipv4, gcp_ipv6, aws_ipv4, aws_ipv6, azure_ipv4, azure_ipv6):
        self.gcp_ipv4 = gcp_ipv4
        self.gcp_ipv6 = gcp_ipv6
        self.aws_ipv4 = aws_ipv4
        self.aws_ipv6 = aws_ipv6
        self.azure_ipv4 = azure_ipv4
        self.azure_ipv6 = azure_ipv6

    def get_gcp_ipv4(self):
        return self.gcp_ipv4

    def get_gcp_ipv6(self):
        return self.gcp_ipv6

    def get_aws_ipv4(self):
        return self.aws_ipv4

    def get_aws_ipv6(self):
        return self.aws_ipv6

    def get_azure_ipv4(self):
        return self.azure_ipv4

    def get_azure_ipv6(self):
        return self.azure_ipv6
