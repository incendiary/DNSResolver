class CSPIPAddresses:
    def __init__(
        self,
        gcp_ipv4,
        gcp_ipv6,
        aws_ipv4,
        aws_ipv6,
        azure_ipv4,
        azure_ipv6,
        metadata=None,
    ):
        self.gcp_ipv4 = gcp_ipv4
        self.gcp_ipv6 = gcp_ipv6
        self.aws_ipv4 = aws_ipv4
        self.aws_ipv6 = aws_ipv6
        self.azure_ipv4 = azure_ipv4
        self.azure_ipv6 = azure_ipv6
        # CIDR -> (region, service). A match is only actionable downstream if the
        # consumer knows where the address is allocated from and what it serves,
        # so the publishers' own metadata is carried through rather than dropped.
        self.metadata = metadata or {}

    def describe(self, cidr):
        """
        Region, service and network border group for a matched prefix.

        Unpublished fields read 'unknown' rather than being inferred — only AWS
        publishes a border group, and not every prefix carries a region.
        """
        return self.metadata.get(cidr, ("unknown", "unknown", "unknown"))

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
