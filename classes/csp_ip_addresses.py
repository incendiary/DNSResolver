class CSPIPAddresses:
    def __init__(
        self,
        gcp_ipv4,
        gcp_ipv6,
        aws_ipv4,
        aws_ipv6,
        azure_ipv4,
        azure_ipv6,
        metadata_by_provider=None,
    ):
        self.gcp_ipv4 = gcp_ipv4
        self.gcp_ipv6 = gcp_ipv6
        self.aws_ipv4 = aws_ipv4
        self.aws_ipv6 = aws_ipv6
        self.azure_ipv4 = azure_ipv4
        self.azure_ipv6 = azure_ipv6
        # Provider -> CIDR -> all published (region, service, border-group)
        # attributions. Providers can publish the same CIDR, and one provider can
        # publish a CIDR under multiple services, so neither dimension is scalar.
        self.metadata_by_provider = metadata_by_provider or {}

    def describe(self, provider, cidr):
        """
        Every region, service and network border group for a provider prefix.

        Unpublished fields read 'unknown' rather than being inferred — only AWS
        publishes a border group, and not every prefix carries a region.
        """
        entries = self.metadata_by_provider.get(provider, {}).get(cidr)
        return entries or [("unknown", "unknown", "unknown")]

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
