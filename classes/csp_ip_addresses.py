class CSPIPAddresses:
    """
    A class to store IP ranges for various Cloud Service Providers (CSPs).

    Attributes:
        gcp_ipv4 (list): Google Cloud Platform IPv4 ranges.
        gcp_ipv6 (list): Google Cloud Platform IPv6 ranges.
        aws_ipv4 (list): AWS IPv4 ranges.
        aws_ipv6 (list): AWS IPv6 ranges.
        azure_ipv4 (list): Azure IPv4 ranges.
        azure_ipv6 (list): Azure IPv6 ranges.
    """

    def __init__(self, gcp_ipv4, gcp_ipv6, aws_ipv4, aws_ipv6, azure_ipv4, azure_ipv6):
        """
        Initialize CSPIPAddresses with IP ranges for GCP, AWS, and Azure.

        Args:
            gcp_ipv4 (list): Google Cloud Platform IPv4 ranges.
            gcp_ipv6 (list): Google Cloud Platform IPv6 ranges.
            aws_ipv4 (list): AWS IPv4 ranges.
            aws_ipv6 (list): AWS IPv6 ranges.
            azure_ipv4 (list): Azure IPv4 ranges.
            azure_ipv6 (list): Azure IPv6 ranges.
        """
        self.gcp_ipv4 = gcp_ipv4
        self.gcp_ipv6 = gcp_ipv6
        self.aws_ipv4 = aws_ipv4
        self.aws_ipv6 = aws_ipv6
        self.azure_ipv4 = azure_ipv4
        self.azure_ipv6 = azure_ipv6

    def get_gcp_ipv4(self):
        """
        Get Google Cloud Platform IPv4 ranges.

        Returns:
            list: Google Cloud Platform IPv4 ranges.
        """
        return self.gcp_ipv4

    def get_gcp_ipv6(self):
        """
        Get Google Cloud Platform IPv6 ranges.

        Returns:
            list: Google Cloud Platform IPv6 ranges.
        """
        return self.gcp_ipv6

    def get_aws_ipv4(self):
        """
        Get AWS IPv4 ranges.

        Returns:
            list: AWS IPv4 ranges.
        """
        return self.aws_ipv4

    def get_aws_ipv6(self):
        """
        Get AWS IPv6 ranges.

        Returns:
            list: AWS IPv6 ranges.
        """
        return self.aws_ipv6

    def get_azure_ipv4(self):
        """
        Get Azure IPv4 ranges.

        Returns:
            list: Azure IPv4 ranges.
        """
        return self.azure_ipv4

    def get_azure_ipv6(self):
        """
        Get Azure IPv6 ranges.

        Returns:
            list: Azure IPv6 ranges.
        """
        return self.azure_ipv6
