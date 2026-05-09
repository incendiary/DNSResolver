import re


class DomainCategoriser:
    @staticmethod
    def categorise_domain(domain, patterns):
        for category, pattern in patterns.items():
            if re.search(pattern["regex"], domain):
                return category, pattern["recommendation"], pattern["evidence"]
        return "unknown", "Unclassified", "N/A"
