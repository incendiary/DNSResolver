import json
import re


class DomainCategoriser:
    @staticmethod
    async def load_domain_categorisation_patterns(config_file="config.json"):
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        return config.get("domain_categorization", {})

    @staticmethod
    def categorise_domain(domain, patterns):
        for category, pattern in patterns.items():
            if re.search(pattern["regex"], domain):
                return category, pattern["recommendation"], pattern["evidence"]
        return "unknown", "Unclassified", "N/A"
