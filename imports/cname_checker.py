import dns.resolver
import re
import json

# Function to detect potential cloud service takeovers


def detect_direct_takeovers(dangling_cname_file, output_file):
    with open("config.json") as f:
        patterns = json.load(f)

    patterns = {k: re.compile(v) for k, v in patterns.items()}

    with open(dangling_cname_file, "r") as infile, open(output_file, "a") as outfile:
        for line in infile:
            domain = line.strip()
            for cloud_provider, pattern in patterns.items():
                if pattern.search(domain):
                    outfile.write(
                        f"Potential {cloud_provider.upper()} takeover candidate: {domain}\n"
                    )
                    print(
                        f"Potential {cloud_provider.upper()} takeover candidate: {domain}"
                    )


def check_dangling_cname(current_domain, nameservers):
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers

    try:
        resolver.resolve(current_domain, "A")
        return False  # If resolving the A record succeeds, it's not a dangling CNAME
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        try:
            resolver.resolve(current_domain, "AAAA")
            return False  # If resolving the AAAA record succeeds, it's not a dangling CNAME
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
        ):
            return True  # If both A and AAAA records cannot be resolved, it's a dangling CNAME
