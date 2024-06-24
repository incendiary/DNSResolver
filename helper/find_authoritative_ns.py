import dns.resolver
import dns.query
import dns.message
import argparse


def query_ns(server_ip, domain):
    try:
        query = dns.message.make_query(domain, dns.rdatatype.NS)
        response = dns.query.udp(query, server_ip, timeout=3)
        return response
    except Exception as e:
        print(f"Failed to query {server_ip} for {domain}: {e}")
        return None


def get_tld_ns(tld):
    root_ns = "a.root-servers.net"
    root_ns_ip = dns.resolver.resolve(root_ns, "A")[0].to_text()
    response = query_ns(root_ns_ip, tld)
    if response:
        tld_ns = [
            rr.target.to_text()
            for rr in response.authority[0]
            if rr.rdtype == dns.rdatatype.NS
        ]
        return tld_ns
    return None


def get_domain_ns(tld_ns, domain):
    for ns in tld_ns:
        try:
            ns_ip = dns.resolver.resolve(ns, "A")[0].to_text()
            response = query_ns(ns_ip, domain)
            if response and response.answer:
                domain_ns = [
                    rr.target.to_text()
                    for rr in response.answer[0]
                    if rr.rdtype == dns.rdatatype.NS
                ]
                return domain_ns
            elif response and response.authority:
                domain_ns = [
                    rr.target.to_text()
                    for rr in response.authority[0]
                    if rr.rdtype == dns.rdatatype.NS
                ]
                return domain_ns
        except dns.exception.DNSException as e:
            print(f"Failed to query {ns} for {domain}: {e}")
            continue
    return None


def get_subdomain_ns(domain_ns, subdomain):
    if not domain_ns:
        return None

    for ns in domain_ns:
        try:
            ns_ip = dns.resolver.resolve(ns, "A")[0].to_text()
            response = query_ns(ns_ip, subdomain)
            if response and response.answer:
                subdomain_ns = [
                    rr.target.to_text()
                    for rr in response.answer[0]
                    if rr.rdtype == dns.rdatatype.NS
                ]
                return subdomain_ns
            elif response and response.authority:
                subdomain_ns = [
                    rr.target.to_text()
                    for rr in response.authority[0]
                    if rr.rdtype == dns.rdatatype.NS
                ]
                return subdomain_ns
        except dns.exception.DNSException as e:
            print(f"Failed to query {ns} for {subdomain}: {e}")
            continue
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Find authoritative name servers for a given subdomain."
    )
    parser.add_argument("subdomain", type=str, help="The subdomain name to query.")
    args = parser.parse_args()

    subdomain = args.subdomain
    domain_parts = subdomain.split(".")
    if len(domain_parts) < 2:
        print(
            "Invalid subdomain format. Please provide a full subdomain (e.g., www.example.com)."
        )
        exit(1)

    domain = ".".join(domain_parts[-2:])
    tld = domain_parts[-1]

    # Step 1: Get TLD name servers
    tld_ns = get_tld_ns(tld)
    if tld_ns:
        print(f"TLD name servers for .{tld}:")
        for ns in tld_ns:
            print(ns)
    else:
        print(f"Failed to retrieve TLD name servers for .{tld}")
        exit(1)

    # Step 2: Get domain name servers
    domain_ns = get_domain_ns(tld_ns, domain)
    if domain_ns:
        print(f"\nAuthoritative name servers for {domain}:")
        for ns in domain_ns:
            print(ns)
    else:
        print(f"No authoritative name servers found for {domain}")
        exit(1)

    # Step 3: Get subdomain name servers
    subdomain_ns = get_subdomain_ns(domain_ns, subdomain)
    if subdomain_ns:
        print(f"\nAuthoritative name servers for {subdomain}:")
        for ns in subdomain_ns:
            print(ns)
    else:
        print(f"No authoritative name servers found for {subdomain}")

        # Since no NS records are found for the subdomain, assume the domain's name servers are authoritative
        if domain_ns:
            print(f"\nThe name servers for {domain} are authoritative for {subdomain}.")
