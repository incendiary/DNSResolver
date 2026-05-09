import asyncio

import aiodns

from classes.dns_constants import NO_DATA, NXDOMAIN, SERVFAIL, is_dns_error_present
from classes.domain_categoriser import DomainCategoriser
from classes.evidence_collector import EvidenceCollector


class TakeoverDetector:
    def __init__(self, aiodns_resolver, env_manager):
        self.aiodns_resolver = aiodns_resolver
        self.env_manager = env_manager
        self.evidence_collector = EvidenceCollector(env_manager)

    async def collect_evidence(self, domain, reason, output_files):
        if not self.env_manager.evidence:
            return
        tasks = [
            self.evidence_collector.perform_dns_evidence(
                domain,
                nameserver,
                reason,
                output_files["evidence"]["dns"],
            )
            for nameserver in self.env_manager.nameservers
        ]
        await asyncio.gather(*tasks)

    async def is_dangling_record_async(self, domain, record_type):
        try:
            await self.aiodns_resolver.query(domain, record_type)
            self.env_manager.log_info(f"Domain {domain} has a valid {record_type} record.")
            return False
        except aiodns.error.DNSError as e:
            self.env_manager.log_info(f"Error querying {record_type} for {domain}: {e}")
            return is_dns_error_present(e, [NXDOMAIN, SERVFAIL])

    async def check_ns_takeover(self, domain_context, domain):
        original_domain = domain_context.get_domain()
        output_files = self.env_manager.output_files
        self.env_manager.log_info(f"Checking NS takeover for domain: {domain}")
        try:
            ns_records = await self.aiodns_resolver.query(domain, "NS")
            for ns in ns_records:
                ns_domain = str(ns.host).strip(".")
                self.env_manager.log_info(f"NS record found: {ns_domain}")
                try:
                    await self.aiodns_resolver.query(ns_domain, "A")
                except aiodns.error.DNSError as e:
                    if is_dns_error_present(e, [NXDOMAIN, SERVFAIL]):
                        await self.env_manager.write_to_file(
                            output_files["standard"]["ns_takeover"],
                            f"{original_domain}|{domain}",
                        )
                        self.env_manager.log_info(
                            f"NS takeover possible for domain {domain}"
                        )
                        await self.collect_evidence(domain, "ns_takeover", output_files)
                        return True
        except aiodns.error.DNSError as e:
            self.env_manager.log_info(f"Error querying NS records for {domain}: {e}")
        return False

    async def handle_takeover_checks(self, domain_context, current_domain):
        self.env_manager.log_info(
            f"Running takeover checks for domain: {current_domain}"
        )
        is_dangling = await self.check_dangling_cname_async(domain_context, current_domain)
        self.env_manager.log_info(
            f"Dangling CNAME check for {current_domain}: {is_dangling}"
        )
        is_nstakeover = await self.check_ns_takeover(domain_context, current_domain)
        self.env_manager.log_info(
            f"NS takeover check for {current_domain}: {is_nstakeover}"
        )
        if is_dangling or is_nstakeover:
            domain_context.add_dangling_domain_to_domains(current_domain)
        return is_dangling or is_nstakeover

    async def check_dangling_cname_async(self, domain_context, current_domain):
        original_domain = domain_context.get_domain()
        output_files = self.env_manager.output_files
        self.env_manager.log_info(
            f"Checking for dangling CNAME for domain: {current_domain}"
        )
        try:
            cname_answer = await self.aiodns_resolver.query(current_domain, "CNAME")
            self.env_manager.log_info(
                f"CNAME query response for {current_domain}: {cname_answer}"
            )
            if cname_answer:
                self.env_manager.log_info(f"Domain {current_domain} is a CNAME record.")
                target = cname_answer.cname
                self.env_manager.log_info(f"CNAME target: {target}")
                if await self.check_dangling_cname_async(domain_context, target):
                    return True
        except aiodns.error.DNSError as e:
            self.env_manager.log_info(f"Error querying CNAME for {current_domain}: {e}")
            if not is_dns_error_present(e, [NXDOMAIN]):
                return False

        for record_type in ["A", "AAAA", "MX"]:
            try:
                await self.aiodns_resolver.query(current_domain, record_type)
                self.env_manager.log_info(
                    f"Domain {current_domain} has a valid {record_type} record."
                )
                return False
            except aiodns.error.DNSError as e:
                self.env_manager.log_info(
                    f"Error querying {record_type} for {current_domain}: {e}"
                )
                if is_dns_error_present(e, [NO_DATA]):
                    continue
                if is_dns_error_present(e, [NXDOMAIN]):
                    break
                return False

        try:
            await self.aiodns_resolver.query(current_domain, "NS")
            await self.env_manager.write_to_file(
                output_files["standard"]["ns_takeover"],
                f"{original_domain}|{current_domain}",
            )
            self.env_manager.log_info(
                f"NS takeover possible for domain {current_domain}"
            )
            return False
        except aiodns.error.DNSError as e:
            self.env_manager.log_info(f"Error querying NS for {current_domain}: {e}")

        patterns = self.env_manager.patterns
        category, recommendation, evidence_link = DomainCategoriser.categorise_domain(
            current_domain, patterns
        )
        await self.env_manager.write_to_file(
            output_files["standard"]["dangling"],
            f"{original_domain}|{current_domain}|{category}|{recommendation}|{evidence_link}",
        )
        self.env_manager.log_info(
            f"Domain {current_domain} is a dangling CNAME with category: {category}"
        )
        await self.collect_evidence(current_domain, "dangling", output_files)
        return True
