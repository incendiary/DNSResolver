import asyncio

import aiodns
import dns.exception
import dns.resolver

from classes.dns_constants import NXDOMAIN, SERVFAIL, is_dns_error_present
from classes.takeover_detector import TakeoverDetector


class DNSHandler:
    def __init__(self, env_manager):
        self.env_manager = env_manager
        self.aiodns_resolver = aiodns.DNSResolver()
        self.dnspython_resolver = dns.resolver.Resolver()

        random_nameserver = self.env_manager.get_random_nameserver()
        if random_nameserver:
            self.aiodns_resolver.nameservers = [random_nameserver]
            self.dnspython_resolver.nameservers = [random_nameserver]

        self.takeover_detector = TakeoverDetector(self.aiodns_resolver, env_manager)

    async def log_and_write_dns_error(self, domain, error, additional_message=""):
        message = f"DNS resolution error for {domain}: {error}"
        if additional_message:
            message += f"|{additional_message}"
        self.env_manager.log_error(message)
        await self.env_manager.write_to_file(
            self.env_manager.output_files["standard"]["unresolved"],
            message,
        )

    async def handle_domain_resolution_errors(
        self, domain_context, current_domain, error, final_retry
    ):
        self.env_manager.log_info(
            f"Handling DNS error for {current_domain}: {error} | final_retry={final_retry}"
        )

        if is_dns_error_present(error, [NXDOMAIN]):
            self.env_manager.log_info(
                f"{current_domain} not found, checking for dangling CNAME."
            )
            if await self.takeover_detector.handle_takeover_checks(
                domain_context, current_domain
            ):
                return True, []

        if final_retry:
            if is_dns_error_present(error, [SERVFAIL]):
                await self.log_and_write_dns_error(
                    current_domain, error, "Could not contact DNS servers"
                )
            else:
                await self.log_and_write_dns_error(current_domain, error)
            self.env_manager.log_error(
                f"DNS resolution error for {current_domain}: {error} | final_retry={final_retry}"
            )

        # Second-opinion check using dnspython — run in executor to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None, self.dnspython_resolver.resolve, current_domain, "A"
            )
            self.env_manager.log_info(
                f"Domain {current_domain} resolved successfully with dnspython_resolver."
            )
            return True, []
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ) as e:
            self.env_manager.log_info(
                f"DNS error with dnspython_resolver for {current_domain}: {e}"
            )
            if isinstance(e, dns.resolver.NXDOMAIN):
                self.env_manager.log_info(
                    f"{current_domain} not found, checking for dangling CNAME."
                )
                if await self.takeover_detector.handle_takeover_checks(
                    domain_context, current_domain
                ):
                    return True, []

        return False, []

    async def resolve_domain_async(self, domain_context):
        current_domain = domain_context.get_domain()
        retries = self.env_manager.retries
        self.env_manager.log_info(
            f"Starting DNS resolution for {current_domain} with {retries + 1} attempts."
        )

        for attempt in range(retries + 1):
            self.env_manager.log_info(
                f"Attempt {attempt + 1} for resolving {current_domain}"
            )
            try:
                answers = await self.aiodns_resolver.query(current_domain, "A")
                final_ips = [answer.host for answer in answers]
                self.env_manager.log_info(
                    f"Successfully resolved {current_domain} to {final_ips}"
                )
                await self.takeover_detector.handle_takeover_checks(
                    domain_context, current_domain
                )
                return True, final_ips
            except aiodns.error.DNSError as e:
                self.env_manager.log_info(
                    f"DNS error on attempt {attempt + 1} of {retries + 1} for {current_domain}: {e}"
                )
                final_retry = attempt == retries
                success, ips = await self.handle_domain_resolution_errors(
                    domain_context, current_domain, e, final_retry
                )
                if success:
                    return success, ips
                if final_retry:
                    self.env_manager.log_info(
                        f"Failed to resolve {current_domain} after {retries + 1} attempts."
                    )
                    return False, []
