import asyncio

import aiodns
import dns.exception
import dns.resolver

from classes.dns_constants import NXDOMAIN, SERVFAIL, is_dns_error_present
from classes.takeover_detector import TakeoverDetector
from classes.wildcard_detector import WildcardDetector


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
        self.wildcard_detector = WildcardDetector(self.aiodns_resolver, env_manager)

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
        loop = asyncio.get_running_loop()
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
        self.env_manager.log_info(f"Resolving {current_domain}")

        # Query A and AAAA concurrently. A host with only AAAA records is still
        # resolvable, so treating an A-record failure as "unresolved" would be
        # wrong for IPv6-only hosts.
        a_result, aaaa_result = await asyncio.gather(
            self.aiodns_resolver.query(current_domain, "A"),
            self.aiodns_resolver.query(current_domain, "AAAA"),
            return_exceptions=True,
        )

        # Anything that is not a DNSError is a genuine fault (not a DNS answer
        # about the domain) — propagate it as the un-gathered code used to.
        for result in (a_result, aaaa_result):
            if isinstance(result, BaseException) and not isinstance(
                result, aiodns.error.DNSError
            ):
                raise result

        a_error = a_result if isinstance(a_result, BaseException) else None
        aaaa_error = aaaa_result if isinstance(aaaa_result, BaseException) else None

        # Only when BOTH record types fail is the domain unresolved. The A error
        # is passed on so the existing NXDOMAIN/SERVFAIL handling is unchanged.
        if a_error is not None and aaaa_error is not None:
            self.env_manager.log_info(
                f"DNS error for {current_domain}: A={a_error} | AAAA={aaaa_error}"
            )
            return await self.handle_domain_resolution_errors(
                domain_context, current_domain, a_error, final_retry=True
            )

        # IPv4 first, then IPv6 — stable ordering for the pipe-delimited output.
        final_ips = []
        for result in (a_result, aaaa_result):
            if not isinstance(result, BaseException):
                final_ips.extend(answer.host for answer in result)

        self.env_manager.log_info(
            f"Successfully resolved {current_domain} to {final_ips}"
        )
        await self.takeover_detector.handle_takeover_checks(
            domain_context, current_domain
        )
        return True, final_ips
