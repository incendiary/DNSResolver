import asyncio

from tqdm import tqdm

from classes.csp_ip_addresses import CSPIPAddresses
from classes.dns_handler import DNSHandler
from classes.environment_manager import EnvironmentManager
from imports.cloud_ip_ranges import (
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
)
from imports.domain_processor import process_domain_async


async def main_async():
    env_manager = EnvironmentManager()

    gcp_ipv4, gcp_ipv6 = fetch_google_cloud_ip_ranges(
        env_manager.get_output_dir(), env_manager.extreme
    )
    aws_ipv4, aws_ipv6 = fetch_aws_ip_ranges(
        env_manager.get_output_dir(), env_manager.extreme
    )
    azure_ipv4, azure_ipv6 = fetch_azure_ip_ranges(
        env_manager.get_output_dir(), env_manager.extreme
    )

    csp_ip_addresses = CSPIPAddresses(
        gcp_ipv4, gcp_ipv6, aws_ipv4, aws_ipv6, azure_ipv4, azure_ipv6
    )

    env_manager.set_domains()
    domains_to_process = list(env_manager.domains)
    retries = env_manager.get_retries()
    dns_handler = DNSHandler(env_manager)
    sem = asyncio.Semaphore(env_manager.max_threads or 50)

    async def bounded_process(domain, pbar):
        async with sem:
            return await process_domain_async(
                domain, env_manager, pbar, csp_ip_addresses, dns_handler
            )

    for attempt in range(retries + 1):
        if not domains_to_process:
            break

        with tqdm(
            total=len(domains_to_process),
            desc=f"Processing Domains (Attempt {attempt + 1} of {retries + 1})",
        ) as pbar:
            tasks = [bounded_process(domain, pbar) for domain in domains_to_process]
            results = await asyncio.gather(*tasks)

        domains_to_process = [
            domain
            for domain, (success, _) in zip(domains_to_process, results)
            if not success
        ]

        if domains_to_process and attempt < retries:
            env_manager.log_info(
                "%d domain(s) failed on attempt %d, retrying...",
                len(domains_to_process),
                attempt + 1,
            )

    if domains_to_process:
        env_manager.log_info(
            "%d domain(s) could not be resolved after %d attempt(s).",
            len(domains_to_process),
            retries + 1,
        )

    env_manager.log_info(
        "All resolutions completed. Results saved to %s", env_manager.get_output_dir()
    )

    if env_manager.get_extreme():
        env_manager.log_info("AWS IPv4 Ranges: %s", csp_ip_addresses.get_aws_ipv4())
        env_manager.log_info("AWS IPv6 Ranges: %s", csp_ip_addresses.get_aws_ipv6())
        env_manager.log_info(
            "Google Cloud IPv4 Ranges: %s", csp_ip_addresses.get_gcp_ipv4()
        )
        env_manager.log_info(
            "Google Cloud IPv6 Ranges: %s", csp_ip_addresses.get_gcp_ipv6()
        )
        env_manager.log_info("Azure IPv4 Ranges: %s", csp_ip_addresses.get_azure_ipv4())
        env_manager.log_info("Azure IPv6 Ranges: %s", csp_ip_addresses.get_azure_ipv6())


if __name__ == "__main__":
    asyncio.run(main_async())
