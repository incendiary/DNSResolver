import asyncio

from tqdm import tqdm

from classes.csp_ip_addresses import CSPIPAddresses
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

    for attempt in range(env_manager.retries + 1):
        if not env_manager.domains:
            break

        current_domains = list(env_manager.domains)
        env_manager.domains.clear()
        failed_domains = set()

        with tqdm(
            total=len(current_domains),
            desc=f"Processing Domains (Attempt {attempt + 1})",
        ) as pbar:
            tasks = [
                process_domain_async(domain, env_manager, pbar, csp_ip_addresses)
                for domain in current_domains
            ]
            results = await asyncio.gather(*tasks)

        for domain, (success, final_ips) in zip(current_domains, results):
            if not success:
                failed_domains.add(domain)

        env_manager.domains.update(failed_domains)

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
