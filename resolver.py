import asyncio
import json
from pathlib import Path

from tqdm import tqdm

from classes.allocator_contract import publish_allocator_targets
from classes.csp_ip_addresses import CSPIPAddresses
from classes.custom_exceptions import ProviderCatalogueError
from classes.dns_handler import DNSHandler
from classes.environment_manager import EnvironmentManager
from classes.run_summary import RunSummary
from imports.cloud_ip_ranges import (
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
)
from imports.domain_processor import process_domain_async
from version import __version__


async def run(env_manager):
    """
    Core resolution pipeline. Accepts any EnvironmentManager-compatible object so
    both the CLI entrypoint (resolver.py) and the Lambda entrypoint (lambda_handler.py)
    can share the same logic.
    """
    catalogues = {
        "gcp": fetch_google_cloud_ip_ranges(
            env_manager.output_dir, env_manager.extreme
        ),
        "aws": fetch_aws_ip_ranges(env_manager.output_dir, env_manager.extreme),
        "azure": fetch_azure_ip_ranges(env_manager.output_dir, env_manager.extreme),
    }
    status_path = Path(env_manager.output_dir) / "provider_catalogues.json"
    with open(status_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                provider: {**catalogue.manifest_entry(), "error": catalogue.error}
                for provider, catalogue in catalogues.items()
            },
            handle,
            indent=2,
        )

    unusable = [name for name, catalogue in catalogues.items() if not catalogue.usable]
    if unusable:
        details = "; ".join(
            f"{name}: {catalogues[name].error or catalogues[name].status}"
            for name in unusable
        )
        raise ProviderCatalogueError(
            "Required provider catalogue(s) unavailable; no domains were processed "
            f"and no actionable results were published. {details}. Status: {status_path}"
        )

    gcp_ipv4, gcp_ipv6, gcp_meta = catalogues["gcp"]
    aws_ipv4, aws_ipv6, aws_meta = catalogues["aws"]
    azure_ipv4, azure_ipv6, azure_meta = catalogues["azure"]

    csp_ip_addresses = CSPIPAddresses(
        gcp_ipv4,
        gcp_ipv6,
        aws_ipv4,
        aws_ipv6,
        azure_ipv4,
        azure_ipv6,
        metadata_by_provider={"gcp": gcp_meta, "aws": aws_meta, "azure": azure_meta},
    )

    env_manager.set_domains()
    domains_to_process = list(env_manager.domains)
    retries = env_manager.retries
    dns_handler = DNSHandler(env_manager)
    sem = asyncio.Semaphore(env_manager.max_threads or 50)

    async def bounded_process(domain, pbar, final_retry):
        async with sem:
            return await process_domain_async(
                domain,
                env_manager,
                pbar,
                csp_ip_addresses,
                dns_handler,
                final_retry=final_retry,
            )

    for attempt in range(retries + 1):
        if not domains_to_process:
            break

        with tqdm(
            total=len(domains_to_process),
            desc=f"Processing Domains (Attempt {attempt + 1} of {retries + 1})",
        ) as pbar:
            final_retry = attempt == retries
            tasks = [
                bounded_process(domain, pbar, final_retry)
                for domain in domains_to_process
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        failed = []
        for domain, result in zip(domains_to_process, results):
            if isinstance(result, Exception):
                env_manager.log_error(
                    "Unhandled exception processing %s: %s", domain, result
                )
                failed.append(domain)
                continue
            success, _final_ips, _dangling = result
            if not success:
                failed.append(domain)
        domains_to_process = failed

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

    targets = publish_allocator_targets(
        env_manager.output_files["standard"]["csp"], env_manager.output_dir
    )
    env_manager.log_info(
        "Published %d actionable target(s) to allocator-targets-v1.json",
        len(targets),
    )

    RunSummary(env_manager.output_files, env_manager.output_dir, __version__).display(
        len(env_manager.domains), len(domains_to_process)
    )

    if env_manager.extreme:
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


async def main_async():
    print(f"DNSResolver v{__version__}")
    env_manager = EnvironmentManager()
    await run(env_manager)


if __name__ == "__main__":
    asyncio.run(main_async())
