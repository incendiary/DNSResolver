import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from tqdm import tqdm

from classes.allocator_contract import (
    clear_allocator_targets,
    publish_allocator_targets,
)
from classes.custom_exceptions import OutputWriteError, ProviderCatalogueError
from classes.dns_handler import DNSHandler
from classes.environment_manager import EnvironmentManager
from classes.run_contract import (
    clear_run_documents,
    publish_dns_observations,
    publish_run_manifest,
)
from classes.run_summary import RunSummary
from imports.cloud_ip_ranges import (
    _timestamp,
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_google_cloud_ip_ranges,
)
from imports.domain_processor import process_domain_async
from version import __version__


async def run(env_manager):
    """
    Core resolution pipeline. Accepts any EnvironmentManager-compatible object so
    the CLI entrypoint (resolver.py) and any other entrypoint
    can share the same logic.
    """
    run_id = str(uuid4())
    started_at = _timestamp(datetime.now(timezone.utc))
    catalogues = {}
    clear_allocator_targets(env_manager.output_dir)
    clear_run_documents(env_manager.output_dir)
    try:
        await _run(env_manager, run_id, started_at, catalogues)
    except ProviderCatalogueError:
        raise
    except Exception:
        try:
            clear_allocator_targets(env_manager.output_dir)
            publish_dns_observations(env_manager.records, env_manager.output_dir)
            if set(catalogues) == {"aws", "gcp", "azure"}:
                publish_run_manifest(
                    env_manager.output_dir,
                    run_id=run_id,
                    status="failed",
                    started_at=started_at,
                    completed_at=_timestamp(datetime.now(timezone.utc)),
                    catalogues=catalogues,
                )
        except Exception as contract_error:
            env_manager.log_error(
                "Unable to publish failed run state: %s", contract_error
            )
        raise


async def _run(env_manager, run_id, started_at, catalogues):
    fetched_catalogues = {
        "gcp": fetch_google_cloud_ip_ranges(env_manager.output_dir),
        "aws": fetch_aws_ip_ranges(env_manager.output_dir),
        "azure": fetch_azure_ip_ranges(env_manager.output_dir),
    }
    catalogues.update(fetched_catalogues)
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
        env_manager.set_domains()
        details = "; ".join(
            f"{name}: {catalogues[name].error or catalogues[name].status}"
            for name in unusable
        )
        publish_dns_observations(
            env_manager.records,
            env_manager.output_dir,
            provider_failures={
                name: catalogues[name].error or catalogues[name].status
                for name in unusable
            },
            hostnames=env_manager.domains,
        )
        publish_run_manifest(
            env_manager.output_dir,
            run_id=run_id,
            status="incomplete",
            started_at=started_at,
            completed_at=_timestamp(datetime.now(timezone.utc)),
            catalogues=catalogues,
        )
        raise ProviderCatalogueError(
            "Required provider catalogue(s) unavailable; no domains were processed "
            f"and no actionable results were published. {details}. Status: {status_path}"
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
                catalogues,
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
            if isinstance(result, OutputWriteError):
                env_manager.log_error(
                    "Required output failure processing %s: %s", domain, result
                )
                raise result
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

    targets = publish_allocator_targets(env_manager.records, env_manager.output_dir)
    env_manager.log_info(
        "Published %d actionable target(s) to allocator-targets-v1.json",
        len(targets),
    )
    publish_dns_observations(env_manager.records, env_manager.output_dir)

    RunSummary(env_manager.records, env_manager.output_dir, __version__).display(
        len(env_manager.domains), len(domains_to_process)
    )

    if env_manager.extreme:
        for provider, label in (
            ("aws", "AWS"),
            ("gcp", "Google Cloud"),
            ("azure", "Azure"),
        ):
            env_manager.log_info(
                "%s IPv4 Ranges: %s", label, catalogues[provider].ipv4_ranges
            )
            env_manager.log_info(
                "%s IPv6 Ranges: %s", label, catalogues[provider].ipv6_ranges
            )

    publish_run_manifest(
        env_manager.output_dir,
        run_id=run_id,
        status="complete",
        started_at=started_at,
        completed_at=_timestamp(datetime.now(timezone.utc)),
        catalogues=catalogues,
    )


async def main_async():
    print(f"DNSResolver v{__version__}")
    env_manager = EnvironmentManager()
    await run(env_manager)


if __name__ == "__main__":
    asyncio.run(main_async())
