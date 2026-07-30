from classes.domain_processing_context import DomainProcessingContext
from imports.cloud_service_provider_checks import perform_csp_checks


async def process_domain_async(
    domain, env_manager, pbar, csp_ip_addresses, dns_handler
):
    domain_context = DomainProcessingContext(env_manager, csp_ip_addresses)
    domain_context.set_domain(domain)

    env_manager.log_info(f"Processing domain: {domain}")

    success, final_ips = await dns_handler.resolve_domain_async(domain_context)

    env_manager.log_info(
        f"Processing domain: {domain} was {'successful' if success else 'unsuccessful'}"
    )

    if success and final_ips:
        output_files = env_manager.output_files
        # A domain resolving only to its zone's wildcard addresses is a catch-all
        # answer, not a real host. Marking it keeps enumerated lists readable
        # without discarding the result.
        is_wildcard = await dns_handler.wildcard_detector.is_wildcard_resolution(
            domain, final_ips
        )
        prefix = "WILDCARD|" if is_wildcard else ""
        await env_manager.write_to_file(
            output_files["standard"]["resolved"],
            f"{prefix}{domain}|{'|'.join(final_ips)}",
        )
        # The wildcard verdict travels with the cloud match too. A catch-all
        # address belongs to the hosting platform and is in active use, so it is
        # not a claimable target — but without the marker a single wildcarded
        # zone emits one cloud record per enumerated subdomain.
        perform_csp_checks(domain_context, env_manager, final_ips, is_wildcard)
        env_manager.log_info(f"Performing CSP Checks for: {domain} and {final_ips}")

    pbar.update(1)
    domain_context.log_info(
        f"Finished processing domain: {domain_context.get_domain()}"
    )

    return success, final_ips, domain_context.dangling_domains
