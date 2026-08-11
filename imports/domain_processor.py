from classes.domain_processing_context import DomainProcessingContext
from imports.cloud_service_provider_checks import perform_csp_checks


async def process_domain_async(
    domain,
    env_manager,
    pbar,
    csp_ip_addresses,
    dns_handler,
    final_retry=True,
):
    domain_context = DomainProcessingContext(env_manager, csp_ip_addresses)
    domain_context.set_domain(domain)

    env_manager.log_info(f"Processing domain: {domain}")

    success, final_ips = await dns_handler.resolve_domain_async(
        domain_context, final_retry=final_retry
    )

    env_manager.log_info(
        f"Processing domain: {domain} was {'successful' if success else 'unsuccessful'}"
    )

    if success and final_ips:
        output_files = env_manager.output_files
        # Two separate facts, because only one of them is reliable: whether the
        # zone answers for anything (always knowable), and whether these exact
        # addresses were among those observed (precise, but a probe only samples
        # a rotating pool). WILDCARD is a confirmed catch-all; WILDCARD_ZONE says
        # the zone answers for anything so this resolution proves nothing either
        # way. Neither discards the result.
        verdict = await dns_handler.wildcard_detector.classify(domain, final_ips)
        prefix = f"{verdict}|" if verdict else ""
        await env_manager.write_to_file(
            output_files["standard"]["resolved"],
            f"{prefix}{domain}|{'|'.join(final_ips)}",
        )
        # The verdict travels with the cloud match too. In a zone that answers
        # for anything, an address cannot be attributed to this domain rather
        # than the platform, so it is not a dependable target either way.
        perform_csp_checks(domain_context, env_manager, final_ips, verdict)
        env_manager.log_info(f"Performing CSP Checks for: {domain} and {final_ips}")

    pbar.update(1)
    domain_context.log_info(
        f"Finished processing domain: {domain_context.get_domain()}"
    )

    return success, final_ips, domain_context.dangling_domains
