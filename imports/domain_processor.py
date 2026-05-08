from imports.cloud_service_provider_checks import perform_csp_checks
from imports.create_domain_context import create_domain_context


async def process_domain_async(domain, env_manager, pbar, csp_ip_addresses, dns_handler):
    domain_context = create_domain_context(
        domain, env_manager, set(), set(), csp_ip_addresses
    )
    domain_context.create_resolver()

    env_manager.log_info(f"Processing domain: {domain}")

    success, final_ips = await dns_handler.resolve_domain_async(domain_context)

    env_manager.log_info(
        f"Processing domain: {domain} was {'successful' if success else 'unsuccessful'}"
    )

    if success and final_ips:
        output_files = env_manager.get_output_files()
        await env_manager.write_to_file(
            output_files["standard"]["resolved"],
            f"{domain}|{'|'.join(final_ips)}",
        )
        perform_csp_checks(domain_context, env_manager, final_ips)
        env_manager.log_info(f"Performing CSP Checks for: {domain} and {final_ips}")

    pbar.update(1)
    domain_context.log_info(
        f"Finished processing domain: {domain_context.get_domain()}"
    )

    return success, final_ips, domain_context.dangling_domains
