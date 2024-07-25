from classes.dns_handler import DNSHandler


async def perform_dns_checks_async(domain_context, env_manager, final_ips):
    """
    Performs DNS checks and evidence collection if enabled.

    :param domain_context: The domain context instance.
    :param env_manager: The environment manager instance for logging and configuration.
    :param final_ips: The final IP addresses resolved for the domain.
    :return: None
    """
    handler = DNSHandler(env_manager)
    patterns = env_manager.get_patterns()
    current_domain = domain_context.get_domain()
    output_files = env_manager.get_output_files()

    if final_ips:
        await env_manager.write_to_file(
            output_files["standard"]["resolved"],
            f"{current_domain}|{'|'.join(final_ips)}",
        )
        env_manager.log_info(f"Resolved IPs for domain {current_domain}: {final_ips}")

    await handler.collect_evidence(current_domain, "dangling", output_files)

    category, recommendation, evidence_link = handler.categorise_domain(
        current_domain, patterns
    )
    await env_manager.write_to_file(
        output_files["standard"]["dangling"],
        f"{current_domain}|{category}|{recommendation}|{evidence_link}",
    )
    env_manager.log_info(
        f"Categorised domain {current_domain} as {category} with recommendation: {recommendation}"
    )
