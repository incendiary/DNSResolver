import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import resolver
from classes.custom_exceptions import OutputWriteError, ProviderCatalogueError
from imports.cloud_ip_ranges import ProviderCatalogue


@pytest.fixture
def run_environment(tmp_path):
    environment = MagicMock()
    environment.output_dir = str(tmp_path)
    csp_path = tmp_path / "csp_matches.txt"
    csp_path.write_text("", encoding="utf-8")
    environment.output_files = {"standard": {"csp": str(csp_path)}}
    environment.domains = {"example.com"}
    environment.retries = 1
    environment.max_threads = 1
    environment.extreme = False
    return environment


async def test_run_marks_only_last_attempt_as_final(run_environment):
    process = AsyncMock(
        side_effect=[
            (False, [], set()),
            (True, ["192.0.2.10"], set()),
        ]
    )

    def catalogue(provider):
        return ProviderCatalogue(
            provider,
            ["192.0.2.0/24"],
            [],
            {},
            "complete",
            True,
            f"https://example.com/{provider}.json",
            "2026-01-01T00:00:00Z",
            f"{provider}-1",
        )

    with (
        patch("resolver.fetch_google_cloud_ip_ranges", return_value=catalogue("gcp")),
        patch("resolver.fetch_aws_ip_ranges", return_value=catalogue("aws")),
        patch("resolver.fetch_azure_ip_ranges", return_value=catalogue("azure")),
        patch("resolver.DNSHandler"),
        patch("resolver.process_domain_async", process),
        patch("resolver.RunSummary"),
    ):
        await resolver.run(run_environment)

    final_retry_values = [
        call.kwargs["final_retry"] for call in process.await_args_list
    ]
    assert final_retry_values == [False, True]
    status = Path(run_environment.output_dir) / "provider_catalogues.json"
    assert status.exists()
    assert (
        json.loads(
            (Path(run_environment.output_dir) / "allocator-targets-v1.json").read_text()
        )
        == []
    )


async def test_run_fails_closed_before_processing_domains(run_environment):
    usable = ProviderCatalogue(
        "aws",
        ["192.0.2.0/24"],
        [],
        {},
        "complete",
        True,
        "https://example.com/aws.json",
        "2026-01-01T00:00:00Z",
        "aws-1",
    )
    failed = ProviderCatalogue(
        "gcp",
        [],
        [],
        {},
        "failed",
        False,
        "https://example.com/gcp.json",
        None,
        None,
        "TLS failure",
    )

    with (
        patch("resolver.fetch_google_cloud_ip_ranges", return_value=failed),
        patch("resolver.fetch_aws_ip_ranges", return_value=usable),
        patch("resolver.fetch_azure_ip_ranges", return_value=usable),
        patch("resolver.process_domain_async", new_callable=AsyncMock) as process,
        pytest.raises(ProviderCatalogueError, match="no domains were processed"),
    ):
        await resolver.run(run_environment)

    run_environment.set_domains.assert_not_called()
    process.assert_not_awaited()
    status = json.loads(
        (Path(run_environment.output_dir) / "provider_catalogues.json").read_text()
    )
    assert status["gcp"]["usable"] is False
    assert status["gcp"]["error"] == "TLS failure"
    assert not (Path(run_environment.output_dir) / "allocator-targets-v1.json").exists()


async def test_run_aborts_before_publication_on_output_failure(run_environment):
    stale_targets = Path(run_environment.output_dir) / "allocator-targets-v1.json"
    stale_targets.write_text('[{"stale": true}]', encoding="utf-8")
    failure = OutputWriteError("disk full")

    def catalogue(provider):
        return ProviderCatalogue(
            provider,
            ["192.0.2.0/24"],
            [],
            {"192.0.2.0/24": [("region", "service", "border-group")]},
            "complete",
            True,
            f"https://example.com/{provider}.json",
            "2026-01-01T00:00:00Z",
            f"{provider}-1",
        )

    with (
        patch("resolver.fetch_google_cloud_ip_ranges", return_value=catalogue("gcp")),
        patch("resolver.fetch_aws_ip_ranges", return_value=catalogue("aws")),
        patch("resolver.fetch_azure_ip_ranges", return_value=catalogue("azure")),
        patch("resolver.DNSHandler"),
        patch(
            "resolver.process_domain_async",
            new_callable=AsyncMock,
            side_effect=failure,
        ),
        patch("resolver.publish_allocator_targets") as publish,
        pytest.raises(OutputWriteError, match="disk full"),
    ):
        await resolver.run(run_environment)

    publish.assert_not_called()
    assert not stale_targets.exists()
    run_environment.log_error.assert_called_once_with(
        "Required output failure processing %s: %s",
        "example.com",
        failure,
    )
