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
    environment.records = []
    environment.domains = {"example.com"}
    environment.retries = 1
    environment.max_threads = 1
    environment.extreme = False
    return environment


async def test_run_marks_only_last_attempt_as_final(run_environment):
    process = AsyncMock(
        side_effect=[
            (False, []),
            (True, ["192.0.2.10"]),
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
    assert (
        json.loads(
            (Path(run_environment.output_dir) / "dns-observations-v1.json").read_text()
        )
        == []
    )
    manifest = json.loads(
        (Path(run_environment.output_dir) / "run-manifest-v1.json").read_text()
    )
    assert manifest["status"] == "complete"
    assert manifest["outputs"]["actionable_targets"] == "allocator-targets-v1.json"


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

    # Input names are loaded only so each excluded hostname can carry the
    # provider-catalogue reason; no DNS processing begins.
    run_environment.set_domains.assert_called_once_with()
    process.assert_not_awaited()
    status = json.loads(
        (Path(run_environment.output_dir) / "provider_catalogues.json").read_text()
    )
    assert status["gcp"]["usable"] is False
    assert status["gcp"]["error"] == "TLS failure"
    assert not (Path(run_environment.output_dir) / "allocator-targets-v1.json").exists()
    observations = json.loads(
        (Path(run_environment.output_dir) / "dns-observations-v1.json").read_text()
    )
    assert observations[0]["kind"] == "provider_catalog_incomplete"
    manifest = json.loads(
        (Path(run_environment.output_dir) / "run-manifest-v1.json").read_text()
    )
    assert manifest["status"] == "incomplete"
    assert manifest["outputs"]["actionable_targets"] is None


async def test_run_aborts_before_publication_on_output_failure(run_environment):
    stale_targets = Path(run_environment.output_dir) / "allocator-targets-v1.json"
    stale_targets.write_text('[{"stale": true}]', encoding="utf-8")
    stale_observations = Path(run_environment.output_dir) / "dns-observations-v1.json"
    stale_observations.write_text('[{"stale": true}]', encoding="utf-8")
    stale_manifest = Path(run_environment.output_dir) / "run-manifest-v1.json"
    stale_manifest.write_text('{"status": "complete"}', encoding="utf-8")
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
    manifest = json.loads(
        (Path(run_environment.output_dir) / "run-manifest-v1.json").read_text()
    )
    assert manifest["status"] == "failed"
    assert manifest["outputs"]["actionable_targets"] is None
    assert json.loads(stale_observations.read_text()) == []


def _catalogue(provider, usable=True):
    return ProviderCatalogue(
        provider,
        ["192.0.2.0/24"] if usable else [],
        [],
        {},
        "complete" if usable else "failed",
        usable,
        f"https://example.com/{provider}.json",
        "2026-01-01T00:00:00Z" if usable else None,
        f"{provider}-1" if usable else None,
        None if usable else "TLS failure",
    )


async def test_incomplete_run_writes_report_without_targets(run_environment):
    run_environment.args.format = "md"
    with (
        patch(
            "resolver.fetch_google_cloud_ip_ranges",
            return_value=_catalogue("gcp", usable=False),
        ),
        patch("resolver.fetch_aws_ip_ranges", return_value=_catalogue("aws")),
        patch("resolver.fetch_azure_ip_ranges", return_value=_catalogue("azure")),
        pytest.raises(ProviderCatalogueError),
    ):
        await resolver.run(run_environment)
    report = (Path(run_environment.output_dir) / "run-report.md").read_text()
    assert report.splitlines()[0].startswith("# DNSResolver run: INCOMPLETE")
    assert "## Actionable targets" not in report
    assert "- example.com" in report


async def test_report_failure_never_masks_the_original_exception(run_environment):
    run_environment.args.format = "md"
    failure = OutputWriteError("disk full")
    with (
        patch("resolver.fetch_google_cloud_ip_ranges", return_value=_catalogue("gcp")),
        patch("resolver.fetch_aws_ip_ranges", return_value=_catalogue("aws")),
        patch("resolver.fetch_azure_ip_ranges", return_value=_catalogue("azure")),
        patch("resolver.DNSHandler"),
        patch(
            "resolver.process_domain_async",
            new_callable=AsyncMock,
            side_effect=failure,
        ),
        patch("resolver._write_text_atomic", side_effect=OSError("read-only")),
        pytest.raises(OutputWriteError, match="disk full"),
    ):
        await resolver.run(run_environment)
    manifest = json.loads(
        (Path(run_environment.output_dir) / "run-manifest-v1.json").read_text()
    )
    assert manifest["status"] == "failed"
    assert not (Path(run_environment.output_dir) / "run-report.md").exists()


async def test_failed_run_report_says_failed_and_lists_no_targets(run_environment):
    run_environment.args.format = "md"
    with (
        patch("resolver.fetch_google_cloud_ip_ranges", return_value=_catalogue("gcp")),
        patch("resolver.fetch_aws_ip_ranges", return_value=_catalogue("aws")),
        patch("resolver.fetch_azure_ip_ranges", return_value=_catalogue("azure")),
        patch("resolver.DNSHandler"),
        patch(
            "resolver.process_domain_async",
            new_callable=AsyncMock,
            side_effect=OutputWriteError("disk full"),
        ),
        pytest.raises(OutputWriteError),
    ):
        await resolver.run(run_environment)
    report = (Path(run_environment.output_dir) / "run-report.md").read_text()
    assert report.splitlines()[0].startswith("# DNSResolver run: FAILED")
    assert "## Actionable targets" not in report
