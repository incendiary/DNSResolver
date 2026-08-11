from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import resolver


@pytest.fixture
def run_environment(tmp_path):
    environment = MagicMock()
    environment.output_dir = str(tmp_path)
    environment.output_files = {"standard": {}}
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
    empty_ranges = ([], [], {})

    with (
        patch("resolver.fetch_google_cloud_ip_ranges", return_value=empty_ranges),
        patch("resolver.fetch_aws_ip_ranges", return_value=empty_ranges),
        patch("resolver.fetch_azure_ip_ranges", return_value=empty_ranges),
        patch("resolver.DNSHandler"),
        patch("resolver.process_domain_async", process),
        patch("resolver.RunSummary"),
    ):
        await resolver.run(run_environment)

    final_retry_values = [
        call.kwargs["final_retry"] for call in process.await_args_list
    ]
    assert final_retry_values == [False, True]
