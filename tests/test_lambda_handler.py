"""Tests for lambda_handler."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

S3_EVENT = {
    "Records": [
        {
            "s3": {
                "bucket": {"name": "my-input-bucket"},
                "object": {"key": "domains/domains.txt"},
            }
        }
    ]
}


@pytest.fixture
def mock_s3(tmp_path):
    """Boto3 S3 client mock that writes a minimal domains file on download_file."""
    client = MagicMock()

    def fake_download(bucket, key, dest):
        with open(dest, "w") as f:
            f.write("example.com\n")

    client.download_file.side_effect = fake_download
    return client


@pytest.fixture
def mock_env_manager(tmp_path):
    mgr = MagicMock()
    mgr.output_dir = str(tmp_path / "output")
    mgr.extreme = False
    mgr.max_threads = 50
    mgr.domains = {"example.com"}
    mgr.retries = 0
    os.makedirs(str(tmp_path / "output"), exist_ok=True)
    return mgr


async def test_handler_downloads_domains_from_s3(tmp_path, mock_s3, mock_env_manager):
    with (
        patch("lambda_handler.boto3.client", return_value=mock_s3),
        patch("lambda_handler.LambdaEnvironmentManager", return_value=mock_env_manager),
        patch("lambda_handler.run", new_callable=AsyncMock),
        patch("lambda_handler._upload_results"),
        patch("lambda_handler.TEMP_DIR", str(tmp_path)),
    ):
        from lambda_handler import _main

        await _main(S3_EVENT)

    mock_s3.download_file.assert_called_once_with(
        "my-input-bucket",
        "domains/domains.txt",
        str(tmp_path / "domains.txt"),
    )


async def test_handler_uploads_results_after_run(tmp_path, mock_s3, mock_env_manager):
    with (
        patch("lambda_handler.boto3.client", return_value=mock_s3),
        patch("lambda_handler.LambdaEnvironmentManager", return_value=mock_env_manager),
        patch("lambda_handler.run", new_callable=AsyncMock) as mock_run,
        patch("lambda_handler._upload_results") as mock_upload,
        patch("lambda_handler.TEMP_DIR", str(tmp_path)),
    ):
        from lambda_handler import _main

        await _main(S3_EVENT)

    mock_run.assert_awaited_once()
    mock_upload.assert_called_once()


async def test_handler_uses_output_bucket_env_var(tmp_path, mock_s3, mock_env_manager):
    with (
        patch.dict(os.environ, {"OUTPUT_BUCKET": "my-output-bucket"}),
        patch("lambda_handler.boto3.client", return_value=mock_s3),
        patch("lambda_handler.LambdaEnvironmentManager", return_value=mock_env_manager),
        patch("lambda_handler.run", new_callable=AsyncMock),
        patch("lambda_handler._upload_results") as mock_upload,
        patch("lambda_handler.TEMP_DIR", str(tmp_path)),
    ):
        from lambda_handler import _main

        await _main(S3_EVENT)

    call_args = mock_upload.call_args[0]
    assert call_args[2] == "my-output-bucket"


async def test_handler_defaults_output_to_input_bucket(
    tmp_path, mock_s3, mock_env_manager
):
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("lambda_handler.boto3.client", return_value=mock_s3),
        patch("lambda_handler.LambdaEnvironmentManager", return_value=mock_env_manager),
        patch("lambda_handler.run", new_callable=AsyncMock),
        patch("lambda_handler._upload_results") as mock_upload,
        patch("lambda_handler.TEMP_DIR", str(tmp_path)),
    ):
        from lambda_handler import _main

        await _main(S3_EVENT)

    call_args = mock_upload.call_args[0]
    assert call_args[2] == "my-input-bucket"


async def test_handler_parses_nameservers_env_var(tmp_path, mock_s3, mock_env_manager):
    with (
        patch.dict(os.environ, {"NAMESERVERS": "8.8.8.8,1.1.1.1"}),
        patch("lambda_handler.boto3.client", return_value=mock_s3),
        patch(
            "lambda_handler.LambdaEnvironmentManager", return_value=mock_env_manager
        ) as MockEM,
        patch("lambda_handler.run", new_callable=AsyncMock),
        patch("lambda_handler._upload_results"),
        patch("lambda_handler.TEMP_DIR", str(tmp_path)),
    ):
        from lambda_handler import _main

        await _main(S3_EVENT)

    _, kwargs = MockEM.call_args
    assert kwargs.get("nameservers") == ["8.8.8.8", "1.1.1.1"]


async def test_handler_passes_max_threads_env_var(tmp_path, mock_s3, mock_env_manager):
    with (
        patch.dict(os.environ, {"MAX_THREADS": "25"}),
        patch("lambda_handler.boto3.client", return_value=mock_s3),
        patch(
            "lambda_handler.LambdaEnvironmentManager", return_value=mock_env_manager
        ) as MockEM,
        patch("lambda_handler.run", new_callable=AsyncMock),
        patch("lambda_handler._upload_results"),
        patch("lambda_handler.TEMP_DIR", str(tmp_path)),
    ):
        from lambda_handler import _main

        await _main(S3_EVENT)

    _, kwargs = MockEM.call_args
    assert kwargs.get("max_threads") == 25


def test_upload_results_walks_and_uploads(tmp_path):
    result_dir = tmp_path / "results" / "20260509_120000"
    result_dir.mkdir(parents=True)
    (result_dir / "dangling.txt").write_text("example.com\n")
    (result_dir / "resolved.txt").write_text("other.com|1.2.3.4\n")

    mock_s3 = MagicMock()

    from lambda_handler import _upload_results

    _upload_results(mock_s3, str(result_dir), "my-bucket", "results")

    assert mock_s3.upload_file.call_count == 2
    uploaded_keys = {call[0][2] for call in mock_s3.upload_file.call_args_list}
    assert any("dangling.txt" in k for k in uploaded_keys)
    assert any("resolved.txt" in k for k in uploaded_keys)
