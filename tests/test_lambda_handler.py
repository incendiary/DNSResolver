"""The Lambda adapter never contacts real DNS or AWS services in tests."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import lambda_handler


def _event(version="v1", key="domains/demo+list.txt"):
    return {
        "Records": [
            {
                "eventSource": "aws:s3",
                "s3": {
                    "bucket": {"name": "demo-bucket"},
                    "object": {"key": key, "versionId": version},
                },
            }
        ]
    }


def _s3():
    client = MagicMock()

    def download(_bucket, _key, destination, ExtraArgs):
        assert ExtraArgs == {"VersionId": "v1"}
        Path(destination).write_text("owned.example.com\n")

    client.download_file.side_effect = download
    return client


def test_versioned_input_runs_pipeline_and_publishes_manifest_last(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(lambda_handler, "TMP_DIR", tmp_path)
    monkeypatch.chdir(tmp_path)
    s3 = _s3()
    seen = {}

    async def run(manager):
        seen["args"] = manager.args
        seen["domains"] = Path(manager.domains_file).read_text()
        output = Path(manager.output_dir)
        (output / "allocator-targets-v1.json").write_text("[]\n")
        (output / "run-manifest-v1.json").write_text('{"status":"complete"}\n')

    with patch("lambda_handler.run", side_effect=run):
        result = lambda_handler._handle(
            _event(), SimpleNamespace(aws_request_id="request-1"), s3
        )

    assert result == {"runs": [{"bucket": "demo-bucket", "prefix": "runs/request-1/0"}]}
    s3.download_file.assert_called_once()
    assert s3.download_file.call_args.args[:2] == (
        "demo-bucket",
        "domains/demo list.txt",
    )
    assert seen["domains"] == "owned.example.com\n"
    assert seen["args"].format == "json"
    assert seen["args"].evidence is False
    assert seen["args"].record_external_ip is False
    assert not (tmp_path / "dnsresolver.log").exists()
    keys = [call.args[2] for call in s3.upload_file.call_args_list]
    assert "runs/request-1/0/allocator-targets-v1.json" in keys
    assert keys[-1] == "runs/request-1/0/run-manifest-v1.json"


def test_incomplete_run_still_uploads_manifest_last(tmp_path, monkeypatch):
    monkeypatch.setattr(lambda_handler, "TMP_DIR", tmp_path)
    s3 = _s3()

    async def run(manager):
        output = Path(manager.output_dir)
        (output / "dns-observations-v1.json").write_text("[]\n")
        (output / "run-manifest-v1.json").write_text('{"status":"incomplete"}\n')
        raise RuntimeError("catalogue unavailable")

    with (
        patch("lambda_handler.run", side_effect=run),
        pytest.raises(RuntimeError, match="catalogue unavailable"),
    ):
        lambda_handler._handle(
            _event(), SimpleNamespace(aws_request_id="request-2"), s3
        )

    keys = [call.args[2] for call in s3.upload_file.call_args_list]
    assert "runs/request-2/0/dns-observations-v1.json" in keys
    assert keys[-1] == "runs/request-2/0/run-manifest-v1.json"


@pytest.mark.parametrize(
    "event,reason",
    [
        (_event(version=None), "versionId"),
        (_event(key="runs/output.json"), "domains/"),
        ({"Records": []}, "no records"),
    ],
)
def test_invalid_input_is_rejected_before_download(event, reason):
    s3 = _s3()
    with pytest.raises(ValueError, match=reason):
        lambda_handler._handle(event, SimpleNamespace(aws_request_id="request-3"), s3)
    s3.download_file.assert_not_called()
