"""S3-triggered Lambda adapter for the DNSResolver pipeline."""

import asyncio
import tempfile
from pathlib import Path
from urllib.parse import unquote_plus

from classes.environment_manager import EnvironmentManager
from classes.run_contract import MANIFEST_FILENAME
from resolver import run

TMP_DIR = Path("/tmp")
CONFIG_FILE = Path(__file__).with_name("config.json")


def handler(event, context):
    import boto3

    return _handle(event, context, boto3.client("s3"))


def _handle(event, context, s3):
    records = event.get("Records", [])
    if not records:
        raise ValueError("S3 event has no records")
    return {
        "runs": [
            _process_record(record, context.aws_request_id, index, s3)
            for index, record in enumerate(records)
        ]
    }


def _process_record(record, request_id, index, s3):
    if record.get("eventSource") != "aws:s3":
        raise ValueError("Expected an S3 event record")
    source = record["s3"]
    bucket = source["bucket"]["name"]
    key = unquote_plus(source["object"]["key"])
    version = source["object"].get("versionId")
    if not version:
        raise ValueError("S3 input versionId is required")
    if not key.startswith("domains/") or key.endswith("/"):
        raise ValueError("Input must be a file under domains/")

    prefix = f"runs/{request_id}/{index}"
    with tempfile.TemporaryDirectory(dir=TMP_DIR) as directory:
        work = Path(directory)
        domains_file = work / "domains.txt"
        s3.download_file(
            bucket, key, str(domains_file), ExtraArgs={"VersionId": version}
        )
        manager = EnvironmentManager(
            argv=[
                str(domains_file),
                "--config-file",
                str(CONFIG_FILE),
                "--output-dir",
                str(work / "output"),
                "--format",
                "json",
                "--no-evidence",
                "--no-record-external-ip",
                "--verbose",
            ],
            log_file=None,
        )
        try:
            asyncio.run(run(manager))
        finally:
            _upload_outputs(s3, bucket, prefix, Path(manager.output_dir))
    return {"bucket": bucket, "prefix": prefix}


def _upload_outputs(s3, bucket, prefix, output_dir):
    files = sorted(path for path in output_dir.rglob("*") if path.is_file())
    manifest = output_dir / MANIFEST_FILENAME
    for path in files:
        if path != manifest:
            s3.upload_file(
                str(path), bucket, f"{prefix}/{path.relative_to(output_dir)}"
            )
    if manifest in files:
        s3.upload_file(str(manifest), bucket, f"{prefix}/{MANIFEST_FILENAME}")
