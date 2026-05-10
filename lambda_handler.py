"""
AWS Lambda entrypoint for DNSResolver.

Trigger:  S3 PutObject event — upload a plain-text domains file to the
          input bucket to kick off a run.

Environment variables:
  OUTPUT_BUCKET   S3 bucket for results (default: same as input bucket)
  OUTPUT_PREFIX   S3 key prefix for results (default: results/)
  NAMESERVERS     Comma-separated resolvers, e.g. 8.8.8.8,1.1.1.1 (optional)
  MAX_THREADS     Concurrent domain tasks (default: 50)
  TIMEOUT         DNS query timeout in seconds (default: from config.json)
  RETRIES         Retry attempts for failed domains (default: from config.json)
  VERBOSE         Set to "true" for verbose CloudWatch logging (default: false)

IAM permissions required:
  s3:GetObject  on the input bucket
  s3:PutObject  on the output bucket

Deployment: container image recommended — pycares bundles a native extension
that must match the Lambda execution environment architecture.
See Dockerfile for the reference image definition.
"""

import asyncio
import logging
import os

import boto3

from classes.lambda_environment_manager import LambdaEnvironmentManager
from resolver import run

logger = logging.getLogger("DNSResolver")

TEMP_DIR = "/tmp"


def handler(event, context):
    """Lambda handler — synchronous wrapper required by the Lambda runtime."""
    asyncio.run(_main(event))


async def _main(event):
    record = event["Records"][0]["s3"]
    input_bucket = record["bucket"]["name"]
    input_key = record["object"]["key"]

    output_bucket = os.environ.get("OUTPUT_BUCKET", input_bucket)
    output_prefix = os.environ.get("OUTPUT_PREFIX", "results/").rstrip("/")

    nameservers_raw = os.environ.get("NAMESERVERS", "")
    nameservers = [n.strip() for n in nameservers_raw.split(",") if n.strip()] or None

    max_threads = int(os.environ.get("MAX_THREADS", "50"))
    timeout = int(os.environ["TIMEOUT"]) if os.environ.get("TIMEOUT") else None
    retries = int(os.environ["RETRIES"]) if os.environ.get("RETRIES") else None
    verbose = os.environ.get("VERBOSE", "").lower() == "true"

    s3 = boto3.client("s3")

    domains_path = os.path.join(TEMP_DIR, "domains.txt")
    s3.download_file(input_bucket, input_key, domains_path)
    logger.info("Downloaded %s/%s to %s", input_bucket, input_key, domains_path)

    output_dir = os.path.join(TEMP_DIR, "dnsresolver_output")

    env_manager = LambdaEnvironmentManager(
        domains_file=domains_path,
        output_dir=output_dir,
        nameservers=nameservers,
        max_threads=max_threads,
        timeout=timeout,
        retries=retries,
        verbose=verbose,
    )

    await run(env_manager)

    _upload_results(s3, env_manager.output_dir, output_bucket, output_prefix)
    logger.info("Results uploaded to s3://%s/%s/", output_bucket, output_prefix)


def _upload_results(s3_client, local_dir, bucket, prefix):
    """Walk local_dir and upload every file to S3 under prefix."""
    for root, _dirs, files in os.walk(local_dir):
        for filename in files:
            local_path = os.path.join(root, filename)
            relative_path = os.path.relpath(local_path, local_dir)
            s3_key = f"{prefix}/{relative_path}"
            s3_client.upload_file(local_path, bucket, s3_key)
            logger.info("Uploaded %s → s3://%s/%s", local_path, bucket, s3_key)
